use crate::piece_cache::PieceCache;
use crate::utils::readers_and_pieces::ReadersAndPieces;
use crate::NodeClient;
use async_trait::async_trait;
use backoff::future::retry;
use backoff::ExponentialBackoff;
use parking_lot::Mutex;
use std::collections::HashSet;
use std::error::Error;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use subspace_core_primitives::{Piece, PieceIndex};
use subspace_farmer_components::plotting::{PieceGetter, PieceGetterRetryPolicy};
use subspace_networking::libp2p::kad::RecordKey;
use subspace_networking::libp2p::PeerId;
use subspace_networking::utils::multihash::ToMultihash;
use subspace_networking::utils::piece_provider::{PieceProvider, PieceValidator, RetryPolicy};
use subspace_networking::Node;
use tracing::{debug, error, trace, warn};

/// Defines initial duration between get_piece calls.
const GET_PIECE_INITIAL_INTERVAL: Duration = Duration::from_secs(5);
/// Defines max duration between get_piece calls.
const GET_PIECE_MAX_INTERVAL: Duration = Duration::from_secs(40);

pub struct FarmerPieceGetter<PV, NC> {
    node: Node,
    piece_provider: PieceProvider<PV>,
    piece_cache: PieceCache,
    node_client: NC,
    readers_and_pieces: Arc<Mutex<Option<ReadersAndPieces>>>,
    disable_dsn_pull: bool,
}

impl<PV, NC> FarmerPieceGetter<PV, NC> {
    pub fn new(
        node: Node,
        piece_provider: PieceProvider<PV>,
        piece_cache: PieceCache,
        node_client: NC,
        readers_and_pieces: Arc<Mutex<Option<ReadersAndPieces>>>,
        disable_dsn_pull: bool,
    ) -> Self {
        Self {
            node,
            piece_provider,
            piece_cache,
            node_client,
            readers_and_pieces,
            disable_dsn_pull,
        }
    }

    fn convert_retry_policy(retry_policy: PieceGetterRetryPolicy) -> RetryPolicy {
        match retry_policy {
            PieceGetterRetryPolicy::Limited(retries) => RetryPolicy::Limited(retries),
            PieceGetterRetryPolicy::Unlimited => RetryPolicy::Unlimited,
        }
    }
}

#[async_trait]
impl<PV, NC> PieceGetter for FarmerPieceGetter<PV, NC>
where
    PV: PieceValidator + Send + 'static,
    NC: NodeClient,
{
    async fn get_piece(
        &self,
        piece_index: PieceIndex,
        retry_policy: PieceGetterRetryPolicy,
    ) -> Result<Option<Piece>, Box<dyn Error + Send + Sync + 'static>> {
        let key = RecordKey::from(piece_index.to_multihash());

        trace!(%piece_index, "Getting piece from local cache");
        if let Some(piece) = self.piece_cache.get_piece(key).await {
            trace!(%piece_index, "Got piece from local cache successfully");
            return Ok(Some(piece));
        }

        if self.disable_dsn_pull {
            let backoff = ExponentialBackoff {
                initial_interval: GET_PIECE_INITIAL_INTERVAL,
                max_interval: GET_PIECE_MAX_INTERVAL,
                // Try until we get a valid piece
                max_elapsed_time: None,
                multiplier: 1.75,
                ..ExponentialBackoff::default()
            };

            let retries = AtomicU64::default();

            return retry(backoff, || async {
                let current_attempt = retries.fetch_add(1, Ordering::Relaxed);

                if let Some(piece) = self.piece_cache.get_piece_l2(piece_index).await {
                    trace!(%piece_index, current_attempt, "Got piece from local l2 cache successfully");
                    return Ok(Some(piece));
                }

                warn!(%piece_index, current_attempt, "Couldn't get a piece from local l2 cache. Retrying...");

                Err(backoff::Error::transient(
                    "Couldn't get piece from local l2 cache".into(),
                ))
            })
            .await;
        } else if let Some(piece) = self.piece_cache.get_piece_l2(piece_index).await {
            trace!(%piece_index, "Got piece from local l2 cache successfully");
            return Ok(Some(piece));
        }

        // L2 piece acquisition
        trace!(%piece_index, "Getting piece from DSN L2 cache");
        let maybe_piece = self
            .piece_provider
            .get_piece(piece_index, Self::convert_retry_policy(retry_policy))
            .await?;

        if maybe_piece.is_some() {
            trace!(%piece_index, "Got piece from DSN L2 cache successfully");
            return Ok(maybe_piece);
        }

        // Try node's RPC before reaching to L1 (archival storage on DSN)
        trace!(%piece_index, "Getting piece from node");
        match self.node_client.piece(piece_index).await {
            Ok(Some(piece)) => {
                trace!(%piece_index, "Got piece from node successfully");
                return Ok(Some(piece));
            }
            Ok(None) => {
                // Nothing to do
            }
            Err(error) => {
                error!(
                    %error,
                    %piece_index,
                    "Failed to retrieve first segment piece from node"
                );
            }
        }

        trace!(%piece_index, "Getting piece from local plot");
        let maybe_read_piece_fut = self
            .readers_and_pieces
            .lock()
            .as_ref()
            .and_then(|readers_and_pieces| readers_and_pieces.read_piece(&piece_index));

        if let Some(read_piece_fut) = maybe_read_piece_fut {
            if let Some(piece) = read_piece_fut.await {
                trace!(%piece_index, "Got piece from local plot successfully");
                return Ok(Some(piece));
            }
        }

        // L1 piece acquisition
        // TODO: consider using retry policy for L1 lookups as well.
        trace!(%piece_index, "Getting piece from DSN L1");
        let connected_peers = HashSet::<PeerId>::from_iter(self.node.connected_peers().await?);
        if connected_peers.is_empty() {
            debug!(%piece_index, "Cannot acquire piece from DSN L1: no connected peers");

            return Ok(None);
        }

        for peer_id in connected_peers.iter() {
            let maybe_piece = self
                .piece_provider
                .get_piece_from_peer(*peer_id, piece_index)
                .await;

            if maybe_piece.is_some() {
                trace!(%piece_index, %peer_id, "DSN L1 lookup succeeded");

                return Ok(maybe_piece);
            }
        }

        debug!(
            %piece_index,
            connected_peers=%connected_peers.len(),
            "Cannot acquire piece: all methods yielded empty result"
        );
        Ok(None)
    }
}
