//! Provides methods to retrieve pieces from DSN.

use crate::utils::multihash::ToMultihash;
use crate::{Node, PieceByIndexRequest, PieceByIndexResponse};
use async_trait::async_trait;
use backoff::future::retry;
use backoff::ExponentialBackoff;
use futures::StreamExt;
use libp2p::PeerId;
use std::error::Error;
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use std::{io, mem};
use subspace_core_primitives::crypto::blake3_hash_list;
use subspace_core_primitives::{Blake3Hash, Piece, PieceIndex};
use thiserror::Error;
use tracing::{debug, error, info, trace, warn};

/// Defines initial duration between get_piece calls.
const GET_PIECE_INITIAL_INTERVAL: Duration = Duration::from_secs(5);
/// Defines max duration between get_piece calls.
const GET_PIECE_MAX_INTERVAL: Duration = Duration::from_secs(40);

/// Disk piece cache open error
#[derive(Debug, Error)]
enum DiskPieceCacheError {
    /// I/O error occurred
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    /// Checksum mismatch
    #[error("Checksum mismatch")]
    ChecksumMismatch,
}

/// Validates piece against using its commitment.
#[async_trait]
pub trait PieceValidator: Sync + Send {
    /// Validates piece against using its commitment.
    async fn validate_piece(
        &self,
        source_peer_id: PeerId,
        piece_index: PieceIndex,
        piece: Piece,
    ) -> Option<Piece>;
}

/// Stub implementation for piece validation.
pub struct NoPieceValidator;

/// Defines retry policy on error during piece acquiring.
#[derive(PartialEq, Eq, Clone, Debug, Copy)]
pub enum RetryPolicy {
    /// Retry N times (including zero)
    Limited(u16),
    /// No restrictions on retries
    Unlimited,
}

impl Default for RetryPolicy {
    #[inline]
    fn default() -> Self {
        Self::Limited(0)
    }
}

#[async_trait]
impl PieceValidator for NoPieceValidator {
    async fn validate_piece(&self, _: PeerId, _: PieceIndex, piece: Piece) -> Option<Piece> {
        Some(piece)
    }
}

/// Piece provider with cancellation and optional piece validator.
pub struct PieceProvider<PV> {
    node: Node,
    piece_validator: Option<PV>,
    l2_cache_path: PathBuf,
}

impl<PV> PieceProvider<PV>
where
    PV: PieceValidator,
{
    /// Creates new piece provider.
    pub fn new(node: Node, piece_validator: Option<PV>, l2_cache_path: PathBuf) -> Self {
        Self {
            node,
            piece_validator,
            l2_cache_path,
        }
    }

    // Get from piece cache (L2)
    async fn get_piece_from_cache(&self, piece_index: PieceIndex) -> Option<Piece> {
        let key = piece_index.to_multihash();

        let mut request_batch = self.node.get_requests_batch_handle().await;
        let get_providers_result = request_batch.get_providers(key).await;

        match get_providers_result {
            Ok(mut get_providers_stream) => {
                while let Some(provider_id) = get_providers_stream.next().await {
                    trace!(%piece_index, %provider_id, "get_providers returned an item");

                    let request_result = request_batch
                        .send_generic_request(provider_id, PieceByIndexRequest { piece_index })
                        .await;

                    match request_result {
                        Ok(PieceByIndexResponse { piece: Some(piece) }) => {
                            trace!(%provider_id, %piece_index, ?key, "Piece request succeeded.");

                            if let Some(validator) = &self.piece_validator {
                                return validator
                                    .validate_piece(provider_id, piece_index, piece)
                                    .await;
                            } else {
                                return Some(piece);
                            }
                        }
                        Ok(PieceByIndexResponse { piece: None }) => {
                            debug!(%provider_id, %piece_index, ?key, "Piece request returned empty piece.");
                        }
                        Err(error) => {
                            debug!(%provider_id, %piece_index, ?key, ?error, "Piece request failed.");
                        }
                    }
                }
            }
            Err(err) => {
                warn!(%piece_index,?key, ?err, "get_providers returned an error");
            }
        }

        None
    }

    /// Returns piece by its index. Uses retry policy for error handling.
    pub async fn get_piece(
        &self,
        piece_index: PieceIndex,
        retry_policy: RetryPolicy,
    ) -> Result<Option<Piece>, Box<dyn Error + Send + Sync + 'static>> {
        trace!(%piece_index, "Piece request.");

        let backoff = ExponentialBackoff {
            initial_interval: GET_PIECE_INITIAL_INTERVAL,
            max_interval: GET_PIECE_MAX_INTERVAL,
            // Try until we get a valid piece
            max_elapsed_time: None,
            multiplier: 1.75,
            ..ExponentialBackoff::default()
        };

        let retries = AtomicU64::default();

        retry(backoff, || async {
            let current_attempt = retries.fetch_add(1, Ordering::Relaxed);

            // read piece from l2 local cache
            match self.read_piece_l2(piece_index) {
                Ok(maybe_piece) => {
                    if maybe_piece.is_some() {
                        info!(%piece_index, "Read piece from l2 local cache successfully");
                        return Ok(maybe_piece);
                    }
                }
                Err(error) => {
                    error!(
                        %error,
                        %piece_index,
                        "Error while reading piece from cache, might be a disk corruption"
                    );
                }
            }

            if let Some(piece) = self.get_piece_from_cache(piece_index).await {
                trace!(%piece_index, current_attempt, "Got piece");
                return Ok(Some(piece));
            }

            match retry_policy {
                RetryPolicy::Limited(max_retries) => {
                    if current_attempt >= max_retries.into() {
                        if max_retries > 0 {
                            debug!(
                                %piece_index,
                                current_attempt,
                                max_retries,
                                "Couldn't get a piece from DSN L2. No retries left."
                            );
                        }
                        return Ok(None);
                    }

                    max_retries as u64
                }
                RetryPolicy::Unlimited => u64::MAX,
            };

            trace!(%piece_index, current_attempt, "Couldn't get a piece from DSN L2. Retrying...");

            Err(backoff::Error::transient(
                "Couldn't get piece from DSN".into(),
            ))
        })
        .await
    }

    /// Get piece from a particular peer.
    pub async fn get_piece_from_peer(
        &self,
        peer_id: PeerId,
        piece_index: PieceIndex,
    ) -> Option<Piece> {
        let request_result = self
            .node
            .send_generic_request(peer_id, PieceByIndexRequest { piece_index })
            .await;

        match request_result {
            Ok(PieceByIndexResponse { piece: Some(piece) }) => {
                trace!(%peer_id, %piece_index, "Piece request succeeded.");

                if let Some(validator) = &self.piece_validator {
                    return validator.validate_piece(peer_id, piece_index, piece).await;
                } else {
                    return Some(piece);
                }
            }
            Ok(PieceByIndexResponse { piece: None }) => {
                debug!(%peer_id, %piece_index, "Piece request returned empty piece.");
            }
            Err(error) => {
                debug!(%peer_id, %piece_index, ?error, "Piece request failed.");
            }
        }

        None
    }

    const fn element_size() -> usize {
        PieceIndex::SIZE + Piece::SIZE + mem::size_of::<Blake3Hash>()
    }

    fn read_piece_internal(
        file: &mut File,
        element: &mut [u8],
    ) -> Result<Option<PieceIndex>, DiskPieceCacheError> {
        file.read_exact(element)?;

        let (piece_index_bytes, remaining_bytes) = element.split_at(PieceIndex::SIZE);
        let (piece_bytes, expected_checksum) = remaining_bytes.split_at(Piece::SIZE);

        // Verify checksum
        let actual_checksum = blake3_hash_list(&[piece_index_bytes, piece_bytes]);
        if actual_checksum != expected_checksum {
            if element.iter().all(|&byte| byte == 0) {
                return Ok(None);
            }

            debug!(
                actual_checksum = %hex::encode(actual_checksum),
                expected_checksum = %hex::encode(expected_checksum),
                "Hash doesn't match, corrupted piece in cache"
            );

            return Err(DiskPieceCacheError::ChecksumMismatch);
        }

        let piece_index = PieceIndex::from_bytes(
            piece_index_bytes
                .try_into()
                .expect("Statically known to have correct size; qed"),
        );
        Ok(Some(piece_index))
    }

    /// Read piece from cache at specified index.
    ///
    /// Returns `None` if piece cann't be read.
    ///
    /// NOTE: it is possible to do concurrent reads and writes, higher level logic must ensure this
    /// doesn't happen for the same piece being accessed!
    fn read_piece_l2(&self, piece_index: PieceIndex) -> Result<Option<Piece>, DiskPieceCacheError> {
        let path = self.l2_cache_path.join(format!("{:?}", piece_index));
        if !path.exists() {
            return Ok(None);
        }

        let mut file = OpenOptions::new().read(true).open(path)?;

        let mut element = vec![0; Self::element_size()];
        if Self::read_piece_internal(&mut file, &mut element)?.is_some() {
            let mut piece = Piece::default();
            piece.copy_from_slice(&element[PieceIndex::SIZE..][..Piece::SIZE]);
            Ok(Some(piece))
        } else {
            Ok(None)
        }
    }
}
