#[cfg(test)]
mod tests;

use crate::node_client::NodeClient;
use crate::single_disk_farm::piece_cache_v2::DiskPieceCacheV2;
use crate::utils::AsyncJoinOnDrop;
use event_listener_primitives::{Bag, HandlerId};
use futures::channel::oneshot;
use futures::stream::FuturesUnordered;
use futures::{select, FutureExt, StreamExt};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::fmt;
use std::num::NonZeroU16;
use std::sync::Arc;
use subspace_core_primitives::{Piece, PieceIndex, SegmentHeader, SegmentIndex};
use subspace_farmer_components::plotting::{PieceGetter, PieceGetterRetryPolicy};
use subspace_networking::libp2p::kad::{ProviderRecord, RecordKey};
use subspace_networking::libp2p::PeerId;
use subspace_networking::utils::multihash::ToMultihash;
use subspace_networking::{KeyWrapper, LocalRecordProvider, UniqueRecordBinaryHeap};
use tokio::sync::mpsc;
use tracing::{debug, error, info, trace, warn};

const WORKER_CHANNEL_CAPACITY: usize = 100;
const CONCURRENT_PIECES_TO_DOWNLOAD: usize = 1_000;
/// Make caches available as they are building without waiting for the initialization to finish,
/// this number defines an interval in pieces after which cache is updated
const INTERMEDIATE_CACHE_UPDATE_INTERVAL: usize = 100;
/// Get piece retry attempts number.
const PIECE_GETTER_RETRY_NUMBER: NonZeroU16 = NonZeroU16::new(4).expect("Not zero; qed");

type HandlerFn<A> = Arc<dyn Fn(&A) + Send + Sync + 'static>;
type Handler<A> = Bag<HandlerFn<A>, A>;

#[derive(Default, Debug)]
struct Handlers {
    progress: Handler<f32>,
}

#[derive(Debug, Clone, Default)]
struct DiskPieceCacheState {
    limit: usize,
    backend: DiskPieceCacheV2,
}

#[derive(Debug)]
enum WorkerCommand {
    ReplaceBackingCaches {
        new_cache: DiskPieceCacheV2,
        acknowledgement: oneshot::Sender<()>,
    },
}

#[derive(Debug)]
struct CacheWorkerState {
    heap: UniqueRecordBinaryHeap<KeyWrapper<PieceIndex>>,
    last_segment_index: SegmentIndex,
}

/// Cache worker used to drive the cache
#[derive(Debug)]
#[must_use = "Cache will not work unless its worker is running"]
pub struct CacheWorker<NC>
where
    NC: fmt::Debug,
{
    peer_id: PeerId,
    node_client: NC,
    cache: Arc<RwLock<DiskPieceCacheState>>,
    handlers: Arc<Handlers>,
    worker_receiver: Option<mpsc::Receiver<WorkerCommand>>,
}

impl<NC> CacheWorker<NC>
where
    NC: NodeClient,
{
    /// Run the cache worker with provided piece getter
    pub async fn run<PG>(mut self, piece_getter: PG)
    where
        PG: PieceGetter,
    {
        // Limit is dynamically set later
        let mut worker_state = CacheWorkerState {
            heap: UniqueRecordBinaryHeap::new(self.peer_id, 0),
            last_segment_index: SegmentIndex::ZERO,
        };

        let mut worker_receiver = self
            .worker_receiver
            .take()
            .expect("Always set during worker instantiation");

        if let Some(WorkerCommand::ReplaceBackingCaches {
            new_cache,
            acknowledgement,
        }) = worker_receiver.recv().await
        {
            self.initialize(&piece_getter, &mut worker_state, new_cache)
                .await;
            // Doesn't matter if receiver is still waiting for acknowledgement
            let _ = acknowledgement.send(());
        } else {
            // Piece cache is dropped before backing caches were sent
            return;
        }

        let mut segment_headers_notifications =
            match self.node_client.subscribe_archived_segment_headers().await {
                Ok(segment_headers_notifications) => segment_headers_notifications,
                Err(error) => {
                    error!(%error, "Failed to subscribe to archived segments notifications");
                    return;
                }
            };

        // Keep up with segment indices that were potentially created since reinitialization,
        // depending on the size of the diff this may pause block production for a while (due to
        // subscription we have created above)
        self.keep_up_after_initial_sync(&piece_getter, &mut worker_state)
            .await;

        loop {
            select! {
                maybe_command = worker_receiver.recv().fuse() => {
                    let Some(command) = maybe_command else {
                        // Nothing else left to do
                        return;
                    };

                    self.handle_command(command, &piece_getter, &mut worker_state).await;
                }
                maybe_segment_header = segment_headers_notifications.next().fuse() => {
                    if let Some(segment_header) = maybe_segment_header {
                        self.process_segment_header(segment_header, &mut worker_state).await;
                    } else {
                        // Keep-up sync only ends with subscription, which lasts for duration of an
                        // instance
                        return;
                    }
                }
            }
        }
    }

    async fn handle_command<PG>(
        &self,
        command: WorkerCommand,
        piece_getter: &PG,
        worker_state: &mut CacheWorkerState,
    ) where
        PG: PieceGetter,
    {
        match command {
            WorkerCommand::ReplaceBackingCaches {
                new_cache,
                acknowledgement,
            } => {
                self.initialize(piece_getter, worker_state, new_cache).await;
                // Doesn't matter if receiver is still waiting for acknowledgement
                let _ = acknowledgement.send(());
            }
        }
    }

    async fn initialize<PG>(
        &self,
        piece_getter: &PG,
        worker_state: &mut CacheWorkerState,
        new_cache: DiskPieceCacheV2,
    ) where
        PG: PieceGetter,
    {
        info!("Initializing piece cache");

        let cache = DiskPieceCacheState {
            limit: 10000000,
            backend: new_cache,
        };
        *self.cache.write() = cache.clone();

        info!("Synchronizing piece cache");

        // TODO: Query from the DSN too such that we don't build outdated cache at start if node is
        //  not synced fully
        let last_segment_index = match self.node_client.farmer_app_info().await {
            Ok(farmer_app_info) => farmer_app_info.protocol_info.history_size.segment_index(),
            Err(error) => {
                error!(
                    %error,
                    "Failed to get farmer app info from node, keeping old cache state without \
                    updates"
                );

                return;
            }
        };

        debug!(%last_segment_index, "Identified last segment index");

        worker_state.heap.clear();
        // Change limit to number of pieces
        worker_state.heap.set_limit(cache.limit);

        for segment_index in SegmentIndex::ZERO..=last_segment_index {
            for piece_index in segment_index.segment_piece_indexes() {
                worker_state.heap.insert(KeyWrapper(piece_index));
            }
        }

        // This hashset is faster than `heap`
        // Clippy complains about `RecordKey`, but it is not changing here, so it is fine
        #[allow(clippy::mutable_key_type)]
        let piece_indices_to_store = worker_state
            .heap
            .keys()
            .map(|KeyWrapper(piece_index)| {
                (RecordKey::from(piece_index.to_multihash()), *piece_index)
            })
            .collect::<HashMap<_, _>>();

        debug!(
            count = %piece_indices_to_store.len(),
            "Identified piece indices that should be cached",
        );

        let mut piece_indices_to_store = piece_indices_to_store.into_values();

        let download_piece = |piece_index| async move {
            {
                trace!(%piece_index, "Checking piece");
                let inner_cache = self.cache.read();
                // check stored piece
                match inner_cache.backend.read_piece(piece_index) {
                    Ok(Some(_piece)) => {
                        trace!(%piece_index, "Checked piece successfully");

                        return None;
                    }
                    Ok(None) => {
                        debug!(%piece_index, "Couldn't find piece in local cache");
                    }
                    Err(error) => {
                        error!(%error, %piece_index, "Failed to get piece from local cache");
                    }
                }
            }

            trace!(%piece_index, "Downloading piece");

            let result = piece_getter
                .get_piece(
                    piece_index,
                    PieceGetterRetryPolicy::Limited(PIECE_GETTER_RETRY_NUMBER.get()),
                )
                .await;

            match result {
                Ok(Some(piece)) => {
                    trace!(%piece_index, "Downloaded piece successfully");

                    Some((piece_index, piece))
                }
                Ok(None) => {
                    debug!(%piece_index, "Couldn't find piece");
                    None
                }
                Err(error) => {
                    debug!(%error, %piece_index, "Failed to get piece for piece cache");
                    None
                }
            }
        };

        let pieces_to_download_total = piece_indices_to_store.len();
        let mut downloading_pieces = piece_indices_to_store
            .by_ref()
            .take(CONCURRENT_PIECES_TO_DOWNLOAD)
            .map(download_piece)
            .collect::<FuturesUnordered<_>>();

        let mut downloaded_pieces_count = 0;
        self.handlers.progress.call_simple(&0.0);
        while let Some(maybe_piece) = downloading_pieces.next().await {
            // Push another piece to download
            if let Some(piece_index_to_download) = piece_indices_to_store.next() {
                downloading_pieces.push(download_piece(piece_index_to_download));
            }

            let Some((piece_index, piece)) = maybe_piece else {
                continue;
            };

            if let Err(error) = cache.backend.write_piece(piece_index, &piece) {
                error!(
                    %error,
                    %piece_index,
                    "Failed to write piece into cache"
                );
            }

            downloaded_pieces_count += 1;
            let progress = downloaded_pieces_count as f32 / pieces_to_download_total as f32 * 100.0;
            if downloaded_pieces_count % INTERMEDIATE_CACHE_UPDATE_INTERVAL == 0 {
                *self.cache.write() = cache.clone();

                info!("Piece cache sync {progress:.2}% complete");
            }
            self.handlers.progress.call_simple(&progress);
        }

        *self.cache.write() = cache;
        self.handlers.progress.call_simple(&100.0);
        worker_state.last_segment_index = last_segment_index;

        info!("Finished piece cache synchronization");
    }

    async fn process_segment_header(
        &self,
        segment_header: SegmentHeader,
        worker_state: &mut CacheWorkerState,
    ) {
        let segment_index = segment_header.segment_index();
        debug!(%segment_index, "Starting to process newly archived segment");

        if worker_state.last_segment_index < segment_index {
            debug!(%segment_index, "Downloading potentially useful pieces");

            // We do not insert pieces into cache/heap yet, so we don't know if all of these pieces
            // will be included, but there is a good chance they will be and we want to acknowledge
            // new segment header as soon as possible
            let pieces_to_maybe_include = segment_index
                .segment_piece_indexes()
                .into_iter()
                .filter(|&piece_index| {
                    let maybe_include = worker_state
                        .heap
                        .should_include_key(KeyWrapper(piece_index));
                    if !maybe_include {
                        trace!(%piece_index, "Piece doesn't need to be cached #1");
                    }

                    maybe_include
                })
                .map(|piece_index| async move {
                    let maybe_piece = match self.node_client.piece(piece_index).await {
                        Ok(maybe_piece) => maybe_piece,
                        Err(error) => {
                            error!(
                                %error,
                                %segment_index,
                                %piece_index,
                                "Failed to retrieve piece from node right after archiving, this \
                                should never happen and is an implementation bug"
                            );

                            return None;
                        }
                    };

                    let Some(piece) = maybe_piece else {
                        error!(
                            %segment_index,
                            %piece_index,
                            "Failed to retrieve piece from node right after archiving, this should \
                            never happen and is an implementation bug"
                        );

                        return None;
                    };

                    Some((piece_index, piece))
                })
                .collect::<FuturesUnordered<_>>()
                .filter_map(|maybe_piece| async move { maybe_piece })
                .collect::<Vec<_>>()
                .await;

            debug!(%segment_index, "Downloaded potentially useful pieces");

            self.acknowledge_archived_segment_processing(segment_index)
                .await;

            // Go through potentially matching pieces again now that segment was acknowledged and
            // try to persist them if necessary
            for (piece_index, piece) in pieces_to_maybe_include {
                if !worker_state
                    .heap
                    .should_include_key(KeyWrapper(piece_index))
                {
                    trace!(%piece_index, "Piece doesn't need to be cached #2");

                    continue;
                }

                trace!(%piece_index, "Piece needs to be cached #1");

                self.persist_piece_in_cache(piece_index, piece, worker_state);
            }

            worker_state.last_segment_index = segment_index;
        } else {
            self.acknowledge_archived_segment_processing(segment_index)
                .await;
        }

        debug!(%segment_index, "Finished processing newly archived segment");
    }

    async fn acknowledge_archived_segment_processing(&self, segment_index: SegmentIndex) {
        match self
            .node_client
            .acknowledge_archived_segment_header(segment_index)
            .await
        {
            Ok(()) => {
                debug!(%segment_index, "Acknowledged archived segment");
            }
            Err(error) => {
                error!(%segment_index, ?error, "Failed to acknowledge archived segment");
            }
        };
    }

    async fn keep_up_after_initial_sync<PG>(
        &self,
        piece_getter: &PG,
        worker_state: &mut CacheWorkerState,
    ) where
        PG: PieceGetter,
    {
        let last_segment_index = match self.node_client.farmer_app_info().await {
            Ok(farmer_app_info) => farmer_app_info.protocol_info.history_size.segment_index(),
            Err(error) => {
                error!(
                    %error,
                    "Failed to get farmer app info from node, keeping old cache state without \
                    updates"
                );
                return;
            }
        };

        if last_segment_index <= worker_state.last_segment_index {
            return;
        }

        info!(
            "Syncing piece cache to the latest history size, this may pause block production if \
            takes too long"
        );

        // Keep up with segment indices that were potentially created since reinitialization
        let piece_indices = (worker_state.last_segment_index..=last_segment_index)
            .flat_map(|segment_index| segment_index.segment_piece_indexes());

        // TODO: Can probably do concurrency here
        for piece_index in piece_indices {
            let key = KeyWrapper(piece_index);
            if !worker_state.heap.should_include_key(key) {
                trace!(%piece_index, "Piece doesn't need to be cached #3");

                continue;
            }

            trace!(%piece_index, "Piece needs to be cached #2");

            let result = piece_getter
                .get_piece(
                    piece_index,
                    PieceGetterRetryPolicy::Limited(PIECE_GETTER_RETRY_NUMBER.get()),
                )
                .await;

            let piece = match result {
                Ok(Some(piece)) => piece,
                Ok(None) => {
                    debug!(%piece_index, "Couldn't find piece");
                    continue;
                }
                Err(error) => {
                    debug!(
                        %error,
                        %piece_index,
                        "Failed to get piece for piece cache"
                    );
                    continue;
                }
            };

            self.persist_piece_in_cache(piece_index, piece, worker_state);
        }

        info!("Finished syncing piece cache to the latest history size");

        worker_state.last_segment_index = last_segment_index;
    }

    /// This assumes it was already checked that piece needs to be stored, no verification for this
    /// is done internally and invariants will break if this assumption doesn't hold true
    fn persist_piece_in_cache(
        &self,
        piece_index: PieceIndex,
        piece: Piece,
        worker_state: &mut CacheWorkerState,
    ) {
        let heap_key = KeyWrapper(piece_index);

        let cache = self.cache.write();
        match worker_state.heap.insert(heap_key) {
            // Entry is already occupied, we need to find and replace old piece with new one
            Some(KeyWrapper(old_piece_index)) => {
                if let Err(error) = cache.backend.write_piece(piece_index, &piece) {
                    error!(
                        %error,
                        %piece_index,
                        "Failed to write piece into cache"
                    );
                } else {
                    trace!(
                        %old_piece_index,
                        %piece_index,
                        "Successfully replaced old cached piece"
                    );
                }
            }
            // There is free space in cache, need to find a free spot and place piece there
            None => {
                if let Err(error) = cache.backend.write_piece(piece_index, &piece) {
                    error!(
                        %error,
                        %piece_index,
                        "Failed to write piece into cache"
                    );
                } else {
                    trace!(
                        %piece_index,
                        "Successfully stored piece in cache"
                    );
                }
            }
        };
    }
}

/// Piece cache that aggregates caches of multiple disks
#[derive(Debug, Clone)]
pub struct PieceCache {
    /// Individual disk caches where pieces are stored
    cache: Arc<RwLock<DiskPieceCacheState>>,
    handlers: Arc<Handlers>,
    // We do not want to increase capacity unnecessarily on clone
    worker_sender: mpsc::Sender<WorkerCommand>,
}

impl PieceCache {
    /// Create new piece cache instance and corresponding worker.
    ///
    /// NOTE: Returned future is async, but does blocking operations and should be running in
    /// dedicated thread.
    pub fn new<NC>(node_client: NC, peer_id: PeerId) -> (Self, CacheWorker<NC>)
    where
        NC: NodeClient,
    {
        let cache = Arc::default();
        let (worker_sender, worker_receiver) = mpsc::channel(WORKER_CHANNEL_CAPACITY);
        let handlers = Arc::new(Handlers::default());

        let instance = Self {
            cache: Arc::clone(&cache),
            handlers: Arc::clone(&handlers),
            worker_sender,
        };
        let worker = CacheWorker {
            peer_id,
            node_client,
            cache,
            handlers,
            worker_receiver: Some(worker_receiver),
        };

        (instance, worker)
    }

    /// Get piece from cache
    pub async fn get_piece(&self, piece_index: PieceIndex) -> Option<Piece> {
        let cache = Arc::clone(&self.cache);

        let maybe_piece_fut = tokio::task::spawn_blocking({
            let piece_index = piece_index.clone();

            move || {
                let cache = cache.read();
                match cache.backend.read_piece(piece_index) {
                    Ok(maybe_piece) => maybe_piece,
                    Err(error) => {
                        error!(
                            %error,
                            %piece_index,
                            "Error while reading piece from cache, might be a disk corruption"
                        );

                        None
                    }
                }
            }
        });

        match AsyncJoinOnDrop::new(maybe_piece_fut, false).await {
            Ok(maybe_piece) => maybe_piece,
            Err(error) => {
                error!(%error, %piece_index, "Piece reading task failed");
                None
            }
        }
    }

    /// Initialize replacement of backing caches, returns acknowledgement receiver that can be used
    /// to identify when cache initialization has finished
    pub async fn replace_backing_caches(
        &self,
        new_cache: DiskPieceCacheV2,
    ) -> oneshot::Receiver<()> {
        let (sender, receiver) = oneshot::channel();
        if let Err(error) = self
            .worker_sender
            .send(WorkerCommand::ReplaceBackingCaches {
                new_cache,
                acknowledgement: sender,
            })
            .await
        {
            warn!(%error, "Failed to replace backing caches, worker exited");
        }

        receiver
    }

    /// Subscribe to cache sync notifications
    pub fn on_sync_progress(&self, callback: HandlerFn<f32>) -> HandlerId {
        self.handlers.progress.add(callback)
    }
}

impl LocalRecordProvider for PieceCache {
    fn record(&self, _key: &RecordKey) -> Option<ProviderRecord> {
        None
    }
}
