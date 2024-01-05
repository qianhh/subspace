mod dsn;

use crate::commands::farm::dsn::configure_dsn;
use crate::utils::shutdown_signal;
use anyhow::anyhow;
use clap::{Parser, ValueHint};
use futures::FutureExt;
use lru::LruCache;
use parking_lot::Mutex;
use std::fs;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::pin::pin;
use std::sync::Arc;
use subspace_core_primitives::crypto::kzg::{embedded_kzg_settings, Kzg};
use subspace_farmer::piece_cache::PieceCache;
use subspace_farmer::single_disk_farm::piece_cache_v2::DiskPieceCacheV2;
use subspace_farmer::utils::farmer_piece_getter::FarmerPieceGetter;
use subspace_farmer::utils::piece_validator::SegmentCommitmentPieceValidator;
use subspace_farmer::utils::{run_future_in_dedicated_thread, AsyncJoinOnDrop};
use subspace_farmer::{Identity, NodeClient, NodeRpcClient};
use subspace_metrics::{start_prometheus_metrics_server, RegistryAdapter};
use subspace_networking::libp2p::identity::{ed25519, Keypair};
use subspace_networking::libp2p::Multiaddr;
use subspace_networking::utils::piece_provider::PieceProvider;
use tracing::info;
use zeroize::Zeroizing;

const RECORDS_ROOTS_CACHE_SIZE: NonZeroUsize = NonZeroUsize::new(1_000_000).expect("Not zero; qed");

/// Arguments for farmer
#[derive(Debug, Parser)]
pub(crate) struct FarmingArgs {
    /// Specify base directory
    #[arg(long)]
    base_path: PathBuf,
    /// Specify piece cache directory
    #[arg(long)]
    piece_cache_path: PathBuf,
    /// WebSocket RPC URL of the Subspace node to connect to
    #[arg(long, value_hint = ValueHint::Url, default_value = "ws://127.0.0.1:9944")]
    node_rpc_url: String,
    /// Sets some flags that are convenient during development, currently `--enable-private-ips`.
    #[arg(long)]
    dev: bool,
    /// DSN parameters
    #[clap(flatten)]
    dsn: DsnArgs,
    /// Defines endpoints for the prometheus metrics server. It doesn't start without at least
    /// one specified endpoint. Format: 127.0.0.1:8080
    #[arg(long, alias = "metrics-endpoint")]
    metrics_endpoints: Vec<SocketAddr>,
}

/// Arguments for DSN
#[derive(Debug, Parser)]
struct DsnArgs {
    /// Multiaddrs of bootstrap nodes to connect to on startup, multiple are supported
    #[arg(long)]
    bootstrap_nodes: Vec<Multiaddr>,
    /// Multiaddr to listen on for subspace networking, for instance `/ip4/0.0.0.0/tcp/0`,
    /// multiple are supported.
    #[arg(long, default_values_t = [
        "/ip4/0.0.0.0/udp/30533/quic-v1".parse::<Multiaddr>().expect("Statically correct; qed"),
        "/ip4/0.0.0.0/tcp/30533".parse::<Multiaddr>().expect("Statically correct; qed"),
    ])]
    listen_on: Vec<Multiaddr>,
    /// Determines whether we allow keeping non-global (private, shared, loopback..) addresses in
    /// Kademlia DHT.
    #[arg(long, default_value_t = false)]
    enable_private_ips: bool,
    /// Multiaddrs of reserved nodes to maintain a connection to, multiple are supported
    #[arg(long)]
    reserved_peers: Vec<Multiaddr>,
    /// Defines max established incoming connection limit.
    #[arg(long, default_value_t = 300)]
    in_connections: u32,
    /// Defines max established outgoing swarm connection limit.
    #[arg(long, default_value_t = 100)]
    out_connections: u32,
    /// Defines max pending incoming connection limit.
    #[arg(long, default_value_t = 100)]
    pending_in_connections: u32,
    /// Defines max pending outgoing swarm connection limit.
    #[arg(long, default_value_t = 100)]
    pending_out_connections: u32,
    /// Known external addresses
    #[arg(long, alias = "external-address")]
    external_addresses: Vec<Multiaddr>,
    /// Defines whether we should run blocking Kademlia bootstrap() operation before other requests.
    #[arg(long, default_value_t = false)]
    disable_bootstrap_on_start: bool,
}

/// Start farming by using multiple replica plot in specified path and connecting to WebSocket
/// server at specified address.
pub(crate) async fn farm(farming_args: FarmingArgs) -> anyhow::Result<()>
{
    let signal = shutdown_signal();

    let FarmingArgs {
        base_path,
        piece_cache_path,
        node_rpc_url,
        mut dsn,
        dev,
        metrics_endpoints,
    } = farming_args;

    // Override flags with `--dev`
    dsn.enable_private_ips = dsn.enable_private_ips || dev;
    dsn.disable_bootstrap_on_start = dsn.disable_bootstrap_on_start || dev;

    let readers_and_pieces = Arc::new(Mutex::new(None));

    info!(url = %node_rpc_url, "Connecting to node RPC");
    let node_client = NodeRpcClient::new(&node_rpc_url).await?;

    let farmer_app_info = node_client
        .farmer_app_info()
        .await
        .map_err(|error| anyhow::anyhow!(error))?;

    let base_path_directory = &base_path;
    fs::create_dir_all(base_path_directory)?;

    let identity = Identity::open_or_create(base_path_directory)
        .map_err(|error| anyhow!("Failed to open or create identity: {error}"))?;
    let keypair = derive_libp2p_keypair(identity.secret_key());
    let peer_id = keypair.public().to_peer_id();

    let (piece_cache, piece_cache_worker) = PieceCache::new(node_client.clone(), peer_id);

    let metrics_endpoints_are_specified = !metrics_endpoints.is_empty();

    let (node, mut node_runner, metrics_registry) = {
        if dsn.bootstrap_nodes.is_empty() {
            dsn.bootstrap_nodes = farmer_app_info.dsn_bootstrap_nodes.clone();
        }

        configure_dsn(
            hex::encode(farmer_app_info.genesis_hash),
            base_path_directory,
            keypair,
            dsn,
            Arc::downgrade(&readers_and_pieces),
            node_client.clone(),
            piece_cache.clone(),
            metrics_endpoints_are_specified,
        )?
    };

    let _prometheus_worker = if metrics_endpoints_are_specified {
        let prometheus_task = start_prometheus_metrics_server(
            metrics_endpoints,
            RegistryAdapter::Libp2p(metrics_registry),
        )?;

        let join_handle = tokio::spawn(prometheus_task);
        Some(AsyncJoinOnDrop::new(join_handle, true))
    } else {
        None
    };

    let kzg = Kzg::new(embedded_kzg_settings());
    // TODO: Consider introducing and using global in-memory segment header cache (this comment is
    //  in multiple files)
    let segment_commitments_cache = Mutex::new(LruCache::new(RECORDS_ROOTS_CACHE_SIZE));
    let piece_provider = PieceProvider::new(
        node.clone(),
        Some(SegmentCommitmentPieceValidator::new(
            node.clone(),
            node_client.clone(),
            kzg.clone(),
            segment_commitments_cache,
        )),
    );

    let piece_getter = Arc::new(FarmerPieceGetter::new(
        node.clone(),
        piece_provider,
        piece_cache.clone(),
        node_client.clone(),
        Arc::clone(&readers_and_pieces),
    ));

    let _piece_cache_worker = run_future_in_dedicated_thread(
        {
            let future = piece_cache_worker.run(piece_getter.clone());

            move || future
        },
        "cache-worker".to_string(),
    );

    let cache = DiskPieceCacheV2::new(piece_cache_path)?;
    let cache_acknowledgement_receiver = piece_cache.replace_backing_caches(cache).await;
    drop(piece_cache);

    // Wait for cache initialization before starting plotting
    tokio::spawn(async move {
        if cache_acknowledgement_receiver.await.is_ok() {
            // do something
        }
    });

    // Drop original instance such that the only remaining instances are in `SingleDiskFarm`
    // event handlers
    drop(readers_and_pieces);

    let networking_fut = pin!(run_future_in_dedicated_thread(
        move || async move { node_runner.run().await },
        "farmer-networking".to_string(),
    )?);

    futures::select!(
        // Signal future
        _ = signal.fuse() => {},

        // Node runner future
        _ = networking_fut.fuse() => {
            info!("Node runner exited.")
        },
    );

    anyhow::Ok(())
}

fn derive_libp2p_keypair(schnorrkel_sk: &schnorrkel::SecretKey) -> Keypair {
    let mut secret_bytes = Zeroizing::new(schnorrkel_sk.to_ed25519_bytes());

    let keypair = ed25519::Keypair::from(
        ed25519::SecretKey::try_from_bytes(&mut secret_bytes.as_mut()[..32])
            .expect("Secret key is exactly 32 bytes in size; qed"),
    );

    Keypair::from(keypair)
}
