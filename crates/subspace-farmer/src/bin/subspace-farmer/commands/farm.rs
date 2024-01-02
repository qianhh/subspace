mod dsn;

use crate::commands::farm::dsn::configure_dsn;
use crate::utils::shutdown_signal;
use anyhow::anyhow;
use bytesize::ByteSize;
use clap::{Parser, ValueHint};
use futures::FutureExt;
use lru::LruCache;
use parking_lot::Mutex;
use std::fs;
use std::net::SocketAddr;
use std::num::{NonZeroU8, NonZeroUsize};
use std::path::PathBuf;
use std::pin::pin;
use std::str::FromStr;
use std::sync::Arc;
use subspace_core_primitives::crypto::kzg::{embedded_kzg_settings, Kzg};
use subspace_core_primitives::PublicKey;
use subspace_farmer::piece_cache::PieceCache;
use subspace_farmer::single_disk_farm::piece_cache_v2::DiskPieceCacheV2;
use subspace_farmer::utils::farmer_piece_getter::FarmerPieceGetter;
use subspace_farmer::utils::piece_validator::SegmentCommitmentPieceValidator;
use subspace_farmer::utils::ss58::parse_ss58_reward_address;
use subspace_farmer::utils::{run_future_in_dedicated_thread, AsyncJoinOnDrop};
use subspace_farmer::{Identity, NodeClient, NodeRpcClient};
use subspace_metrics::{start_prometheus_metrics_server, RegistryAdapter};
use subspace_networking::libp2p::identity::{ed25519, Keypair};
use subspace_networking::libp2p::Multiaddr;
use subspace_networking::utils::piece_provider::PieceProvider;
use subspace_proof_of_space::Table;
use tempfile::TempDir;
use tracing::{error, info, info_span, warn};
use zeroize::Zeroizing;

const RECORDS_ROOTS_CACHE_SIZE: NonZeroUsize = NonZeroUsize::new(1_000_000).expect("Not zero; qed");

fn available_parallelism() -> usize {
    match std::thread::available_parallelism() {
        Ok(parallelism) => parallelism.get(),
        Err(error) => {
            warn!(
                %error,
                "Unable to identify available parallelism, you might want to configure thread pool sizes with CLI \
                options manually"
            );

            0
        }
    }
}

fn should_farm_during_initial_plotting() -> bool {
    available_parallelism() > 8
}

/// Arguments for farmer
#[derive(Debug, Parser)]
pub(crate) struct FarmingArgs {
    /// One or more farm located at specified path, each with its own allocated space.
    ///
    /// In case of multiple disks, it is recommended to specify them individually rather than using
    /// RAID 0, that way farmer will be able to better take advantage of concurrency of individual
    /// drives.
    ///
    /// Format for each farm is coma-separated list of strings like this:
    ///
    ///   path=/path/to/directory,size=5T
    ///
    /// `size` is max allocated size in human readable format (e.g. 10GB, 2TiB) or just bytes that
    /// farmer will make sure not not exceed (and will pre-allocated all the space on startup to
    /// ensure it will not run out of space in runtime).
    disk_farms: Vec<DiskFarm>,
    /// WebSocket RPC URL of the Subspace node to connect to
    #[arg(long, value_hint = ValueHint::Url, default_value = "ws://127.0.0.1:9944")]
    node_rpc_url: String,
    /// Address for farming rewards
    #[arg(long, value_parser = parse_ss58_reward_address)]
    reward_address: PublicKey,
    /// Percentage of allocated space dedicated for caching purposes, 99% max
    #[arg(long, default_value = "1", value_parser = cache_percentage_parser)]
    cache_percentage: NonZeroU8,
    /// Sets some flags that are convenient during development, currently `--enable-private-ips`.
    #[arg(long)]
    dev: bool,
    /// Run temporary farmer with specified plot size in human readable format (e.g. 10GB, 2TiB) or
    /// just bytes (e.g. 4096), this will create a temporary directory for storing farmer data that
    /// will be deleted at the end of the process.
    #[arg(long, conflicts_with = "disk_farms")]
    tmp: Option<ByteSize>,
    /// Maximum number of pieces in sector (can override protocol value to something lower).
    ///
    /// This will make plotting of individual sectors faster, decrease load on CPU proving, but also
    /// proportionally increase amount of disk reads during audits since every sector needs to be
    /// audited and there will be more of them.
    ///
    /// This is primarily for development and not recommended to use by regular users.
    #[arg(long)]
    max_pieces_in_sector: Option<u16>,
    /// DSN parameters
    #[clap(flatten)]
    dsn: DsnArgs,
    /// Do not print info about configured farms on startup
    #[arg(long)]
    no_info: bool,
    /// Defines endpoints for the prometheus metrics server. It doesn't start without at least
    /// one specified endpoint. Format: 127.0.0.1:8080
    #[arg(long, alias = "metrics-endpoint")]
    metrics_endpoints: Vec<SocketAddr>,
    /// Defines how many sectors farmer will download concurrently, allows to limit memory usage of
    /// the plotting process, increasing beyond 2 makes practical sense due to limited networking
    /// concurrency and will likely result in slower plotting overall
    #[arg(long, default_value = "2")]
    sector_downloading_concurrency: NonZeroUsize,
    /// Defines how many sectors farmer will encode concurrently, should generally never be set to
    /// more than 1 because it will most likely result in slower plotting overall
    #[arg(long, default_value = "1")]
    sector_encoding_concurrency: NonZeroUsize,
    /// Allows to enable farming during initial plotting. Not used by default because plotting is so
    /// intense on CPU and memory that farming will likely not work properly, yet it will
    /// significantly impact plotting speed, delaying the time when farming can actually work
    /// properly.
    #[arg(long, default_value_t = should_farm_during_initial_plotting(), action = clap::ArgAction::Set)]
    farm_during_initial_plotting: bool,
    /// Size of PER FARM thread pool used for farming (mostly for blocking I/O, but also for some
    /// compute-intensive operations during proving), defaults to number of CPU cores available in
    /// the system
    #[arg(long, default_value_t = available_parallelism())]
    farming_thread_pool_size: usize,
    /// Size of PER FARM thread pool used for plotting, defaults to number of CPU cores available
    /// in the system.
    ///
    /// NOTE: The fact that this parameter is per farm doesn't mean farmer will plot multiple
    /// sectors concurrently, see `--sector-downloading-concurrency` and
    /// `--sector-encoding-concurrency` options.
    #[arg(long, default_value_t = available_parallelism())]
    plotting_thread_pool_size: usize,
    /// Size of PER FARM thread pool used for replotting, typically smaller pool than for plotting
    /// to not affect farming as much, defaults to half of the number of CPU cores available in the
    /// system.
    ///
    /// NOTE: The fact that this parameter is per farm doesn't mean farmer will replot multiple
    /// sectors concurrently, see `--sector-downloading-concurrency` and
    /// `--sector-encoding-concurrency` options.
    #[arg(long, default_value_t = available_parallelism() / 2)]
    replotting_thread_pool_size: usize,
}

fn cache_percentage_parser(s: &str) -> anyhow::Result<NonZeroU8> {
    let cache_percentage = NonZeroU8::from_str(s)?;

    if cache_percentage.get() > 99 {
        return Err(anyhow::anyhow!("Cache percentage can't exceed 99"));
    }

    Ok(cache_percentage)
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

#[derive(Debug, Clone)]
pub(crate) struct DiskFarm {
    /// Path to directory where data is stored.
    directory: PathBuf,
    /// How much space in bytes can farm use for plots (metadata space is not included)
    allocated_plotting_space: u64,
}

impl FromStr for DiskFarm {
    type Err = String;

    fn from_str(s: &str) -> anyhow::Result<Self, Self::Err> {
        let parts = s.split(',').collect::<Vec<_>>();
        if parts.len() != 2 {
            return Err("Must contain 2 coma-separated components".to_string());
        }

        let mut plot_directory = None;
        let mut allocated_plotting_space = None;

        for part in parts {
            let part = part.splitn(2, '=').collect::<Vec<_>>();
            if part.len() != 2 {
                return Err("Each component must contain = separating key from value".to_string());
            }

            let key = *part.first().expect("Length checked above; qed");
            let value = *part.get(1).expect("Length checked above; qed");

            match key {
                "path" => {
                    plot_directory.replace(
                        PathBuf::try_from(value).map_err(|error| {
                            format!("Failed to parse `path` \"{value}\": {error}")
                        })?,
                    );
                }
                "size" => {
                    allocated_plotting_space.replace(
                        value
                            .parse::<ByteSize>()
                            .map_err(|error| {
                                format!("Failed to parse `size` \"{value}\": {error}")
                            })?
                            .as_u64(),
                    );
                }
                key => {
                    return Err(format!(
                        "Key \"{key}\" is not supported, only `path` or `size`"
                    ));
                }
            }
        }

        Ok(DiskFarm {
            directory: plot_directory.ok_or({
                "`path` key is required with path to directory where plots will be stored"
            })?,
            allocated_plotting_space: allocated_plotting_space.ok_or({
                "`size` key is required with path to directory where plots will be stored"
            })?,
        })
    }
}

/// Start farming by using multiple replica plot in specified path and connecting to WebSocket
/// server at specified address.
pub(crate) async fn farm<PosTable>(farming_args: FarmingArgs) -> anyhow::Result<()>
where
    PosTable: Table,
{
    let signal = shutdown_signal();

    let FarmingArgs {
        node_rpc_url,
        reward_address,
        max_pieces_in_sector,
        mut dsn,
        cache_percentage,
        no_info,
        dev,
        tmp,
        mut disk_farms,
        metrics_endpoints,
        sector_downloading_concurrency,
        sector_encoding_concurrency,
        farm_during_initial_plotting,
        farming_thread_pool_size,
        plotting_thread_pool_size,
        replotting_thread_pool_size,
    } = farming_args;

    // Override flags with `--dev`
    dsn.enable_private_ips = dsn.enable_private_ips || dev;
    dsn.disable_bootstrap_on_start = dsn.disable_bootstrap_on_start || dev;

    let _tmp_directory = if let Some(plot_size) = tmp {
        let tmp_directory = TempDir::new()?;

        disk_farms = vec![DiskFarm {
            directory: tmp_directory.as_ref().to_path_buf(),
            allocated_plotting_space: plot_size.as_u64(),
        }];

        Some(tmp_directory)
    } else {
        if disk_farms.is_empty() {
            return Err(anyhow!("There must be at least one disk farm provided"));
        }

        for farm in &disk_farms {
            if !farm.directory.exists() {
                if let Err(error) = fs::create_dir(&farm.directory) {
                    return Err(anyhow!(
                        "Directory {} doesn't exist and can't be created: {}",
                        farm.directory.display(),
                        error
                    ));
                }
            }
        }
        None
    };

    let readers_and_pieces = Arc::new(Mutex::new(None));

    info!(url = %node_rpc_url, "Connecting to node RPC");
    let node_client = NodeRpcClient::new(&node_rpc_url).await?;

    let farmer_app_info = node_client
        .farmer_app_info()
        .await
        .map_err(|error| anyhow::anyhow!(error))?;

    let first_farm_directory = &disk_farms
        .first()
        .expect("Disk farm collection is not be empty as checked above; qed")
        .directory;

    let identity = Identity::open_or_create(first_farm_directory)
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
            first_farm_directory,
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

    let cache = DiskPieceCacheV2::new(first_farm_directory.join("pieces"))?;
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
