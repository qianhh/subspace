use crate::{ChannelId, Channels, Config};
use frame_support::storage::generator::StorageDoubleMap;
use sp_core::storage::StorageKey;
use sp_core::H256;
use sp_state_machine::backend::Backend;
use sp_state_machine::{prove_read, InMemoryBackend};
use sp_trie::StorageProof;

pub(crate) type DomainId = u64;

macro_rules! impl_runtime {
    ($runtime:ty, $domain_id:literal) => {
        use crate::mock::{mock_system_domain_tracker, DomainId};
        use frame_support::parameter_types;
        use sp_core::H256;
        use sp_runtime::testing::Header;
        use sp_runtime::traits::{BlakeTwo256, ConstU16, ConstU32, ConstU64, IdentityLookup};
        use sp_std::vec::Vec;

        type UncheckedExtrinsic = frame_system::mocking::MockUncheckedExtrinsic<Runtime>;
        type Block = frame_system::mocking::MockBlock<Runtime>;

        frame_support::construct_runtime!(
            pub struct Runtime where
                Block = Block,
                NodeBlock = Block,
                UncheckedExtrinsic = UncheckedExtrinsic,
            {
                System: frame_system::{Pallet, Call, Config, Storage, Event<T>},
                SystemDomainTracker: mock_system_domain_tracker::{Pallet, Storage},
                Messenger: crate::{Pallet, Call, Event<T>}
            }
        );


        impl frame_system::Config for $runtime {
            type BaseCallFilter = frame_support::traits::Everything;
            type BlockWeights = ();
            type BlockLength = ();
            type DbWeight = ();
            type Origin = Origin;
            type Call = Call;
            type Index = u64;
            type BlockNumber = u64;
            type Hash = H256;
            type Hashing = BlakeTwo256;
            type AccountId = u64;
            type Lookup = IdentityLookup<Self::AccountId>;
            type Header = Header;
            type Event = Event;
            type BlockHashCount = ConstU64<250>;
            type Version = ();
            type PalletInfo = PalletInfo;
            type AccountData = ();
            type OnNewAccount = ();
            type OnKilledAccount = ();
            type SystemWeightInfo = ();
            type SS58Prefix = ConstU16<42>;
            type OnSetCode = ();
            type MaxConsumers = ConstU32<16>;
        }

        parameter_types! {
            pub const ExistentialDeposit: u64 = 1;
        }

        impl mock_system_domain_tracker::Config for $runtime {}

        parameter_types! {
            pub const SelfDomainId: DomainId = $domain_id;
        }

        impl crate::Config for $runtime {
            type Event = Event;
            type DomainId = DomainId;
            type SelfDomainId = SelfDomainId;
            type SystemDomainTracker = SystemDomainTracker;
        }

        pub fn new_test_ext() -> sp_io::TestExternalities {
           let t = frame_system::GenesisConfig::default()
                    .build_storage::<Runtime>()
                    .unwrap();

           let mut t: sp_io::TestExternalities = t.into();
           t.execute_with(|| System::set_block_number(1));
           t
        }
    };
}

pub(crate) mod domain_a {
    impl_runtime!(Runtime, 1);
}

pub(crate) mod domain_b {
    impl_runtime!(Runtime, 2);
}

#[frame_support::pallet]
pub(crate) mod mock_system_domain_tracker {
    use frame_support::pallet_prelude::*;
    use sp_core::H256;
    use sp_messenger::SystemDomainTracker as SystemDomainTrackerT;

    #[pallet::config]
    pub trait Config: frame_system::Config {}

    /// Pallet messenger used to communicate between domains and other blockchains.
    #[pallet::pallet]
    #[pallet::generate_store(pub (super) trait Store)]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(_);

    #[pallet::storage]
    pub(super) type StateRoot<T: Config> = StorageValue<_, H256, ValueQuery>;

    impl<T: Config> SystemDomainTrackerT<H256> for Pallet<T> {
        fn latest_state_roots() -> Vec<H256> {
            vec![StateRoot::<T>::get()]
        }
    }
}

fn storage_proof_for_key(
    backend: InMemoryBackend<sp_core::Blake2Hasher>,
    key: StorageKey,
) -> (H256, StorageProof) {
    let state_version = sp_runtime::StateVersion::default();
    let root = backend.storage_root(std::iter::empty(), state_version).0;
    let proof = StorageProof::new(prove_read(backend, &[key]).unwrap().iter_nodes());
    (root, proof)
}

pub(crate) fn storage_proof_of_channels<T: Config>(
    backend: InMemoryBackend<sp_core::Blake2Hasher>,
    domain_id: T::DomainId,
    channel_id: ChannelId,
) -> (H256, StorageKey, StorageProof) {
    let key = Channels::<T>::storage_double_map_final_key(domain_id, channel_id);
    let storage_key = StorageKey(key);
    let (root, proof) = storage_proof_for_key(backend, storage_key.clone());
    (root, storage_key, proof)
}
