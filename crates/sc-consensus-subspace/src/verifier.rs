//! Stateless and parallelized block verification that happens before block is imported (except for locally produced
//! blocks that are imported directly).
//!
//! The goal of verifier is to check internal consistency of the block, which includes things like
//! solution according to claimed inputs, signature, Proof of Time checkpoints in justifications,
//! etc.
//!
//! This should be the majority of the block verification computation such that all that is left for
//! [`block_import`](crate::block_import) to check is that information in the block corresponds to
//! the state of the parent block, which for the most part is comparing bytes against known good
//! values.
//!
//! This is a significant tradeoff in the protocol: having a smaller header vs being able to verify
//! a lot of things stateless and in parallel.

use futures::lock::Mutex;
use rand::prelude::*;
use rayon::prelude::*;
use sc_client_api::backend::AuxStore;
use sc_consensus::block_import::BlockImportParams;
use sc_consensus::import_queue::Verifier;
use sc_consensus_slots::check_equivocation;
use sc_proof_of_time::verifier::PotVerifier;
use sc_telemetry::{telemetry, TelemetryHandle, CONSENSUS_TRACE};
use sc_transaction_pool_api::OffchainTransactionPoolFactory;
use schnorrkel::context::SigningContext;
use sp_api::{ApiExt, BlockT, HeaderT, ProvideRuntimeApi};
use sp_block_builder::BlockBuilder as BlockBuilderApi;
use sp_blockchain::HeaderBackend;
use sp_consensus::BlockOrigin;
use sp_consensus_slots::Slot;
use sp_consensus_subspace::digests::{
    extract_subspace_digest_items, CompatibleDigestItem, PreDigest, SubspaceDigestItems,
};
use sp_consensus_subspace::{
    ChainConstants, FarmerPublicKey, FarmerSignature, PotNextSlotInput, SubspaceApi,
    SubspaceJustification,
};
use sp_runtime::traits::NumberFor;
use sp_runtime::{DigestItem, Justifications};
use std::iter;
use std::marker::PhantomData;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::thread::available_parallelism;
use subspace_core_primitives::crypto::kzg::Kzg;
use subspace_core_primitives::{BlockNumber, PublicKey, RewardSignature};
use subspace_proof_of_space::Table;
use subspace_verification::{check_reward_signature, verify_solution, VerifySolutionParams};
use tokio::sync::Semaphore;
use tracing::{debug, info, trace, warn};

/// This corresponds to default value of `--max-runtime-instances` in Substrate
const BLOCKS_LIST_CHECK_CONCURRENCY: usize = 8;

/// Errors encountered by the Subspace verification task.
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum VerificationError<Header: HeaderT> {
    /// Header has a bad seal
    #[error("Header {0:?} has a bad seal")]
    HeaderBadSeal(Header::Hash),
    /// Header is unsealed
    #[error("Header {0:?} is unsealed")]
    HeaderUnsealed(Header::Hash),
    /// Bad reward signature
    #[error("Bad reward signature on {0:?}")]
    BadRewardSignature(Header::Hash),
    /// Missing Subspace justification
    #[error("Missing Subspace justification")]
    MissingSubspaceJustification,
    /// Invalid Subspace justification
    #[error("Invalid Subspace justification: {0}")]
    InvalidSubspaceJustification(codec::Error),
    /// Invalid Subspace justification contents
    #[error("Invalid Subspace justification contents")]
    InvalidSubspaceJustificationContents,
    /// Invalid proof of time
    #[error("Invalid proof of time")]
    InvalidProofOfTime,
    /// Verification error
    #[error("Verification error on slot {0:?}: {1:?}")]
    VerificationError(Slot, subspace_verification::Error),
}

/// A header which has been checked
struct CheckedHeader<H> {
    /// A header which is fully checked, including signature. This is the pre-header accompanied by
    /// the seal components.
    ///
    /// Includes the digest item that encoded the seal.
    pre_header: H,
    /// Pre-digest
    pre_digest: PreDigest<FarmerPublicKey, FarmerPublicKey>,
    /// Seal (signature)
    seal: DigestItem,
}

/// Subspace verification parameters
struct VerificationParams<'a, Header>
where
    Header: HeaderT + 'a,
{
    /// The header being verified.
    header: Header,
    /// Parameters for solution verification
    verify_solution_params: &'a VerifySolutionParams,
}

/// Options for Subspace block verifier
pub struct SubspaceVerifierOptions<Block, Client, SelectChain>
where
    Block: BlockT,
{
    /// Substrate client
    pub client: Arc<Client>,
    /// Subspace chain constants
    pub chain_constants: ChainConstants,
    /// Kzg instance
    pub kzg: Kzg,
    /// Chain selection rule
    pub select_chain: SelectChain,
    /// Telemetry
    pub telemetry: Option<TelemetryHandle>,
    /// The offchain transaction pool factory.
    ///
    /// Will be used when sending equivocation reports and votes.
    pub offchain_tx_pool_factory: OffchainTransactionPoolFactory<Block>,
    /// Context for reward signing
    pub reward_signing_context: SigningContext,
    /// Approximate target block number for syncing purposes
    pub sync_target_block_number: Arc<AtomicU32>,
    /// Whether this node is authoring blocks
    pub is_authoring_blocks: bool,
    /// Proof of time verifier
    pub pot_verifier: PotVerifier,
}

/// A verifier for Subspace blocks.
pub struct SubspaceVerifier<PosTable, Block, Client, SelectChain>
where
    Block: BlockT,
{
    client: Arc<Client>,
    kzg: Kzg,
    select_chain: SelectChain,
    telemetry: Option<TelemetryHandle>,
    offchain_tx_pool_factory: OffchainTransactionPoolFactory<Block>,
    chain_constants: ChainConstants,
    reward_signing_context: SigningContext,
    sync_target_block_number: Arc<AtomicU32>,
    is_authoring_blocks: bool,
    pot_verifier: PotVerifier,
    equivocation_mutex: Mutex<()>,
    block_list_verification_semaphore: Semaphore,
    _pos_table: PhantomData<PosTable>,
    _block: PhantomData<Block>,
}

impl<PosTable, Block, Client, SelectChain> SubspaceVerifier<PosTable, Block, Client, SelectChain>
where
    PosTable: Table,
    Block: BlockT,
    BlockNumber: From<NumberFor<Block>>,
    Client: AuxStore + HeaderBackend<Block> + ProvideRuntimeApi<Block>,
    Client::Api: BlockBuilderApi<Block> + SubspaceApi<Block, FarmerPublicKey>,
    SelectChain: sp_consensus::SelectChain<Block>,
{
    /// Create new instance
    pub fn new(options: SubspaceVerifierOptions<Block, Client, SelectChain>) -> Self {
        let SubspaceVerifierOptions {
            client,
            chain_constants,
            kzg,
            select_chain,
            telemetry,
            offchain_tx_pool_factory,
            reward_signing_context,
            sync_target_block_number,
            is_authoring_blocks,
            pot_verifier,
        } = options;

        Self {
            client,
            kzg,
            select_chain,
            telemetry,
            offchain_tx_pool_factory,
            chain_constants,
            reward_signing_context,
            sync_target_block_number,
            is_authoring_blocks,
            pot_verifier,
            equivocation_mutex: Mutex::default(),
            block_list_verification_semaphore: Semaphore::new(BLOCKS_LIST_CHECK_CONCURRENCY),
            _pos_table: Default::default(),
            _block: Default::default(),
        }
    }

    /// Determine if full proof of time verification is needed for this block number
    fn full_pot_verification(&self, block_number: NumberFor<Block>) -> bool {
        let sync_target_block_number: BlockNumber =
            self.sync_target_block_number.load(Ordering::Relaxed);
        let Some(diff) = sync_target_block_number.checked_sub(BlockNumber::from(block_number))
        else {
            return true;
        };

        let sample_size = match diff {
            ..=1_581 => {
                return true;
            }
            1_582..=6_234 => 1_581,
            6_235..=63_240 => 3_162 * (diff - 3_162) / (diff - 1),
            63_241..=3_162_000 => 3_162,
            _ => diff / 1_000,
        };

        let n = thread_rng().gen_range(0..=diff);

        n < sample_size
    }

    /// Check a header has been signed correctly and whether solution is correct. If the slot is too
    /// far in the future, an error will be returned. If successful, returns the pre-header and the
    /// digest item containing the seal.
    ///
    /// The seal must be the last digest. Otherwise, the whole header is considered unsigned. This
    /// is required for security and must not be changed.
    ///
    /// This digest item will always return `Some` when used with `as_subspace_pre_digest`.
    ///
    /// `pre_digest` argument is optional in case it is available to avoid doing the work of
    /// extracting it from the header twice.
    async fn check_header(
        &self,
        params: VerificationParams<'_, Block::Header>,
        subspace_digest_items: SubspaceDigestItems<
            FarmerPublicKey,
            FarmerPublicKey,
            FarmerSignature,
        >,
        full_pot_verification: bool,
        justifications: &Option<Justifications>,
    ) -> Result<CheckedHeader<Block::Header>, VerificationError<Block::Header>> {
        let VerificationParams {
            mut header,
            verify_solution_params,
        } = params;

        let pre_digest = subspace_digest_items.pre_digest;
        let slot = pre_digest.slot();

        let seal = header
            .digest_mut()
            .pop()
            .ok_or_else(|| VerificationError::HeaderUnsealed(header.hash()))?;

        let signature = seal
            .as_subspace_seal()
            .ok_or_else(|| VerificationError::HeaderBadSeal(header.hash()))?;

        // The pre-hash of the header doesn't include the seal and that's what we sign
        let pre_hash = header.hash();

        // With justifications we can verify PoT checkpoints quickly and efficiently, the only check
        // that will remain is to ensure that seed and number of iterations (inputs) is correct
        // during block import.
        {
            let Some(subspace_justification) = justifications
                .as_ref()
                .and_then(|justifications| {
                    justifications
                        .iter()
                        .find_map(SubspaceJustification::try_from_justification)
                })
                .transpose()
                .map_err(VerificationError::InvalidSubspaceJustification)?
            else {
                return Err(VerificationError::MissingSubspaceJustification);
            };

            let SubspaceJustification::PotCheckpoints { seed, checkpoints } =
                subspace_justification;

            // Last checkpoint must be our future proof of time, this is how we anchor the rest of
            // checks together
            if checkpoints.last().map(|checkpoints| checkpoints.output())
                != Some(pre_digest.pot_info().future_proof_of_time())
            {
                return Err(VerificationError::InvalidSubspaceJustificationContents);
            }

            let future_slot = slot + self.chain_constants.block_authoring_delay();
            let slot_to_check = Slot::from(
                future_slot
                    .checked_sub(checkpoints.len() as u64 - 1)
                    .ok_or(VerificationError::InvalidProofOfTime)?,
            );
            let slot_iterations = subspace_digest_items
                .pot_parameters_change
                .as_ref()
                .and_then(|parameters_change| {
                    (parameters_change.slot == slot_to_check)
                        .then_some(parameters_change.slot_iterations)
                })
                .unwrap_or(subspace_digest_items.pot_slot_iterations);

            let mut pot_input = PotNextSlotInput {
                slot: slot_to_check,
                slot_iterations,
                seed,
            };
            // Collect all the data we will use for verification so we can process it in parallel
            let checkpoints_verification_input = iter::once((
                pot_input,
                *checkpoints
                    .first()
                    .expect("Not empty, contents was checked above; qed"),
            ));
            let checkpoints_verification_input = checkpoints_verification_input
                .chain(checkpoints.windows(2).map(|checkpoints_pair| {
                    pot_input = PotNextSlotInput::derive(
                        pot_input.slot_iterations,
                        pot_input.slot,
                        checkpoints_pair[0].output(),
                        &subspace_digest_items.pot_parameters_change,
                    );

                    (pot_input, checkpoints_pair[1])
                }))
                .collect::<Vec<_>>();

            // All checkpoints must be valid, at least according to the seed included in
            // justifications, search for the first error
            let pot_verifier = &self.pot_verifier;
            checkpoints_verification_input
                .into_par_iter()
                .find_map_first(|(pot_input, checkpoints)| {
                    if full_pot_verification {
                        // Try to find invalid checkpoints
                        if !pot_verifier.verify_checkpoints(
                            pot_input.seed,
                            pot_input.slot_iterations,
                            &checkpoints,
                        ) {
                            return Some(VerificationError::InvalidProofOfTime);
                        }
                    } else {
                        // We inject verified checkpoints in order to avoid full proving when votes
                        // included in the block will inevitably be verified during block execution
                        pot_verifier.inject_verified_checkpoints(
                            pot_input.seed,
                            pot_input.slot_iterations,
                            checkpoints,
                        );
                    }

                    // We search for errors
                    None
                })
                .map_or(Ok(()), Err)?;
        }

        // Verify that block is signed properly
        if check_reward_signature(
            pre_hash.as_ref(),
            &RewardSignature::from(&signature),
            &PublicKey::from(&pre_digest.solution().public_key),
            &self.reward_signing_context,
        )
        .is_err()
        {
            return Err(VerificationError::BadRewardSignature(pre_hash));
        }

        // Verify that solution is valid
        verify_solution::<PosTable, _, _>(
            pre_digest.solution(),
            slot.into(),
            verify_solution_params,
            &self.kzg,
        )
        .map_err(|error| VerificationError::VerificationError(slot, error))?;

        Ok(CheckedHeader {
            pre_header: header,
            pre_digest,
            seal,
        })
    }

    async fn check_and_report_equivocation(
        &self,
        slot_now: Slot,
        slot: Slot,
        header: &Block::Header,
        author: &FarmerPublicKey,
        origin: &BlockOrigin,
    ) -> Result<(), String> {
        // don't report any equivocations during initial sync
        // as they are most likely stale.
        if *origin == BlockOrigin::NetworkInitialSync {
            return Ok(());
        }

        // Equivocation verification uses `AuxStore` in a way that is not safe from concurrency,
        // this lock ensures that we process one header at a time
        let _guard = self.equivocation_mutex.lock().await;

        // check if authorship of this header is an equivocation and return a proof if so.
        let equivocation_proof =
            match check_equivocation(&*self.client, slot_now, slot, header, author)
                .map_err(|error| error.to_string())?
            {
                Some(proof) => proof,
                None => return Ok(()),
            };

        info!(
            "Slot author {:?} is equivocating at slot {} with headers {:?} and {:?}",
            author,
            slot,
            equivocation_proof.first_header.hash(),
            equivocation_proof.second_header.hash(),
        );

        if self.is_authoring_blocks {
            // get the best block on which we will build and send the equivocation report.
            let best_hash = self
                .select_chain
                .best_chain()
                .await
                .map(|h| h.hash())
                .map_err(|error| error.to_string())?;

            // submit equivocation report at best block.
            let mut runtime_api = self.client.runtime_api();
            // Register the offchain tx pool to be able to use it from the runtime.
            runtime_api.register_extension(
                self.offchain_tx_pool_factory
                    .offchain_transaction_pool(best_hash),
            );
            runtime_api
                .submit_report_equivocation_extrinsic(best_hash, equivocation_proof)
                .map_err(|error| error.to_string())?;

            info!(%author, "Submitted equivocation report for author");
        } else {
            info!("Not submitting equivocation report because node is not authoring blocks");
        }

        Ok(())
    }
}

#[async_trait::async_trait]
impl<PosTable, Block, Client, SelectChain> Verifier<Block>
    for SubspaceVerifier<PosTable, Block, Client, SelectChain>
where
    PosTable: Table,
    Block: BlockT,
    BlockNumber: From<NumberFor<Block>>,
    Client: HeaderBackend<Block> + ProvideRuntimeApi<Block> + Send + Sync + AuxStore,
    Client::Api: BlockBuilderApi<Block> + SubspaceApi<Block, FarmerPublicKey>,
    SelectChain: sp_consensus::SelectChain<Block>,
{
    fn verification_concurrency(&self) -> NonZeroUsize {
        available_parallelism().unwrap_or(NonZeroUsize::new(1).expect("Not zero; qed"))
    }

    async fn verify(
        &self,
        mut block: BlockImportParams<Block>,
    ) -> Result<BlockImportParams<Block>, String> {
        trace!(
            origin = ?block.origin,
            header = ?block.header,
            justifications = ?block.justifications,
            body = ?block.body,
            "Verifying",
        );

        let hash = block.header.hash();

        debug!(
            "We have {:?} logs in this header",
            block.header.digest().logs().len()
        );

        let subspace_digest_items = extract_subspace_digest_items::<
            Block::Header,
            FarmerPublicKey,
            FarmerPublicKey,
            FarmerSignature,
        >(&block.header)?;

        // Check if farmer's plot is burned, ignore runtime API errors since this check will happen
        // during block import anyway
        {
            // We need to limit number of threads to avoid running out of WASM instances
            let _permit = self
                .block_list_verification_semaphore
                .acquire()
                .await
                .expect("Never closed; qed");
            if self
                .client
                .runtime_api()
                .is_in_block_list(
                    *block.header.parent_hash(),
                    &subspace_digest_items.pre_digest.solution().public_key,
                )
                .unwrap_or_default()
            {
                warn!(
                    public_key = %subspace_digest_items.pre_digest.solution().public_key,
                    "Verifying block with solution provided by farmer in block list"
                );

                return Err(format!(
                    "Farmer {} is in block list",
                    subspace_digest_items
                        .pre_digest
                        .solution()
                        .public_key
                        .clone(),
                ));
            }
        }

        let full_pot_verification = self.full_pot_verification(*block.header.number());

        // Stateless header verification only. This means only check that header contains required
        // contents, correct signature and valid Proof-of-Space, but because previous block is not
        // guaranteed to be imported at this point, it is not possible to verify
        // Proof-of-Archival-Storage. In order to verify PoAS randomness and solution range
        // from the header are checked against expected correct values during block import as well
        // as whether piece in the header corresponds to the actual archival history of the
        // blockchain.
        let checked_header = self
            .check_header(
                VerificationParams {
                    header: block.header.clone(),
                    verify_solution_params: &VerifySolutionParams {
                        proof_of_time: subspace_digest_items.pre_digest.pot_info().proof_of_time(),
                        solution_range: subspace_digest_items.solution_range,
                        piece_check_params: None,
                    },
                },
                subspace_digest_items,
                full_pot_verification,
                &block.justifications,
            )
            .await
            .map_err(|error| error.to_string())?;

        let CheckedHeader {
            pre_header,
            pre_digest,
            seal,
        } = checked_header;

        let slot = pre_digest.slot();
        // Estimate what the "current" slot is according to sync target since we don't have other way to know it
        let diff_in_blocks = self
            .sync_target_block_number
            .load(Ordering::Relaxed)
            .saturating_sub(BlockNumber::from(*pre_header.number()));
        let slot_now = if diff_in_blocks > 0 {
            slot + Slot::from(
                u64::from(diff_in_blocks) * self.chain_constants.slot_probability().1
                    / self.chain_constants.slot_probability().0,
            )
        } else {
            slot
        };

        // the header is valid but let's check if there was something else already proposed at the
        // same slot by the given author. if there was, we will report the equivocation to the
        // runtime.
        if let Err(error) = self
            .check_and_report_equivocation(
                slot_now,
                slot,
                &block.header,
                &pre_digest.solution().public_key,
                &block.origin,
            )
            .await
        {
            warn!(
                %error,
                "Error checking/reporting Subspace equivocation"
            );
        }

        trace!(?pre_header, "Checked header; importing");
        telemetry!(
            self.telemetry;
            CONSENSUS_TRACE;
            "subspace.checked_and_importing";
            "pre_header" => ?pre_header,
        );

        block.header = pre_header;
        block.post_digests.push(seal);
        block.post_hash = Some(hash);

        Ok(block)
    }
}
