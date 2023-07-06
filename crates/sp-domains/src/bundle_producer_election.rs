use crate::{DomainId, OperatorPublicKey, StakeWeight};
use parity_scale_codec::{Decode, Encode};
use scale_info::TypeInfo;
use sp_core::crypto::{VrfPublic, Wraps};
use sp_core::sr25519::vrf::{VrfOutput, VrfSignature, VrfTranscript};
use subspace_core_primitives::Blake2b256Hash;

const VRF_TRANSCRIPT_LABEL: &[u8] = b"bundle_producer_election";

/// Generates a domain-specific vrf transcript from given global_challenge.
pub fn make_transcript(domain_id: DomainId, global_challenge: &Blake2b256Hash) -> VrfTranscript {
    VrfTranscript::new(
        VRF_TRANSCRIPT_LABEL,
        &[
            (b"domain", &domain_id.to_le_bytes()),
            (b"global_challenge", global_challenge.as_ref()),
        ],
    )
}

/// Returns the election threshold based on the operator stake proportion and slot probability.
pub fn calculate_threshold(
    operator_stake: StakeWeight,
    total_domain_stake: StakeWeight,
    bundle_slot_probability: (u64, u64),
) -> u128 {
    // The calculation is written for not causing the overflow, which might be harder to
    // understand, the formula in a readable form is as followes:
    //
    //              bundle_slot_probability.0      operator_stake
    // threshold =  ------------------------- * --------------------- * u128::MAX
    //              bundle_slot_probability.1    total_domain_stake
    //
    // TODO: better to have more audits on this calculation.
    u128::MAX / u128::from(bundle_slot_probability.1) * u128::from(bundle_slot_probability.0)
        / total_domain_stake
        * operator_stake
}

pub fn is_below_threshold(vrf_output: &VrfOutput, threshold: u128) -> bool {
    let vrf_output = u128::from_le_bytes(
        vrf_output
            .0
            .to_bytes()
            .split_at(core::mem::size_of::<u128>())
            .0
            .try_into()
            .expect("VrfOutput is 32 bytes which must fit into u128; qed"),
    );

    vrf_output < threshold
}

#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub enum VrfProofError {
    /// Invalid vrf proof.
    BadProof,
}

/// Verify the vrf proof generated in the bundle election.
pub(crate) fn verify_vrf_proof(
    domain_id: DomainId,
    public_key: &OperatorPublicKey,
    vrf_signature: &VrfSignature,
    global_challenge: &Blake2b256Hash,
) -> Result<(), VrfProofError> {
    if !public_key.as_inner_ref().vrf_verify(
        &make_transcript(domain_id, global_challenge).into(),
        vrf_signature,
    ) {
        return Err(VrfProofError::BadProof);
    }

    Ok(())
}
