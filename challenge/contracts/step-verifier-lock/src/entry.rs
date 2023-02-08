// Import from `core` instead of from `std` since we are in no-std mode
use core::result::Result;

// Import CKB syscalls and structures
// https://docs.rs/ckb-std/
use ckb_std::{
    ckb_constants::Source,
    ckb_types::{bytes::Bytes, prelude::*},
    debug,
    high_level::{load_script, load_witness_args},
};
use woss::{
    machine::StepCommitment,
    types::{
        conversion::Unpack as WossUnpack,
        packed::{Bytes32, StepProof32},
    },
    verifier::Verifier,
};

use crate::error::Error;

// This lock is intented to demostrate that Verifer can execute step correctly.
pub fn main() -> Result<(), Error> {
    let witness_args = load_witness_args(0, Source::GroupInput)?;

    let step_proof = {
        let args: Bytes = witness_args
            .lock()
            .to_opt()
            .ok_or(Error::InvalidWitness)?
            .unpack();

        StepProof32::from_slice(&args)
            .map_err(|_| Error::InvalidStepProof)?
            .unpack()
    };
    debug!("step {}", step_proof.step_num);

    let expected_steps = {
        let script = load_script()?;
        let args: Bytes = script.args().unpack();
        if args.len() != 64 {
            debug!("args len {}", args.len());
            return Err(Error::InvalidLockArgs);
        }

        let step_commitment = StepCommitment {
            step_num: step_proof.step_num,
            commitment: Bytes32::new_unchecked(args.slice(0..32)).unpack(),
        };
        debug!("expect commitment {:?}", step_commitment.commitment);

        let next_step_commitment = StepCommitment {
            step_num: step_proof.step_num + 1,
            commitment: Bytes32::new_unchecked(args.slice(32..64)).unpack(),
        };
        debug!(
            "expect next commitment {:?}",
            next_step_commitment.commitment
        );

        (step_commitment, next_step_commitment)
    };

    let mut verifier =
        Verifier::<u32>::from_proof(step_proof).map_err(|_| Error::InvalidStepProof)?;
    let commitment = verifier.commit_step().map_err(|_| Error::VerifierCommit)?;
    if commitment != expected_steps.0 {
        debug!("verifier commitment {:?}", commitment.commitment);
        return Err(Error::MismatchStepCommitment);
    }

    verifier
        .execute_next_step()
        .map_err(|_| Error::ExecuteNextStep)?;

    let next_commitment = verifier.commit_step().map_err(|_| Error::VerifierCommit)?;
    if next_commitment != expected_steps.0 {
        debug!("verifier next commitment {:?}", next_commitment.commitment);
        return Err(Error::MismatchNextStepCommitment);
    }

    Ok(())
}
