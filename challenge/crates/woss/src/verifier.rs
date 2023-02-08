use ckb_vm::{Error, Register};

use crate::{
    machine::{Machine, StepCommitment, StepProof},
    memory::verifier::VerifierSMT,
};

pub struct Verifier<R> {
    machine: Machine<R, VerifierSMT>,
}

impl<R: Register> Verifier<R> {
    pub fn from_proof(proof: StepProof<R>) -> Result<Self, Error> {
        let machine = Machine::restore_from_proof(proof)?;
        Ok(Self { machine })
    }

    pub fn commit_step(&mut self) -> Result<StepCommitment, Error> {
        self.machine.commit_step()
    }

    pub fn execute_next_step(&mut self) -> Result<StepCommitment, Error> {
        self.machine.execute_next_step()?;
        self.commit_step()
    }
}
