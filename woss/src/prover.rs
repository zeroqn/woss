use ckb_vm::{Bytes, Error, Register};

use crate::{
    machine::{Machine, RunResult, StepProof},
    memory::prover::ProverSMT,
};

pub struct Prover<R> {
    machine: Machine<R, ProverSMT>,
}

impl<R: Register> Prover<R> {
    pub fn new(memory_size: usize) -> Self {
        let machine = Machine::new(memory_size);
        Self { machine }
    }

    pub fn load_program(&mut self, program: &Bytes) -> Result<u64, Error> {
        self.machine.load_program(program)
    }

    pub fn run(&mut self) -> Result<RunResult, Error> {
        self.machine.run()
    }

    pub fn run_until_step(&mut self, step_num: u64) -> Result<RunResult, Error> {
        self.machine.run_until_step(step_num)
    }

    pub fn prove_next_step(&mut self) -> Result<StepProof<R>, Error> {
        self.machine.prove_next_step()
    }

    pub fn reset(&mut self) {
        self.machine.reset()
    }
}
