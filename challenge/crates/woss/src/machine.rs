use ckb_vm::{
    decoder::build_decoder, machine::VERSION1, Bytes, CoreMachine, DefaultCoreMachine,
    DefaultMachine, DefaultMachineBuilder, Error, Register, SupportMachine, ISA_IMC,
    RISCV_GENERAL_REGISTER_NUMBER,
};
use serde::{Deserialize, Serialize};

#[cfg(feature = "std")]
use crate::memory::prover::ProverSMT;
use crate::{
    common::{blake2b, blake2b_hasher},
    memory::{verifier::VerifierSMT, MemoryProof, SMTMemory, SMTOps},
    types::Bytes32,
};
use crate::{string::ToString, vec::Vec};

pub type Reg = u32;

#[derive(Debug, PartialEq, Eq, Clone, Copy, PartialOrd, Ord)]
pub struct StepCommitment {
    pub step_num: u64,
    pub commitment: Bytes32,
}

pub struct RunResult {
    pub step_count: u64,
    pub step_commitments: Vec<StepCommitment>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct StepProof<Reg> {
    pub step_num: u64,
    pub registers: [Reg; RISCV_GENERAL_REGISTER_NUMBER],
    pub pc: Reg,
    pub next_pc: Reg,
    pub memory: MemoryProof,
    pub cycles: u64,
    pub max_cycles: u64,
    pub running: bool,
    pub isa: u8,
    pub version: u32,
}

pub struct Machine<R, M> {
    inner: DefaultMachine<DefaultCoreMachine<R, SMTMemory<R, M>>>,
    step: u64,
}

impl<R: Register, M: SMTOps> Machine<R, M> {
    pub fn new(memory_size: usize) -> Self {
        let core = DefaultCoreMachine::<R, _>::new(ISA_IMC, VERSION1, u64::MAX, memory_size);
        let inner = DefaultMachineBuilder::new(core).build();
        Self { inner, step: 0 }
    }

    pub fn load_program(&mut self, program: &Bytes) -> Result<u64, Error> {
        self.inner.load_program(program, &[])
    }

    pub fn reset(&mut self) {
        self.inner.reset(u64::MAX);
        self.step = 0;
    }

    pub fn run(&mut self) -> Result<RunResult, Error> {
        self.run_until_step(u64::MAX)
    }

    pub fn run_until_step(&mut self, step_num: u64) -> Result<RunResult, Error> {
        let mut decoder = build_decoder::<R>(self.inner.isa(), self.inner.version());
        let mut step_commitments: Vec<StepCommitment> = vec![self.commit_step()?];

        self.inner.set_running(true);
        while self.inner.running() && self.step < step_num {
            self.inner.step(&mut decoder)?;
            self.step = self.next_step()?;
            step_commitments.push(self.commit_step()?);
        }

        let ret = RunResult {
            step_count: self.step,
            step_commitments,
        };
        Ok(ret)
    }

    pub fn next_step(&mut self) -> Result<u64, Error> {
        let step_num = self
            .step
            .checked_add(1)
            .ok_or(Error::Unexpected("step overflow".to_string()))?;
        Ok(step_num)
    }

    pub fn execute_next_step(&mut self) -> Result<(), Error> {
        let mut decoder = build_decoder::<R>(self.inner.isa(), self.inner.version());

        self.inner.set_running(true);
        self.inner.step(&mut decoder)?;
        self.step = self.next_step()?;

        Ok(())
    }

    pub fn get_next_pc(&mut self) -> R {
        let pc_backup = self.inner.pc().clone();
        self.inner.commit_pc();
        let next_pc = self.inner.pc().clone();
        self.inner.update_pc(pc_backup);
        next_pc
    }

    pub fn commit_step(&mut self) -> Result<StepCommitment, Error> {
        let com = StepCommitment {
            step_num: self.step,
            commitment: self.commit()?,
        };

        Ok(com)
    }

    pub fn commit(&mut self) -> Result<Bytes32, Error> {
        let mut hasher = blake2b_hasher();

        hasher.update(b"Machine");
        hasher.update(&self.commit_registers());
        hasher.update(&blake2b([
            b"PC",
            R::BITS.to_le_bytes().as_slice(),
            self.inner.pc().to_u64().to_le_bytes().as_slice(),
        ]));
        hasher.update(&self.commit_next_pc());
        hasher.update(&self.commit_memory()?);
        hasher.update(&blake2b([
            b"Cycles",
            self.inner.cycles().to_le_bytes().as_slice(),
        ]));
        hasher.update(&blake2b([
            b"Max_Cycles",
            self.inner.max_cycles().to_le_bytes().as_slice(),
        ]));
        hasher.update(&blake2b([
            b"Running",
            u8::from(self.inner.running()).to_le_bytes().as_slice(),
        ]));
        hasher.update(&blake2b([
            b"ISA",
            self.inner.isa().to_le_bytes().as_slice(),
        ]));
        hasher.update(&blake2b([
            b"Version",
            self.inner.version().to_le_bytes().as_slice(),
        ]));

        let mut buf = [0u8; 32];
        hasher.finalize(&mut buf);
        Ok(buf.into())
    }

    fn commit_next_pc(&mut self) -> Bytes32 {
        let next_pc = self.get_next_pc();
        blake2b([
            b"Next_PC",
            R::BITS.to_le_bytes().as_slice(),
            next_pc.to_u64().to_le_bytes().as_slice(),
        ])
        .into()
    }

    fn commit_memory(&self) -> Result<Bytes32, Error> {
        let mut hasher = blake2b_hasher();
        let mem_com = self.inner.memory().commit_memory()?;

        hasher.update(b"Memory");
        hasher.update(&mem_com.size.to_le_bytes());
        hasher.update(&mem_com.root);

        let mut buf = [0u8; 32];
        hasher.finalize(&mut buf);
        Ok(buf.into())
    }

    fn commit_registers(&self) -> Bytes32 {
        let mut hasher = blake2b_hasher();

        hasher.update(b"Registers");
        self.inner
            .registers()
            .iter()
            .enumerate()
            .for_each(|(idx, r)| {
                hasher.update(&idx.to_le_bytes());
                hasher.update(&R::BITS.to_le_bytes());
                hasher.update(&r.to_u64().to_le_bytes());
            });

        let mut buf = [0u8; 32];
        hasher.finalize(&mut buf);
        buf.into()
    }
}

#[cfg(feature = "std")]
impl<R: Register> Machine<R, ProverSMT> {
    pub fn prove_next_step(&mut self) -> Result<StepProof<R>, Error> {
        let mut decoder = build_decoder::<R>(self.inner.isa(), self.inner.version());
        self.inner.memory_mut().enable_tracer();

        let step_num = self.step;
        let mut registers: [R; RISCV_GENERAL_REGISTER_NUMBER] = Default::default();
        self.inner
            .registers()
            .iter()
            .enumerate()
            .for_each(|(idx, r)| registers[idx] = r.clone());
        let pc = self.inner.pc().clone();
        let next_pc = self.get_next_pc();
        let cycles = self.inner.cycles();
        let max_cycles = self.inner.max_cycles();
        let running = self.inner.running();
        let isa = self.inner.isa();
        let version = self.inner.version();

        self.inner.set_running(true);
        self.inner.step(&mut decoder)?;
        self.step = self.next_step()?;

        let memory = self.inner.memory().prove_traces()?.expect("tracer enabled");

        let step_proof = StepProof {
            step_num,
            registers,
            pc,
            next_pc,
            memory,
            cycles,
            max_cycles,
            running,
            isa,
            version,
        };

        Ok(step_proof)
    }
}

impl<R: Register> Machine<R, VerifierSMT> {
    pub fn restore_from_proof(proof: StepProof<R>) -> Result<Self, Error> {
        let core = DefaultCoreMachine::<R, SMTMemory<R, VerifierSMT>>::new(
            proof.isa,
            proof.version,
            proof.max_cycles,
            proof.memory.memory_size,
        );
        let mut inner = DefaultMachineBuilder::new(core).build();

        for (idx, reg) in proof.registers.into_iter().enumerate() {
            inner.set_register(idx, reg);
        }

        inner.update_pc(proof.pc);
        inner.commit_pc();
        inner.update_pc(proof.next_pc);

        inner.memory_mut().restore_from_proof(proof.memory)?;

        inner.set_cycles(proof.cycles);
        inner.set_running(proof.running);

        Ok(Self {
            inner,
            step: proof.step_num,
        })
    }
}
