extern crate alloc;

use ckb_vm::Error;
use sparse_merkle_tree::SMTBuilder;

use crate::types::Bytes32;

use super::{SMTOps, SMTRestore};

pub struct VerifierSMT {
    inner: sparse_merkle_tree::SMT,
    proof: alloc::vec::Vec<u8>,
}

impl SMTOps for VerifierSMT {
    fn update(&mut self, key: Bytes32, value: Bytes32) -> Result<(), Error> {
        self.inner
            .update(&(key.into()), &(value).into())
            .map_err(|err| Error::Unexpected(err.to_string()))?;
        self.inner.normalize();
        Ok(())
    }

    fn get(&self, key: Bytes32) -> Result<Bytes32, Error> {
        self.inner
            .get(&(key.into()))
            .map(Into::into)
            .map_err(|err| Error::Unexpected(err.to_string()))
    }

    fn root(&self) -> Result<Bytes32, Error> {
        self.inner
            .calculate_root(&self.proof)
            .map(Into::into)
            .map_err(|err| Error::Unexpected(err.to_string()))
    }
}

impl Default for VerifierSMT {
    fn default() -> Self {
        VerifierSMT {
            inner: SMTBuilder::default().build().expect("always ok"),
            proof: Default::default(),
        }
    }
}

impl SMTRestore for VerifierSMT {
    fn restore_from_proof(proof: super::MemoryProof) -> Result<Self, Error> {
        let mut builder = SMTBuilder::default();
        for (k, v) in proof.kvs {
            builder = builder
                .insert(&k.into(), &v.into())
                .map_err(|err| Error::Unexpected(err.to_string()))?;
        }

        let inner = { builder.build() }.map_err(|err| Error::Unexpected(err.to_string()))?;
        inner
            .verify(&proof.root.into(), &proof.merkle_proof)
            .map_err(|err| Error::Unexpected(err.to_string()))?;

        let smt = Self {
            inner,
            proof: proof.merkle_proof,
        };

        Ok(smt)
    }
}
