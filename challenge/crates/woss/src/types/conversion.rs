use crate::{borrow::ToOwned, memory::MemoryProof, vec::Vec};

use ckb_vm::RISCV_GENERAL_REGISTER_NUMBER;
use molecule::bytes::Bytes;
pub use molecule::prelude::{Builder, Entity, Reader};

use crate::{
    machine::StepProof,
    types::{packed, Bytes32},
};

#[macro_use]
pub mod macros;

pub trait Unpack<T> {
    fn unpack(&self) -> T;
}

pub trait Pack<T: Entity> {
    fn pack(&self) -> T;
}

pub trait PackVec<T: Entity, I: Entity>: IntoIterator<Item = I> {
    fn pack(self) -> T;
}

impl_conversion_for_step_proof!(StepProof<u32>, StepProof32, StepProof32Reader);
impl_conversion_for_step_proof!(StepProof<u64>, StepProof64, StepProof64Reader);

impl Pack<packed::MemoryProof> for MemoryProof {
    fn pack(&self) -> packed::MemoryProof {
        let kvs: Vec<_> = self.kvs.clone().into_iter().map(|(k, v)| (k, v)).collect();
        packed::MemoryProof::new_builder()
            .memory_size((self.memory_size as u64).pack())
            .root(self.root.pack())
            .kvs(kvs.pack())
            .merkle_proof(self.merkle_proof.pack())
            .build()
    }
}

impl<'r> Unpack<MemoryProof> for packed::MemoryProofReader<'r> {
    #[inline]
    fn unpack(&self) -> MemoryProof {
        MemoryProof {
            memory_size: Unpack::<u64>::unpack(&self.memory_size()) as usize,
            root: self.root().unpack(),
            kvs: self.kvs().iter().map(|kv| kv.unpack()).collect(),
            merkle_proof: self.merkle_proof().unpack(),
        }
    }
}
impl_conversion_for_entity_unpack!(MemoryProof, MemoryProof);

impl_conversion_for_registers!(u32, Uint32Reader, Registers32, Registers32Reader);
impl_conversion_for_registers!(u64, Uint64Reader, Registers64, Registers64Reader);

impl Pack<packed::Uint32> for u32 {
    fn pack(&self) -> packed::Uint32 {
        packed::Uint32::new_unchecked(Bytes::from(self.to_le_bytes().to_vec()))
    }
}

impl Pack<packed::Uint64> for u64 {
    fn pack(&self) -> packed::Uint64 {
        packed::Uint64::new_unchecked(Bytes::from(self.to_le_bytes().to_vec()))
    }
}

impl Pack<packed::Uint64> for usize {
    fn pack(&self) -> packed::Uint64 {
        (*self as u64).pack()
    }
}

impl<'r> Unpack<u32> for packed::Uint32Reader<'r> {
    #[inline]
    fn unpack(&self) -> u32 {
        u32::from_le_bytes(self.as_slice().try_into().expect("unpack Uint32Reader"))
    }
}
impl_conversion_for_entity_unpack!(u32, Uint32);

impl<'r> Unpack<u64> for packed::Uint64Reader<'r> {
    #[inline]
    fn unpack(&self) -> u64 {
        u64::from_le_bytes(self.as_slice().try_into().expect("unpack Uint32Reader"))
    }
}
impl_conversion_for_entity_unpack!(u64, Uint64);

impl<'r> Unpack<usize> for packed::Uint64Reader<'r> {
    fn unpack(&self) -> usize {
        let x: u64 = self.unpack();
        x as usize
    }
}
impl_conversion_for_entity_unpack!(usize, Uint64);

impl Pack<packed::Bytes> for [u8] {
    fn pack(&self) -> packed::Bytes {
        let len = self.len();
        let mut vec: Vec<u8> = Vec::with_capacity(4 + len);
        vec.extend_from_slice(&(len as u32).to_le_bytes()[..]);
        vec.extend_from_slice(self);
        packed::Bytes::new_unchecked(Bytes::from(vec))
    }
}

impl<'r> Unpack<Vec<u8>> for packed::BytesReader<'r> {
    fn unpack(&self) -> Vec<u8> {
        self.raw_data().to_owned()
    }
}
impl_conversion_for_entity_unpack!(Vec<u8>, Bytes);

impl Pack<packed::Bytes32> for Bytes32 {
    fn pack(&self) -> packed::Bytes32 {
        packed::Bytes32::from_slice(&self.0).expect("pack bytes32")
    }
}

impl<'r> Unpack<Bytes32> for packed::Bytes32Reader<'r> {
    #[inline]
    fn unpack(&self) -> Bytes32 {
        let r: [u8; 32] = self.as_slice().try_into().expect("unpack Bytes32Reader");
        r.into()
    }
}
impl_conversion_for_entity_unpack!(Bytes32, Bytes32);

impl Pack<packed::KVPair> for (Bytes32, Bytes32) {
    fn pack(&self) -> packed::KVPair {
        packed::KVPair::new_builder()
            .k(self.0.pack())
            .v(self.1.pack())
            .build()
    }
}

impl_conversion_for_entity_unpack!((Bytes32, Bytes32), KVPair);

impl<'r> Unpack<(Bytes32, Bytes32)> for packed::KVPairReader<'r> {
    fn unpack(&self) -> (Bytes32, Bytes32) {
        (self.k().unpack(), self.v().unpack())
    }
}
impl_conversion_for_vector!((Bytes32, Bytes32), KVPairVec, KVPairVecReader);
impl_conversion_for_packed_iterator_pack!(KVPair, KVPairVec);
