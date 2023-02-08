use crate::{collections::BTreeMap, marker::PhantomData, string::ToString, vec::Vec};

use ckb_vm::{
    memory::{fill_page_data, get_page_indices, set_dirty},
    Error, Memory, Register, RISCV_PAGESIZE,
};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::{common::blake2b, types::Bytes32};

#[cfg(feature = "std")]
pub mod prover;
pub mod verifier;

pub trait SMTOps: Default {
    fn update(&mut self, key: Bytes32, value: Bytes32) -> Result<(), Error>;
    fn get(&self, key: Bytes32) -> Result<Bytes32, Error>;
    fn root(&self) -> Result<Bytes32, Error>;
}

pub trait SMTProve: Sized {
    fn snap(&self) -> Self;
    fn prove(&self, key: &[Bytes32]) -> Result<Vec<u8>, Error>;
}

pub trait SMTRestore: Sized {
    fn restore_from_proof(proof: MemoryProof) -> Result<Self, Error>;
}

pub struct MemoryCommitment {
    pub size: u64,
    pub root: Bytes32,
}

#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct MemoryProof {
    pub memory_size: usize,
    pub root: Bytes32,
    #[serde_as(as = "Vec<(_, _)>")]
    pub kvs: BTreeMap<Bytes32, Bytes32>,
    pub merkle_proof: Vec<u8>,
}

pub struct MemoryTracer<S> {
    smt_snap: S,
    kvs: BTreeMap<Bytes32, Bytes32>,
}

impl<S> MemoryTracer<S> {
    pub fn new(smt_snap: S) -> Self {
        Self {
            smt_snap,
            kvs: Default::default(),
        }
    }
}

pub struct SMTMemory<R, S> {
    smt: S,
    tracer: Option<MemoryTracer<S>>,
    memory_size: usize,
    riscv_pages: usize,
    _reg: PhantomData<R>,
}

impl<R: Register, S: SMTOps> SMTMemory<R, S> {
    pub const DATA_CHUNK_SIZE: u64 = 32;

    pub fn flag_key(page: u64) -> Bytes32 {
        blake2b([b"Flag", page.to_le_bytes().as_slice()]).into()
    }

    pub fn data_chunk_key(addr: u64) -> Bytes32 {
        let idx = addr / Self::DATA_CHUNK_SIZE;
        blake2b([b"Data", idx.to_le_bytes().as_slice()]).into()
    }

    pub fn commit_memory(&self) -> Result<MemoryCommitment, Error> {
        let com = MemoryCommitment {
            size: self.memory_size as u64,
            root: self.smt.root()?,
        };

        Ok(com)
    }

    pub fn get_data(
        &mut self,
        addr: u64,
        buf: &mut [u8], // buf to fill
        data_size: u64,
    ) -> Result<(), Error> {
        check_addr(self, addr, data_size)?;

        let mut remain = data_size as usize;
        let mut buf_filled = 0usize;
        let mut addr = addr;

        while remain > 0 {
            let chunk_key = Self::data_chunk_key(addr).into();
            let chunk_offset = addr.rem_euclid(Self::DATA_CHUNK_SIZE) as usize;
            let chunk_available_size = Self::DATA_CHUNK_SIZE as usize - chunk_offset;

            let read_size = crate::cmp::min(chunk_available_size, remain);
            let start = buf_filled;
            let end = buf_filled + read_size;

            let chunk = self.smt_get(chunk_key)?;
            chunk.read_value(&mut buf[start..end], chunk_offset, read_size);

            remain = remain.saturating_sub(read_size);
            buf_filled = buf_filled.saturating_add(read_size);
            addr = addr.saturating_add(read_size as u64);
        }

        Ok(())
    }

    pub fn update_data(&mut self, addr: u64, value: &[u8]) -> Result<(), Error> {
        check_addr(self, addr, value.len() as u64)?;

        let mut remain = value.len();
        let mut value_wrote = 0usize;
        let mut addr = addr;

        while remain > 0 {
            let chunk_key = Self::data_chunk_key(addr).into();
            let chunk_offset = addr.rem_euclid(Self::DATA_CHUNK_SIZE) as usize;
            let chunk_available_size = Self::DATA_CHUNK_SIZE as usize - chunk_offset;

            let write_size = crate::cmp::min(remain, chunk_available_size);
            let start = value_wrote;
            let end = value_wrote + write_size;

            let mut chunk = self.smt_get(chunk_key)?;
            chunk.write_value(&value[start..end], chunk_offset);
            self.smt_update(chunk_key, chunk)?;

            remain = remain.saturating_sub(write_size);
            value_wrote = value_wrote.saturating_add(write_size);
            addr = addr.saturating_add(write_size as u64);
        }

        Ok(())
    }

    fn smt_get(&mut self, key: Bytes32) -> Result<Bytes32, Error> {
        self.record(key)?;

        self.smt
            .get(key)
            .map_err(|err| Error::Unexpected(err.to_string()))
    }

    fn smt_update(&mut self, key: Bytes32, value: Bytes32) -> Result<(), Error> {
        self.record(key)?;

        self.smt
            .update(key.into(), value)
            .map_err(|err| Error::Unexpected(err.to_string()))?;
        Ok(())
    }

    fn record(&mut self, key: Bytes32) -> Result<(), Error> {
        if let Some(tracer) = self.tracer.as_mut() {
            if !tracer.kvs.contains_key(&key) {
                let value = self.smt.get(key)?;
                tracer.kvs.insert(key, value);
            }
        }

        Ok(())
    }
}

impl<R: Register, S: SMTRestore + SMTOps> SMTMemory<R, S> {
    pub fn restore_from_proof(&mut self, proof: MemoryProof) -> Result<(), Error> {
        self.smt = S::restore_from_proof(proof)?;
        Ok(())
    }
}

impl<R: Register, S: SMTProve + SMTOps> SMTMemory<R, S> {
    pub fn enable_tracer(&mut self) {
        self.tracer = Some(MemoryTracer::new(self.smt.snap()))
    }

    pub fn disable_tracer(&mut self) {
        self.tracer = None
    }

    pub fn prove_traces(&self) -> Result<Option<MemoryProof>, Error> {
        let tracer = match self.tracer.as_ref() {
            Some(tracer) => tracer,
            None => return Ok(None),
        };

        let keys: Vec<Bytes32> = tracer.kvs.keys().cloned().collect();
        let proof = MemoryProof {
            root: tracer.smt_snap.root()?,
            memory_size: self.memory_size,
            kvs: tracer.kvs.clone(),
            merkle_proof: tracer.smt_snap.prove(&keys)?,
        };

        Ok(Some(proof))
    }
}

impl<R: Register, S: SMTOps> Memory for SMTMemory<R, S> {
    type REG = R;

    fn new(memory_size: usize) -> Self {
        assert!(memory_size % RISCV_PAGESIZE == 0);

        Self {
            smt: S::default(),
            memory_size,
            riscv_pages: memory_size / RISCV_PAGESIZE,
            tracer: None,
            _reg: PhantomData,
        }
    }

    fn init_pages(
        &mut self,
        addr: u64,
        size: u64,
        _flags: u8,
        source: Option<ckb_vm::Bytes>,
        offset_from_addr: u64,
    ) -> Result<(), Error> {
        fill_page_data(self, addr, size, source, offset_from_addr)
    }

    fn memory_size(&self) -> usize {
        self.memory_size as usize
    }

    fn fetch_flag(&mut self, page: u64) -> Result<u8, Error> {
        if page < self.riscv_pages as u64 {
            Ok(self.smt_get(Self::flag_key(page))?.to_u8())
        } else {
            Err(Error::MemOutOfBound)
        }
    }

    fn set_flag(&mut self, page: u64, flag: u8) -> Result<(), Error> {
        if page < self.riscv_pages as u64 {
            let key = Self::flag_key(page);
            let flag = self.smt_get(key)?.to_u8() | flag;
            self.smt_update(key, Bytes32::from_u8(flag))
        } else {
            Err(Error::MemOutOfBound)
        }
    }

    fn clear_flag(&mut self, page: u64, flag: u8) -> Result<(), Error> {
        if page < self.riscv_pages as u64 {
            let key = Self::flag_key(page);
            let flag = self.smt_get(key)?.to_u8() & !flag;
            self.smt_update(key, Bytes32::from_u8(flag))
        } else {
            Err(Error::MemOutOfBound)
        }
    }

    fn execute_load16(&mut self, addr: u64) -> Result<u16, Error> {
        self.load16(&Self::REG::from_u64(addr)).map(|v| v.to_u16())
    }

    fn execute_load32(&mut self, addr: u64) -> Result<u32, Error> {
        self.load32(&R::from_u64(addr)).map(|v| v.to_u32())
    }

    fn load8(&mut self, addr: &Self::REG) -> Result<Self::REG, Error> {
        let addr = addr.to_u64();
        check_addr(self, addr, 1)?;

        let mut buf = [0u8];
        self.get_data(addr, &mut buf, 1)?;

        Ok(Self::REG::from_u8(buf[0]))
    }

    fn load16(&mut self, addr: &Self::REG) -> Result<Self::REG, Error> {
        let addr = addr.to_u64();
        check_addr(self, addr, 2)?;

        let mut buf = [0u8; 2];
        self.get_data(addr, &mut buf, 2)?;
        let v = u16::from_le_bytes(buf);

        Ok(Self::REG::from_u16(v))
    }

    fn load32(&mut self, addr: &Self::REG) -> Result<Self::REG, Error> {
        let addr = addr.to_u64();
        check_addr(self, addr, 4)?;

        let mut buf = [0u8; 4];
        self.get_data(addr, &mut buf, 4)?;
        let v = u32::from_le_bytes(buf);

        Ok(Self::REG::from_u32(v))
    }

    fn load64(&mut self, addr: &Self::REG) -> Result<Self::REG, Error> {
        let addr = addr.to_u64();
        check_addr(self, addr, 8)?;

        let mut buf = [0u8; 8];
        self.get_data(addr, &mut buf, 8)?;
        let v = u64::from_le_bytes(buf);

        Ok(Self::REG::from_u64(v))
    }

    fn store8(&mut self, addr: &Self::REG, value: &Self::REG) -> Result<(), Error> {
        let addr = addr.to_u64();
        let page_indices = get_page_indices(addr, 1)?;
        set_dirty(self, &page_indices)?;
        self.update_data(addr, &[value.to_u8()])
    }

    fn store16(&mut self, addr: &Self::REG, value: &Self::REG) -> Result<(), Error> {
        let addr = addr.to_u64();
        let page_indices = get_page_indices(addr, 2)?;
        set_dirty(self, &page_indices)?;
        self.update_data(addr, value.to_u16().to_le_bytes().as_slice())
    }

    fn store32(&mut self, addr: &Self::REG, value: &Self::REG) -> Result<(), Error> {
        let addr = addr.to_u64();
        let page_indices = get_page_indices(addr, 4)?;
        set_dirty(self, &page_indices)?;
        self.update_data(addr, value.to_u32().to_le_bytes().as_slice())
    }

    fn store64(&mut self, addr: &Self::REG, value: &Self::REG) -> Result<(), Error> {
        let addr = addr.to_u64();
        let page_indices = get_page_indices(addr, 8)?;
        set_dirty(self, &page_indices)?;
        self.update_data(addr, value.to_u64().to_le_bytes().as_slice())
    }

    fn store_bytes(&mut self, addr: u64, value: &[u8]) -> Result<(), Error> {
        let size = value.len() as u64;
        if size == 0 {
            return Ok(());
        }
        let page_indices = get_page_indices(addr.to_u64(), size)?;
        set_dirty(self, &page_indices)?;
        self.update_data(addr, value)
    }

    fn store_byte(&mut self, addr: u64, size: u64, value: u8) -> Result<(), Error> {
        if size == 0 {
            return Ok(());
        }
        let page_indices = get_page_indices(addr.to_u64(), size)?;
        set_dirty(self, &page_indices)?;

        // TODO: optimize
        let mut remain = size;
        let mut addr = addr;

        while remain > 0 {
            self.update_data(addr, &[value])?;

            remain -= 1;
            addr += 1;
        }

        Ok(())
    }

    fn load_bytes(&mut self, addr: u64, size: u64) -> Result<ckb_vm::Bytes, Error> {
        check_addr(self, addr, size)?;

        let mut buf = ckb_vm::bytes::BytesMut::new();
        buf.resize(size as usize, 0);
        self.get_data(addr, buf.as_mut(), size)?;

        Ok(buf.freeze())
    }
}

pub fn check_addr<M: Memory>(mem: &mut M, addr: u64, offset: u64) -> Result<(), Error> {
    let addr_end = addr.checked_add(offset).ok_or(Error::MemOutOfBound)?;
    if addr_end as usize > mem.memory_size() {
        Err(Error::MemOutOfBound)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ckb_vm::{memory::get_page_indices, FlatMemory, Memory, RISCV_MAX_MEMORY, RISCV_PAGESIZE};
    use proptest::prelude::*;

    use super::{prover::ProverSMT, SMTMemory};

    proptest! {
        #[test]
        fn test_flag(
            page in (0..(RISCV_MAX_MEMORY / RISCV_PAGESIZE) as u64),
            flag in any::<u8>()
        ) {
            let mut smt_mem = SMTMemory::<u64, ProverSMT>::new(RISCV_MAX_MEMORY);
            let mut flat_mem = FlatMemory::<u64>::new(RISCV_MAX_MEMORY);

            prop_assert_eq!(smt_mem.fetch_flag(page).unwrap(), flat_mem.fetch_flag(page).unwrap());

            smt_mem.set_flag(page, flag).unwrap();
            flat_mem.set_flag(page, flag).unwrap();

            prop_assert_eq!(smt_mem.fetch_flag(page).unwrap(), flat_mem.fetch_flag(page).unwrap());

            smt_mem.clear_flag(page, flag).unwrap();
            flat_mem.clear_flag(page, flag).unwrap();

            prop_assert_eq!(smt_mem.fetch_flag(page).unwrap(), flat_mem.fetch_flag(page).unwrap());
        }

        #[test]
        fn test_store8(
            addr in (0..RISCV_MAX_MEMORY as u64),
            value in any::<u8>()
        ) {
            let mut smt_mem = SMTMemory::<u64, ProverSMT>::new(RISCV_MAX_MEMORY);
            let mut flat_mem = FlatMemory::<u64>::new(RISCV_MAX_MEMORY);

            let value = value as u64;
            smt_mem.store8(&addr, &value).unwrap();
            flat_mem.store8(&addr, &value).unwrap();

            let page_indices = get_page_indices(addr, 1).unwrap();
            for page in page_indices.0..=page_indices.1 {
                prop_assert_eq!(
                    smt_mem.fetch_flag(page).unwrap(),
                    flat_mem.fetch_flag(page).unwrap()
                );
            }

            prop_assert_eq!(smt_mem.load8(&addr).unwrap(), flat_mem.load8(&addr).unwrap());
        }

        #[test]
        fn test_store16(
            addr in (0..=(RISCV_MAX_MEMORY - 2) as u64),
            value in any::<u16>()
        ) {
            let mut smt_mem = SMTMemory::<u64, ProverSMT>::new(RISCV_MAX_MEMORY);
            let mut flat_mem = FlatMemory::<u64>::new(RISCV_MAX_MEMORY);

            let value = value as u64;
            smt_mem.store16(&addr, &value).unwrap();
            flat_mem.store16(&addr, &value).unwrap();

            let page_indices = get_page_indices(addr, 2).unwrap();
            for page in page_indices.0..=page_indices.1 {
                assert_eq!(
                    smt_mem.fetch_flag(page).unwrap(),
                    flat_mem.fetch_flag(page).unwrap()
                );
            }

            assert_eq!(
                smt_mem.load16(&addr).unwrap(),
                flat_mem.load16(&addr).unwrap()
            )
        }

        #[test]
        fn test_store32(
            addr in (0..=(RISCV_MAX_MEMORY - 4) as u64),
            value in any::<u32>()
        ) {
            let mut smt_mem = SMTMemory::<u64, ProverSMT>::new(RISCV_MAX_MEMORY);
            let mut flat_mem = FlatMemory::<u64>::new(RISCV_MAX_MEMORY);

            let value = value as u64;
            smt_mem.store32(&addr, &value).unwrap();
            flat_mem.store32(&addr, &value).unwrap();

            let page_indices = get_page_indices(addr, 4).unwrap();
            for page in page_indices.0..=page_indices.1 {
                assert_eq!(
                    smt_mem.fetch_flag(page).unwrap(),
                    flat_mem.fetch_flag(page).unwrap()
                );
            }

            assert_eq!(
                smt_mem.load32(&addr).unwrap(),
                flat_mem.load32(&addr).unwrap()
            )
        }

        #[test]
        fn test_store64(
            addr in (0..=(RISCV_MAX_MEMORY - 8) as u64),
            value in any::<u64>()
        ) {
            let mut smt_mem = SMTMemory::<u64, ProverSMT>::new(RISCV_MAX_MEMORY);
            let mut flat_mem = FlatMemory::<u64>::new(RISCV_MAX_MEMORY);

            let value = value as u64;
            smt_mem.store64(&addr, &value).unwrap();
            flat_mem.store64(&addr, &value).unwrap();

            let page_indices = get_page_indices(addr, 8).unwrap();
            for page in page_indices.0..=page_indices.1 {
                assert_eq!(
                    smt_mem.fetch_flag(page).unwrap(),
                    flat_mem.fetch_flag(page).unwrap()
                );
            }

            assert_eq!(
                smt_mem.load64(&addr).unwrap(),
                flat_mem.load64(&addr).unwrap()
            )
        }

        #[test]
        fn test_store_byte(
            addr in (0..=(RISCV_MAX_MEMORY - 100) as u64),
            size in (0..=100 as u64),
            value in any::<u8>()
        ) {
            let mut smt_mem = SMTMemory::<u64, ProverSMT>::new(RISCV_MAX_MEMORY);
            let mut flat_mem = FlatMemory::<u64>::new(RISCV_MAX_MEMORY);

            smt_mem.store_byte(addr, size, value).unwrap();
            flat_mem.store_byte(addr, size, value).unwrap();

            let page_indices = get_page_indices(addr, size).unwrap();
            for page in page_indices.0..=page_indices.1 {
                assert_eq!(
                    smt_mem.fetch_flag(page).unwrap(),
                    flat_mem.fetch_flag(page).unwrap()
                );
            }

            assert_eq!(
                smt_mem.load_bytes(addr, size).unwrap(),
                flat_mem.load_bytes(addr, size).unwrap()
            );
        }

        #[test]
        fn test_store_bytes(
            addr in (0..=(RISCV_MAX_MEMORY - 100) as u64),
        ) {
            let mut smt_mem = SMTMemory::<u64, ProverSMT>::new(RISCV_MAX_MEMORY);
            let mut flat_mem = FlatMemory::<u64>::new(RISCV_MAX_MEMORY);

            let bytes = [1u8; 100];
            smt_mem.store_bytes(addr, &bytes).unwrap();
            flat_mem.store_bytes(addr, &bytes).unwrap();

            let page_indices = get_page_indices(addr, bytes.len() as u64).unwrap();
            for page in page_indices.0..=page_indices.1 {
                assert_eq!(
                    smt_mem.fetch_flag(page).unwrap(),
                    flat_mem.fetch_flag(page).unwrap()
                );
            }

            assert_eq!(
                smt_mem.load_bytes(addr, bytes.len() as u64).unwrap(),
                flat_mem.load_bytes(addr, bytes.len() as u64).unwrap()
            );
        }
    }
}
