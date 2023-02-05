use std::ops::Deref;

use serde::{Deserialize, Serialize};
use sparse_merkle_tree::{traits::Value, H256};

#[derive(Default, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Bytes32([u8; 32]);

impl Bytes32 {
    pub fn from_u8(val: u8) -> Self {
        let mut buf = [0u8; 32];
        buf[0] = val;
        Bytes32(buf)
    }

    pub fn to_u8(&self) -> u8 {
        self.0[0]
    }

    pub fn to_u16(&self) -> u16 {
        u16::from_le_bytes(self.0[0..2].try_into().unwrap())
    }

    pub fn to_u32(&self) -> u32 {
        u32::from_le_bytes(self.0[0..4].try_into().unwrap())
    }

    pub fn from_u64(val: u64) -> Self {
        let mut buf = [0u8; 32];
        buf[0..8].copy_from_slice(&val.to_le_bytes());
        Bytes32(buf)
    }

    pub fn to_u64(&self) -> u64 {
        u64::from_le_bytes(self.0[0..8].try_into().unwrap())
    }

    pub fn read_u64(&self, offset: usize) -> u64 {
        assert!(offset + 8 < 32);
        u64::from_le_bytes(self.0[offset..offset + 8].try_into().unwrap())
    }

    pub fn read_value(&self, buf: &mut [u8], offset: usize, len: usize) {
        assert!((offset + len <= 32) && (len <= buf.len()));
        buf[0..len].copy_from_slice(&self.0[offset..offset + len]);
    }

    pub fn write_value(&mut self, value: &[u8], offset: usize) {
        assert!(offset + value.len() <= 32);
        self.0[offset..offset + value.len()].copy_from_slice(value)
    }
}

impl Deref for Bytes32 {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<[u8; 32]> for Bytes32 {
    fn from(value: [u8; 32]) -> Self {
        Bytes32(value)
    }
}

impl From<Bytes32> for [u8; 32] {
    fn from(value: Bytes32) -> Self {
        value.0
    }
}

impl From<H256> for Bytes32 {
    fn from(value: H256) -> Bytes32 {
        Bytes32(value.into())
    }
}

impl From<Bytes32> for H256 {
    fn from(value: Bytes32) -> Self {
        value.0.into()
    }
}

impl Value for Bytes32 {
    fn zero() -> Self {
        Bytes32([0u8; 32])
    }

    fn to_h256(&self) -> H256 {
        self.0.into()
    }
}
