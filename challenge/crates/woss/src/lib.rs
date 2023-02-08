#![cfg_attr(not(feature = "std"), no_std)]

pub mod common;
pub mod dissection;
pub mod machine;
pub mod memory;
#[cfg(feature = "std")]
pub mod prover;
pub mod types;
pub mod verifier;

cfg_if::cfg_if! {
    if #[cfg(feature = "std")] {
        use std::vec;
        use std::collections;
        use std::marker;
        use std::cell;
        use std::ops;
        use std::cmp;
        use std::string;
        use std::borrow;
    } else {
        use core::marker;
        use core::cell;
        use core::ops;
        use core::cmp;
        #[macro_use]
        extern crate alloc;
        use alloc::vec;
        use alloc::collections;
        use alloc::string;
        use alloc::borrow;
    }
}
