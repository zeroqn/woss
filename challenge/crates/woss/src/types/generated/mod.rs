#![allow(warnings)]
#![allow(unused_imports)]

#[allow(clippy::all)]
mod woss;

pub mod packed {
    pub use super::woss::*;
}
