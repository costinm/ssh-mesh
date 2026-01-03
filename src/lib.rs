#![doc(test(
no_crate_inject,
attr(deny(warnings, rust_2018_idioms), allow(dead_code, unused_variables))
))]

//! Creates a mesh environment, allowing execution of on-demand services.
//!

extern crate libc;

pub mod mesh;
pub mod echo_service;
pub mod pmon;
pub mod lmesh;


