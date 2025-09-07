#![no_std]
#![doc = include_str!("../README.md")]
#![warn(clippy::pedantic)] // Be pedantic by default
//#![allow(non_snake_case)] // Allow notation matching the spec
#![allow(clippy::module_name_repetitions)] // There are many types of signature and otherwise this gets confusing
#![allow(clippy::similar_names)] // TODO: Consider resolving these
#![allow(clippy::clone_on_copy)] // Be explicit about moving data
#![deny(missing_docs)] // Require all public interfaces to be documented

//! # Usage
//!
//! This crate provides Rust FFI bindings for [`slhdsa-c`](https://github.com/pq-code-package/slhdsa-c),
//! a portable C90 implementation of SLH-DSA ("Stateless Hash-Based Digital Signature Standard")
//! as described in NIST [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final).
//!
//! SLH-DSA (based on the SPHINCS+ submission) is a signature algorithm designed
//! to be resistant to quantum computers.
//!
//! While the API exposed by SLH-DSA is the same as conventional
//! signature schemes, it is important to note that the signatures
//! produced by the algorithm are much larger than classical schemes
//! like EdDSA, ranging from over 7KB for the smallest parameter set to
//! nearly 50KB at the largest
//!
//! Currently this crate only provides FFI bindings.
//!

pub mod ffi;
