// Copyright The OpenSSL Project Authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! `rustle` — safe abstractions for writing OpenSSL loadable providers in
//! Rust.
//!
//! This crate is **not** a provider itself: it is the FFI layer a provider
//! crate builds on. Every `unsafe` needed to speak the provider ABI lives
//! here, behind safe APIs, so a provider crate can be written under
//! `#![forbid(unsafe_code)]`:
//!
//! - [`digest::Digest`] — implement this safe trait for a hash type and get
//!   the full `OSSL_FUNC_digest_*` dispatch table from
//!   [`digest::DigestAlgorithm::functions`].
//! - [`bindings::OSSL_ALGORITHM::new`] — declare algorithm tables from
//!   `'static` data, validated at `const`-evaluation time.
//! - [`provider::ProviderDesc`] / [`provider::Provider::from_desc`] — declare
//!   the provider descriptor from plain `'static` data, and [`provider_init!`]
//!   to export its `OSSL_provider_init` entry point.
//!
//! The crate is `no_std` by default (enable the `std` feature to link std);
//! operation contexts are managed with the host process's C allocator (the
//! internal `heap` module), so no Rust `alloc` machinery is required.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(all(feature = "abort", not(feature = "std")))]
mod abort;
pub mod bindings;
pub mod debug;
pub mod digest;
mod heap;
pub mod params;
pub mod provider;

pub use rustle_macros::vtable;
