//! The Stamp aux lib assists various implementations by giving a standard way
//! of interacting with the stamp protocol. This library handles storage of
//! identities, applying various operations to identities, and providing
//! various utilities for interacting with identites.
//!
//! In other words, think of this as a lowest-common-denominator support
//! library for various Stamp user interfaces.

#[macro_use]
pub mod util;
pub mod config;
pub mod db;
pub mod error;
mod models;

pub use models::*;
