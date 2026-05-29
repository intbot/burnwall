//! Burnwall — local proxy for AI coding tools.
//!
//! Library crate exposing the proxy server, security engine, budget tracker,
//! storage layer, and pricing calculator. The `burnwall` binary is a thin CLI
//! wrapper around this library.
//!
//! See `CLAUDE.md` and `docs/` for the full project specification.

#[cfg(feature = "audit")]
pub mod audit;
pub mod budget;
pub mod cli;
pub mod config;
#[cfg(feature = "logscrape")]
pub mod logscrape;
#[cfg(feature = "mcp")]
pub mod mcp;
#[cfg(feature = "observe")]
pub mod observe;
pub mod pricing;
pub mod providers;
pub mod proxy;
pub mod security;
pub mod storage;
#[cfg(feature = "waste")]
pub mod waste;
