//! ZapClaw Tunnels — Secure communication channels.
//!
//! This crate provides:
//! - **Outbound tunnel**: HTTPS proxy with mTLS, domain allowlisting, and rate limiting
//! - **Inbound tunnel**: JSON-RPC 2.0 server for remote task submission
//! - **Telegram**: Telegram bot integration with whitelist enforcement
//!
//! Both are disabled by default and must be explicitly enabled via CLI flags
//! (`--enable-outbound`, `--enable-inbound`, `--enable-telegram`).

pub mod inbound;
pub mod outbound;
pub mod telegram;
