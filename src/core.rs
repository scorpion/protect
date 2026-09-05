//! Shared building blocks used across connectors and the proxy loop:
//! the `Action` seam, identity, audit logging, transport (`net`/`tls`), and
//! the policy engine. Nothing here knows about any particular wire protocol
//! — that lives under `src/connector/`.

pub mod action;
pub mod audit;
pub mod identity;
pub mod net;
pub mod policy;
pub mod tls;
