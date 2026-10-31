//! Independent offline verifier for Agent Passport evidence exports.
//!
//! It reaches the same verdicts as `scripts/verify_evidence.py`: pinned issuer key,
//! hash-linked event chain, operation receipts, reconciliation receipts and witnessed
//! checkpoints. Signatures attest issuer statements, not execution truth, and the key
//! must be pinned out of band. See `docs/rust-verifier.md`.
//!
//! The library does no I/O, so it also builds for `wasm32-unknown-unknown`.

pub mod pybase64;
pub mod pyjson;
mod verify;

pub use pyjson::PyStr;
pub use verify::{
    Failure, Report, ZERO_HASH, key_from_file_text, load_checkpoints, py_splitlines, py_strip,
    verify, verify_bytes, verify_receipt, verify_text,
};
