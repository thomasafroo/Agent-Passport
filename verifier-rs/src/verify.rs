//! A line-for-line port of `scripts/verify_evidence.py`.
//!
//! Every lookup follows the Python operation it replaces, including how Python behaves
//! on unexpected types (iterating an empty dict or string yields nothing, `"type" in s`
//! on a string is a substring test, `==` compares `1` and `1.0` as equal), so both
//! verifiers reach the same verdict on the same input, not only on well-formed input.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::pybase64::unb64;
use crate::pyjson::{self, PyStr, Value, dict_lookup, py_eq};

/// Why verification failed, by the Python exception it corresponds to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    /// A `ValueError` raised by a check. The message is the Python verifier's, verbatim.
    Check(String),
    /// Input that is not JSON or not valid UTF-8 (a `ValueError` subclass in Python;
    /// the wording differs from Python's).
    Decode(String),
    /// A `KeyError`, `TypeError` or `AttributeError`, reported as a failure.
    Malformed(String),
    /// Input on which the Python CLI exits with an uncaught exception (for example an
    /// `AttributeError` when a list stands where a dict is expected). Still a failure.
    Unsupported(String),
}

impl Failure {
    pub fn message(&self) -> String {
        match self {
            Failure::Check(m) => m.clone(),
            Failure::Decode(m) => format!("invalid JSON: {m}"),
            Failure::Malformed(m) => m.clone(),
            Failure::Unsupported(m) => m.clone(),
        }
    }
}

fn check(msg: &str) -> Failure {
    Failure::Check(msg.to_string())
}

pub const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

const LIMITATION: &str = "Signatures attest issuer statements, not execution truth. A reconciliation attests an operator's decision, not the upstream effect. An approval attests that a named operator approved or denied one exact operation, not that the operator was right. A lifecycle receipt attests an operator's provisioning change, not who the owner is. ";
const ANCHORED: &str = "Checkpoints anchor the chain up to the latest one only as far as the witness copy is independent of the issuer. Events after it are unanchored, and a checkpoint does not make the issuer's log truthful.";
const UNANCHORED: &str =
    "An unanchored event chain cannot prove completeness or prevent wholesale rewriting.";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub events: usize,
    pub receipts: usize,
    pub reconciliations: usize,
    pub approvals: usize,
    pub lifecycle: usize,
    pub head: String,
    pub checkpoints: usize,
    pub anchored_events: usize,
    pub unanchored_events: usize,
    pub limitation: String,
}

impl Report {
    /// The same text `print(json.dumps(result, indent=2))` writes, without the newline.
    pub fn to_json(&self) -> String {
        let n = |v: usize| Value::Int {
            negative: false,
            digits: v.to_string(),
        };
        let obj = Value::Dict(vec![
            (PyStr::new("valid"), Value::Bool(true)),
            (PyStr::new("events"), n(self.events)),
            (PyStr::new("receipts"), n(self.receipts)),
            (PyStr::new("reconciliations"), n(self.reconciliations)),
            (PyStr::new("approvals"), n(self.approvals)),
            (PyStr::new("lifecycle"), n(self.lifecycle)),
            (PyStr::new("head"), Value::str(&self.head)),
            (PyStr::new("checkpoints"), n(self.checkpoints)),
            (PyStr::new("anchored_events"), n(self.anchored_events)),
            (PyStr::new("unanchored_events"), n(self.unanchored_events)),
            (PyStr::new("limitation"), Value::str(&self.limitation)),
        ]);
        pyjson::dumps_indent2(&obj)
    }
}

// ------------------------------------------------------------ Python operations

fn key_error(key: &str) -> Failure {
    Failure::Malformed(format!("'{key}'"))
}

/// `value[key]` with a string key.
fn getitem<'a>(value: &'a Value, key: &str) -> Result<&'a Value, Failure> {
    match value {
        Value::Dict(d) => dict_lookup(d, key).ok_or_else(|| key_error(key)),
        Value::List(_) => Err(Failure::Malformed(
            "list indices must be integers or slices, not str".into(),
        )),
        Value::Str(_) => Err(Failure::Malformed(
            "string indices must be integers, not 'str'".into(),
        )),
        other => Err(Failure::Malformed(format!(
            "'{}' object is not subscriptable",
            other.type_name()
        ))),
    }
}

/// `value.get(key)`; only dicts have `get`.
fn get<'a>(value: &'a Value, key: &str) -> Result<Option<&'a Value>, Failure> {
    match value {
        Value::Dict(d) => Ok(dict_lookup(d, key)),
        other => Err(Failure::Unsupported(format!(
            "'{}' object has no attribute 'get'",
            other.type_name()
        ))),
    }
}

/// `for item in value`: lists yield items, dicts yield keys, strings yield characters.
fn iterate(value: &Value) -> Result<Vec<Value>, Failure> {
    match value {
        Value::List(items) => Ok(items.clone()),
        Value::Dict(d) => Ok(d.iter().map(|(k, _)| Value::Str(k.clone())).collect()),
        Value::Str(s) => Ok(s.0.iter().map(|c| Value::Str(PyStr(vec![*c]))).collect()),
        other => Err(Failure::Malformed(format!(
            "'{}' object is not iterable",
            other.type_name()
        ))),
    }
}

/// `len(value)` for a value that `iterate` accepted.
fn length(value: &Value) -> usize {
    match value {
        Value::List(items) => items.len(),
        Value::Dict(d) => d.len(),
        Value::Str(s) => s.len(),
        _ => 0,
    }
}

/// `"type" in value`.
fn contains(value: &Value, needle: &str) -> Result<bool, Failure> {
    match value {
        Value::Dict(d) => Ok(dict_lookup(d, needle).is_some()),
        Value::List(items) => Ok(items.iter().any(|v| v.is_str(needle))),
        Value::Str(s) => Ok(s.contains(needle)),
        other => Err(Failure::Malformed(format!(
            "argument of type '{}' is not iterable",
            other.type_name()
        ))),
    }
}

/// `agent_passport.core.verify_receipt`: Ed25519 over `canonical(receipt["body"])`,
/// trusting only the caller's key. Any exception there makes it return False.
pub fn verify_receipt(receipt: &Value, public_key: &PyStr) -> bool {
    let attempt = || -> Option<()> {
        let key: [u8; 32] = unb64(public_key)?.try_into().ok()?;
        let key = VerifyingKey::from_bytes(&key).ok()?;
        let Value::Str(signature) = getitem(receipt, "signature").ok()? else {
            return None;
        };
        let signature: [u8; 64] = unb64(signature)?.try_into().ok()?;
        let body = getitem(receipt, "body").ok()?;
        key.verify(&pyjson::canonical(body), &Signature::from_bytes(&signature))
            .ok()
    };
    attempt().is_some()
}

fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn run_id(evidence: &Value) -> Result<&Value, Failure> {
    getitem(getitem(evidence, "run")?, "id")
}

fn hashable(value: &Value) -> Result<(), Failure> {
    if matches!(value, Value::List(_) | Value::Dict(_)) {
        return Err(Failure::Malformed(format!(
            "unhashable type: '{}'",
            value.type_name()
        )));
    }
    Ok(())
}

fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(v) => *v,
        Value::Int { digits, .. } => digits != "0",
        Value::Float(v) => *v != 0.0,
        other => length(other) != 0,
    }
}

// ------------------------------------------------------------ verify

/// `verify(evidence, pinned_key, checkpoints)`. Checkpoints must come from a witness
/// copy, never from the evidence being checked.
pub fn verify(
    evidence: &Value,
    pinned_key: &PyStr,
    checkpoints: &[Value],
) -> Result<Report, Failure> {
    match get(evidence, "public_key")? {
        Some(Value::Str(k)) if k == pinned_key => {}
        _ => return Err(check("Issuer does not match pinned key")),
    }

    let events = getitem(evidence, "events")?;
    let mut previous = ZERO_HASH.to_string();
    let mut hashes: Vec<String> = Vec::new();
    for event in iterate(events)? {
        let Value::Dict(fields) = &event else {
            return Err(Failure::Unsupported(format!(
                "'{}' object has no attribute 'items'",
                event.type_name()
            )));
        };
        let body = Value::Dict(
            fields
                .iter()
                .filter(|(k, _)| !k.is("seq") && !k.is("hash"))
                .cloned()
                .collect(),
        );
        if !getitem(&body, "previous")?.is_str(&previous) {
            return Err(check("Event chain is altered or reordered"));
        }
        let digest = sha256_hex(&pyjson::canonical(&body));
        if !getitem(&event, "hash")?.is_str(&digest) {
            return Err(check("Event chain is altered or reordered"));
        }
        previous = digest;
        hashes.push(previous.clone());
    }

    let empty = Value::List(Vec::new());
    let empty_body = Value::Dict(Vec::new());
    let null = Value::Null;
    let mut owner = Value::Null;
    for grant in iterate(get(evidence, "grants")?.unwrap_or(&empty))? {
        if !truthy(get(&grant, "parent")?.unwrap_or(&null)) {
            owner = get(&grant, "owner")?.unwrap_or(&null).clone();
            break;
        }
    }
    let approvals = get(evidence, "approvals")?.unwrap_or(&empty);
    let mut approved: Vec<(Value, String)> = Vec::new();
    for receipt in iterate(approvals)? {
        let body = get(&receipt, "body")?.unwrap_or(&empty_body);
        if !verify_receipt(&receipt, pinned_key)
            || !matches!(get(body, "type")?, Some(t) if t.is_str("approval"))
        {
            return Err(check("Invalid approval signature"));
        }
        let decision = get(body, "decision")?.unwrap_or(&null);
        if matches!(decision, Value::List(_) | Value::Dict(_)) {
            return Err(Failure::Malformed(format!(
                "unhashable type: '{}'",
                decision.type_name()
            )));
        }
        if !decision.is_str("approved") && !decision.is_str("denied") {
            return Err(check("Invalid approval signature"));
        }
        if !py_eq(getitem(body, "run_id")?, run_id(evidence)?) {
            return Err(check("Approval belongs to another run"));
        }
        if decision.is_str("approved") {
            let id = getitem(body, "operation_id")?;
            hashable(id)?;
            approved.retain(|(key, _)| !py_eq(key, id));
            approved.push((id.clone(), sha256_hex(&pyjson::canonical(body))));
        }
    }

    let receipts = getitem(evidence, "receipts")?;
    for receipt in iterate(receipts)? {
        // Operation receipts carry no type, so a signed reconciliation or checkpoint cannot pose as one.
        if !verify_receipt(&receipt, pinned_key) || contains(getitem(&receipt, "body")?, "type")? {
            return Err(check("Invalid receipt signature"));
        }
        if !py_eq(
            getitem(getitem(&receipt, "body")?, "run_id")?,
            run_id(evidence)?,
        ) {
            return Err(check("Receipt belongs to another run"));
        }
        let body = getitem(&receipt, "body")?;
        if contains(body, "approval")? {
            let id = getitem(body, "operation_id")?;
            hashable(id)?;
            let cited = approved
                .iter()
                .find(|(key, _)| py_eq(key, id))
                .map(|(_, digest)| Value::str(digest))
                .unwrap_or(Value::Null);
            if !py_eq(&cited, getitem(body, "approval")?) {
                return Err(check("Receipt cites an approval missing from the evidence"));
            }
        }
        if !py_eq(get(body, "owner")?.unwrap_or(&null), &owner) {
            return Err(check("Receipt belongs to another owner"));
        }
    }

    let empty = Value::List(Vec::new());
    let reconciliations = get(evidence, "reconciliations")?.unwrap_or(&empty);
    for receipt in iterate(reconciliations)? {
        if !verify_receipt(&receipt, pinned_key)
            || !matches!(get(getitem(&receipt, "body")?, "type")?, Some(t) if t.is_str("reconciliation"))
        {
            return Err(check("Invalid reconciliation signature"));
        }
        if !py_eq(
            getitem(getitem(&receipt, "body")?, "run_id")?,
            run_id(evidence)?,
        ) {
            return Err(check("Reconciliation belongs to another run"));
        }
        if !py_eq(
            get(getitem(&receipt, "body")?, "owner")?.unwrap_or(&null),
            &owner,
        ) {
            return Err(check("Reconciliation belongs to another owner"));
        }
    }

    let lifecycle = get(evidence, "lifecycle")?.unwrap_or(&empty);
    for receipt in iterate(lifecycle)? {
        if !verify_receipt(&receipt, pinned_key)
            || !matches!(get(getitem(&receipt, "body")?, "type")?, Some(t) if t.is_str("lifecycle"))
        {
            return Err(check("Invalid lifecycle signature"));
        }
        if matches!(owner, Value::Null)
            || !py_eq(getitem(getitem(&receipt, "body")?, "owner_id")?, &owner)
        {
            return Err(check("Lifecycle receipt belongs to another owner"));
        }
    }

    let empty_body = Value::Dict(Vec::new());
    let mut anchored = 0usize;
    for checkpoint in checkpoints {
        let body = get(checkpoint, "body")?.unwrap_or(&empty_body);
        if !verify_receipt(checkpoint, pinned_key)
            || !matches!(get(body, "type")?, Some(t) if t.is_str("checkpoint"))
        {
            return Err(check("Invalid checkpoint signature"));
        }
        if !py_eq(getitem(body, "run_id")?, run_id(evidence)?) {
            return Err(check("Checkpoint belongs to another run"));
        }
        let size = match getitem(body, "size")? {
            Value::Int {
                negative: false,
                digits,
            } => digits.clone(),
            _ => return Err(check("Checkpoint size is invalid")),
        };
        if pyjson::int_cmp_usize(&size, hashes.len()).is_gt() {
            return Err(check("Evidence is missing events that a checkpoint covers"));
        }
        let size: usize = size.parse().expect("size fits after the length comparison");
        let expected = if size > 0 {
            hashes[size - 1].as_str()
        } else {
            ZERO_HASH
        };
        if !getitem(body, "head")?.is_str(expected) {
            return Err(check("Event history differs from a checkpoint"));
        }
        anchored = anchored.max(size);
    }

    let chain = if checkpoints.is_empty() {
        UNANCHORED
    } else {
        ANCHORED
    };
    Ok(Report {
        events: length(events),
        receipts: length(receipts),
        reconciliations: length(reconciliations),
        approvals: length(approvals),
        lifecycle: length(lifecycle),
        head: previous,
        checkpoints: checkpoints.len(),
        anchored_events: anchored,
        unanchored_events: hashes.len() - anchored,
        limitation: format!("{LIMITATION}{chain}"),
    })
}

// ------------------------------------------------------------ text handling

/// Python text-mode reading (`newline=None`): `\r\n` and `\r` become `\n`.
pub fn universal_newlines(text: &str) -> String {
    text.replace("\r\n", "\n").replace('\r', "\n")
}

/// `str.isspace()`.
pub fn py_isspace(c: char) -> bool {
    matches!(c, '\t'..='\r' | '\x1c'..='\x1f' | ' ' | '\u{85}' | '\u{a0}' | '\u{1680}' | '\u{2000}'..='\u{200a}'
        | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}')
}

/// `str.strip()`.
pub fn py_strip(text: &str) -> &str {
    text.trim_matches(py_isspace)
}

/// `str.splitlines()`.
pub fn py_splitlines(text: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let mut start = 0;
    let mut chars = text.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        let boundary = matches!(
            c,
            '\n' | '\r'
                | '\x0b'
                | '\x0c'
                | '\x1c'
                | '\x1d'
                | '\x1e'
                | '\u{85}'
                | '\u{2028}'
                | '\u{2029}'
        );
        if boundary {
            lines.push(&text[start..i]);
            let mut end = i + c.len_utf8();
            if c == '\r' && matches!(chars.peek(), Some((_, '\n'))) {
                chars.next();
                end += 1;
            }
            start = end;
        }
    }
    if start < text.len() {
        lines.push(&text[start..]);
    }
    lines
}

/// The pinned key as `verify_evidence.py` reads it from `--public-key-file`.
pub fn key_from_file_text(text: &str) -> PyStr {
    PyStr::new(py_strip(&universal_newlines(text)))
}

/// `load_checkpoints`: parse every non-blank line, keep dicts whose `body` is a dict
/// with this run's `run_id`. `verify` checks their signatures.
pub fn load_checkpoints(text: &str, run_id: &Value) -> Result<Vec<Value>, Failure> {
    let text = universal_newlines(text);
    let mut entries = Vec::new();
    for line in py_splitlines(&text) {
        if !py_strip(line).is_empty() {
            entries.push(pyjson::loads(line).map_err(|e| Failure::Decode(e.0))?);
        }
    }
    let null = Value::Null;
    Ok(entries
        .into_iter()
        .filter(|c| match c.as_dict().and_then(|d| dict_lookup(d, "body")) {
            Some(Value::Dict(body)) => py_eq(dict_lookup(body, "run_id").unwrap_or(&null), run_id),
            _ => false,
        })
        .collect())
}

/// What `main()` does after reading the files: parse the evidence, load this run's
/// checkpoints when a witness file is given, and verify. No filesystem access, so the
/// library also builds for `wasm32-unknown-unknown`.
pub fn verify_text(
    evidence_text: &str,
    pinned_key: &PyStr,
    witness_text: Option<&str>,
) -> Result<Report, Failure> {
    let evidence =
        pyjson::loads(&universal_newlines(evidence_text)).map_err(|e| Failure::Decode(e.0))?;
    let checkpoints = match witness_text {
        Some(text) => {
            let checkpoints = load_checkpoints(text, run_id(&evidence)?)?;
            if checkpoints.is_empty() {
                return Err(check("The witness file holds no checkpoint for this run"));
            }
            checkpoints
        }
        None => Vec::new(),
    };
    verify(&evidence, pinned_key, &checkpoints)
}

/// Byte-level entry point: both files must be UTF-8, as Python's `read_text` requires.
pub fn verify_bytes(
    evidence: &[u8],
    pinned_key: &PyStr,
    witness: Option<&[u8]>,
) -> Result<Report, Failure> {
    let decode = |b: &[u8]| {
        std::str::from_utf8(b)
            .map(str::to_owned)
            .map_err(|e| Failure::Decode(format!("not UTF-8: {e}")))
    };
    let evidence = decode(evidence)?;
    let witness = witness.map(decode).transpose()?;
    verify_text(&evidence, pinned_key, witness.as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splitlines_and_strip_follow_python() {
        assert_eq!(
            py_splitlines("a\x1cb\u{2028}c\u{85}d\r\ne"),
            vec!["a", "b", "c", "d", "e"]
        );
        assert_eq!(py_splitlines("a\n\nb\n"), vec!["a", "", "b"]);
        assert_eq!(py_strip("\x1f key \u{3000}\n"), "key");
    }

    #[test]
    fn python_iteration_quirks() {
        let v = |t: &str| pyjson::loads(t).unwrap();
        assert_eq!(iterate(&v("{}")).unwrap().len(), 0);
        assert_eq!(iterate(&v("\"\"")).unwrap().len(), 0);
        assert!(iterate(&v("null")).is_err());
        assert!(contains(&v("\"prototype\""), "type").unwrap());
        assert!(contains(&v("[\"type\"]"), "type").unwrap());
        assert!(contains(&v("3"), "type").is_err());
    }
}
