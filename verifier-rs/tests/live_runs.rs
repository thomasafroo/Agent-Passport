//! Verify the committed live-run evidence against its committed issuer keys.

use std::path::PathBuf;

use agent_passport_verifier::{Failure, key_from_file_text, verify_bytes};

fn live_runs() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../docs/live-runs")
}

fn read(name: &str) -> Vec<u8> {
    std::fs::read(live_runs().join(name)).unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn key(name: &str) -> agent_passport_verifier::PyStr {
    key_from_file_text(&String::from_utf8(read(name)).unwrap())
}

#[test]
fn runs_1_and_2_verify_against_their_key() {
    for run in ["run1", "run2"] {
        let report = verify_bytes(
            &read(&format!("{run}-evidence.json")),
            &key("issuer-public-key.txt"),
            None,
        )
        .unwrap();
        assert!(report.events > 0 && report.receipts > 0, "{run}");
        assert_eq!(report.anchored_events, 0);
    }
}

#[test]
fn run_4_verifies_against_its_key() {
    let report = verify_bytes(
        &read("run4-evidence.json"),
        &key("run4-issuer-public-key.txt"),
        None,
    )
    .unwrap();
    assert!(report.events > 0);
}

#[test]
fn runs_5_to_9_verify_with_their_witnessed_checkpoints() {
    for n in 5..=9 {
        let evidence = read(&format!("run{n}-evidence.json"));
        let witness = read(&format!("run{n}-checkpoint.jsonl"));
        let pinned = key("run5-9-issuer-public-key.txt");
        let report = verify_bytes(&evidence, &pinned, Some(&witness)).unwrap();
        assert!(
            report.checkpoints >= 1 && report.anchored_events > 0,
            "run{n}"
        );
        assert_eq!(
            report.anchored_events + report.unanchored_events,
            report.events
        );
        let unanchored = verify_bytes(&evidence, &pinned, None).unwrap();
        assert_eq!(unanchored.head, report.head);
    }
}

#[test]
fn committed_evidence_fails_against_another_runs_key() {
    let err = verify_bytes(
        &read("run1-evidence.json"),
        &key("run4-issuer-public-key.txt"),
        None,
    )
    .unwrap_err();
    assert_eq!(
        err,
        Failure::Check("Issuer does not match pinned key".into())
    );
}

#[test]
fn a_checkpoint_from_another_run_is_not_used() {
    let err = verify_bytes(
        &read("run5-evidence.json"),
        &key("run5-9-issuer-public-key.txt"),
        Some(&read("run6-checkpoint.jsonl")),
    )
    .unwrap_err();
    assert_eq!(
        err,
        Failure::Check("The witness file holds no checkpoint for this run".into())
    );
}

#[test]
fn an_edited_committed_event_breaks_the_chain() {
    let text = String::from_utf8(read("run5-evidence.json")).unwrap();
    let edited = text.replacen("\"detail\": \"", "\"detail\": \"x", 1);
    assert_ne!(text, edited);
    let err = verify_bytes(
        edited.as_bytes(),
        &key("run5-9-issuer-public-key.txt"),
        None,
    )
    .unwrap_err();
    assert_eq!(
        err,
        Failure::Check("Event chain is altered or reordered".into())
    );
}
