//! `verify-evidence EVIDENCE.json (--public-key-file KEY.txt | --public-key=KEY) [--checkpoints WITNESS.jsonl]`
//!
//! Same arguments, output and exit codes as `scripts/verify_evidence.py`: the report on
//! stdout and exit 0 when valid, `Verification failed: ...` on stderr and exit 1 when
//! not, exit 2 for a usage error.

use std::path::PathBuf;
use std::process::ExitCode;

use agent_passport_verifier::{PyStr, key_from_file_text, verify_bytes};

const USAGE: &str = "usage: verify-evidence [-h] (--public-key PUBLIC_KEY | --public-key-file PUBLIC_KEY_FILE) [--checkpoints CHECKPOINTS] file";
const OPTIONS: [&str; 4] = [
    "--help",
    "--public-key",
    "--public-key-file",
    "--checkpoints",
];

struct Args {
    file: PathBuf,
    public_key: Option<String>,
    public_key_file: Option<PathBuf>,
    checkpoints: Option<PathBuf>,
}

fn usage_error(msg: &str) -> ExitCode {
    eprintln!("{USAGE}\nverify-evidence: error: {msg}");
    ExitCode::from(2)
}

/// argparse treats a leading "-" as an option unless it looks like a negative number.
fn looks_like_option(arg: &str) -> bool {
    if !arg.starts_with('-') || arg == "-" {
        return false;
    }
    let rest = &arg[1..];
    let negative_number = (!rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()))
        || rest.split_once('.').is_some_and(|(a, b)| {
            a.bytes().all(|c| c.is_ascii_digit())
                && !b.is_empty()
                && b.bytes().all(|c| c.is_ascii_digit())
        });
    !negative_number
}

fn parse_args(raw: Vec<String>) -> Result<Option<Args>, String> {
    let (mut file, mut key, mut key_file, mut checkpoints) = (None, None, None, None);
    let mut it = raw.into_iter();
    let mut positional_only = false;
    while let Some(arg) = it.next() {
        if positional_only || !looks_like_option(&arg) {
            if file.is_some() {
                return Err(format!("unrecognized arguments: {arg}"));
            }
            file = Some(arg);
            continue;
        }
        if arg == "--" {
            positional_only = true;
            continue;
        }
        if arg == "-h" {
            return Ok(None);
        }
        let (name, inline) = match arg.split_once('=') {
            Some((n, v)) => (n.to_string(), Some(v.to_string())),
            None => (arg.clone(), None),
        };
        // Exact names win; otherwise a unique prefix, as argparse's allow_abbrev does.
        let option = if OPTIONS.contains(&name.as_str()) {
            name.clone()
        } else {
            let matches: Vec<&str> = OPTIONS
                .iter()
                .copied()
                .filter(|o| name.len() > 2 && o.starts_with(&name))
                .collect();
            match matches.as_slice() {
                [one] => one.to_string(),
                [] => return Err(format!("unrecognized arguments: {arg}")),
                many => {
                    return Err(format!(
                        "ambiguous option: {name} could match {}",
                        many.join(", ")
                    ));
                }
            }
        };
        if option == "--help" {
            return Ok(None);
        }
        let value = match inline {
            Some(v) => v,
            None => match it.next() {
                Some(v) if !looks_like_option(&v) => v,
                _ => return Err(format!("argument {option}: expected one argument")),
            },
        };
        match option.as_str() {
            "--public-key" => key = Some(value),
            "--public-key-file" => key_file = Some(PathBuf::from(value)),
            _ => checkpoints = Some(PathBuf::from(value)),
        }
    }
    if key.is_some() && key_file.is_some() {
        return Err("argument --public-key-file: not allowed with argument --public-key".into());
    }
    let Some(file) = file else {
        return Err("the following arguments are required: file".into());
    };
    if key.is_none() && key_file.is_none() {
        return Err("one of the arguments --public-key --public-key-file is required".into());
    }
    Ok(Some(Args {
        file: PathBuf::from(file),
        public_key: key,
        public_key_file: key_file,
        checkpoints,
    }))
}

fn read(path: &PathBuf) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))
}

fn run(args: Args) -> ExitCode {
    let fail = |msg: String| {
        eprintln!("Verification failed: {msg}");
        ExitCode::from(1)
    };
    let pinned = match (&args.public_key, &args.public_key_file) {
        (Some(k), _) => PyStr::new(k),
        (None, Some(path)) => {
            match read(path).and_then(|b| String::from_utf8(b).map_err(|e| e.to_string())) {
                Ok(text) => key_from_file_text(&text),
                Err(e) => return fail(e),
            }
        }
        (None, None) => unreachable!("argument parsing requires a key"),
    };
    let evidence = match read(&args.file) {
        Ok(b) => b,
        Err(e) => return fail(e),
    };
    let witness = match args.checkpoints.as_ref().map(read).transpose() {
        Ok(w) => w,
        Err(e) => return fail(e),
    };
    match verify_bytes(&evidence, &pinned, witness.as_deref()) {
        Ok(report) => {
            println!("{}", report.to_json());
            ExitCode::SUCCESS
        }
        Err(failure) => fail(failure.message()),
    }
}

fn main() -> ExitCode {
    let raw: Result<Vec<String>, _> = std::env::args_os()
        .skip(1)
        .map(|a| a.into_string())
        .collect();
    let Ok(raw) = raw else {
        return usage_error("arguments must be valid Unicode");
    };
    let args = match parse_args(raw) {
        Ok(Some(args)) => args,
        Ok(None) => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Err(msg) => return usage_error(&msg),
    };
    // Parsing, hashing and dropping nested JSON recurse; give deep documents room.
    std::thread::Builder::new()
        .stack_size(256 << 20)
        .spawn(move || run(args))
        .expect("spawn verifier thread")
        .join()
        .unwrap_or(ExitCode::from(1))
}
