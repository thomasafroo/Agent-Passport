//! A JSON model that reproduces what Python's `json.loads` produces and what
//! `agent_passport.core.canonical` (that is, `json.dumps(value, sort_keys=True,
//! separators=(",", ":"), ensure_ascii=True)`) writes back out.
//!
//! Python does not hash the bytes it read. It parses them into Python objects and
//! re-serialises those, so the verifier has to model the objects, not the text:
//!
//! - Strings are sequences of code points, and may hold lone surrogates (`"\ud800"`
//!   parses in Python). They are kept as `Vec<u32>`, never as Rust `String`.
//! - Integers have arbitrary precision. They are kept as sign plus decimal digits and
//!   written back verbatim (`-0` becomes `0`). Python rejects integer literals with
//!   more than 4300 digits, so this parser does too.
//! - Numbers with a fraction or exponent become IEEE doubles and are written back with
//!   Python's `float.__repr__` rules (shortest round-trip digits, exponent form when the
//!   decimal point position is below -3 or above 16, `.0` on integral values). `NaN`,
//!   `Infinity` and `-Infinity` are accepted and written as Python writes them.
//! - Objects keep the first position of a key and the last value, as a Python dict does.
//! - Keys are sorted by code point, which is how Python compares `str`.

use std::cmp::Ordering;
use std::fmt::Write as _;

/// Containers nested deeper than this are rejected. Python's own limit depends on the
/// interpreter and platform (3.13 on Windows accepts 2000 levels and fails before 5000),
/// so evidence nested between this limit and Python's is accepted only by Python.
pub const MAX_DEPTH: usize = 2000;

/// Python's default `sys.int_info.str_digits_check_threshold` limit for `int(str)`.
pub const MAX_INT_DIGITS: usize = 4300;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PyStr(pub Vec<u32>);

impl PyStr {
    pub fn new(s: &str) -> Self {
        PyStr(s.chars().map(|c| c as u32).collect())
    }
    pub fn is(&self, s: &str) -> bool {
        self.0.len() == s.chars().count()
            && self.0.iter().zip(s.chars()).all(|(a, b)| *a == b as u32)
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    /// Python's `needle in haystack` for strings.
    pub fn contains(&self, needle: &str) -> bool {
        let n: Vec<u32> = needle.chars().map(|c| c as u32).collect();
        n.is_empty() || self.0.windows(n.len()).any(|w| w == n.as_slice())
    }
    /// Lossy display form for messages; lone surrogates become U+FFFD.
    pub fn display(&self) -> String {
        self.0
            .iter()
            .map(|&c| char::from_u32(c).unwrap_or('\u{fffd}'))
            .collect()
    }
}

#[derive(Clone, Debug)]
pub enum Value {
    Null,
    Bool(bool),
    /// Arbitrary-precision integer: sign and decimal digits without leading zeros.
    Int {
        negative: bool,
        digits: String,
    },
    Float(f64),
    Str(PyStr),
    List(Vec<Value>),
    /// Insertion-ordered, unique keys.
    Dict(Vec<(PyStr, Value)>),
}

impl Value {
    pub fn str(s: &str) -> Value {
        Value::Str(PyStr::new(s))
    }
    pub fn as_dict(&self) -> Option<&[(PyStr, Value)]> {
        match self {
            Value::Dict(d) => Some(d),
            _ => None,
        }
    }
    pub fn type_name(&self) -> &'static str {
        match self {
            Value::Null => "NoneType",
            Value::Bool(_) => "bool",
            Value::Int { .. } => "int",
            Value::Float(_) => "float",
            Value::Str(_) => "str",
            Value::List(_) => "list",
            Value::Dict(_) => "dict",
        }
    }
    pub fn is_str(&self, s: &str) -> bool {
        matches!(self, Value::Str(v) if v.is(s))
    }
}

pub fn dict_lookup<'a>(d: &'a [(PyStr, Value)], key: &str) -> Option<&'a Value> {
    d.iter().find(|(k, _)| k.is(key)).map(|(_, v)| v)
}

// ---------------------------------------------------------------- parsing

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError(pub String);

/// Parse like Python's `json.loads(text)` with default (strict) settings.
pub fn loads(text: &str) -> Result<Value, ParseError> {
    let chars: Vec<char> = text.chars().collect();
    if chars.first() == Some(&'\u{feff}') {
        return Err(ParseError(
            "Unexpected UTF-8 BOM (decode using utf-8-sig)".into(),
        ));
    }
    let mut p = Parser { s: &chars, i: 0 };
    p.ws();
    let value = p.value(0)?;
    p.ws();
    if p.i != chars.len() {
        return Err(p.err("Extra data"));
    }
    Ok(value)
}

struct Parser<'a> {
    s: &'a [char],
    i: usize,
}

impl Parser<'_> {
    fn err(&self, msg: &str) -> ParseError {
        ParseError(format!("{msg} (char {})", self.i))
    }
    fn peek(&self) -> Option<char> {
        self.s.get(self.i).copied()
    }
    fn ws(&mut self) {
        while matches!(self.peek(), Some(' ' | '\t' | '\n' | '\r')) {
            self.i += 1;
        }
    }
    fn literal(&mut self, word: &str) -> bool {
        let w: Vec<char> = word.chars().collect();
        if self.s.len() >= self.i + w.len() && self.s[self.i..self.i + w.len()] == w[..] {
            self.i += w.len();
            true
        } else {
            false
        }
    }
    fn value(&mut self, depth: usize) -> Result<Value, ParseError> {
        match self.peek() {
            Some('"') => {
                self.i += 1;
                Ok(Value::Str(self.string()?))
            }
            Some('{') => {
                if depth >= MAX_DEPTH {
                    return Err(self.err("Nesting is too deep"));
                }
                self.i += 1;
                self.object(depth + 1)
            }
            Some('[') => {
                if depth >= MAX_DEPTH {
                    return Err(self.err("Nesting is too deep"));
                }
                self.i += 1;
                self.array(depth + 1)
            }
            Some('n') if self.literal("null") => Ok(Value::Null),
            Some('t') if self.literal("true") => Ok(Value::Bool(true)),
            Some('f') if self.literal("false") => Ok(Value::Bool(false)),
            Some('N') if self.literal("NaN") => Ok(Value::Float(f64::NAN)),
            Some('I') if self.literal("Infinity") => Ok(Value::Float(f64::INFINITY)),
            Some('-') if self.literal("-Infinity") => Ok(Value::Float(f64::NEG_INFINITY)),
            Some('-' | '0'..='9') => self.number(),
            _ => Err(self.err("Expecting value")),
        }
    }
    fn digits(&mut self) -> usize {
        let start = self.i;
        while matches!(self.peek(), Some('0'..='9')) {
            self.i += 1;
        }
        self.i - start
    }
    fn number(&mut self) -> Result<Value, ParseError> {
        let start = self.i;
        let negative = self.peek() == Some('-');
        if negative {
            self.i += 1;
        }
        let int_start = self.i;
        match self.peek() {
            Some('0') => self.i += 1,
            Some('1'..='9') => {
                self.digits();
            }
            _ => {
                self.i = start;
                return Err(self.err("Expecting value"));
            }
        }
        let int_end = self.i;
        let mut is_float = false;
        if self.peek() == Some('.') && matches!(self.s.get(self.i + 1), Some('0'..='9')) {
            self.i += 1;
            self.digits();
            is_float = true;
        }
        if matches!(self.peek(), Some('e' | 'E')) {
            let e_start = self.i;
            self.i += 1;
            if matches!(self.peek(), Some('+' | '-')) {
                self.i += 1;
            }
            if self.digits() > 0 {
                is_float = true;
            } else {
                self.i = e_start; // Python backs off; what follows then fails to parse.
            }
        }
        if is_float {
            let text: String = self.s[start..self.i].iter().collect();
            let f: f64 = text.parse().map_err(|_| self.err("Invalid number"))?;
            Ok(Value::Float(f))
        } else {
            let digits: String = self.s[int_start..int_end].iter().collect();
            if digits.len() > MAX_INT_DIGITS {
                return Err(
                    self.err("Exceeds the limit (4300 digits) for integer string conversion")
                );
            }
            Ok(Value::Int {
                negative: negative && digits != "0",
                digits,
            })
        }
    }
    fn hex4(&mut self) -> Result<u32, ParseError> {
        if self.i + 4 > self.s.len() {
            return Err(self.err("Invalid \\uXXXX escape"));
        }
        let mut v = 0u32;
        for k in 0..4 {
            let d = self.s[self.i + k]
                .to_digit(16)
                .ok_or_else(|| self.err("Invalid \\uXXXX escape"))?;
            v = v * 16 + d;
        }
        self.i += 4;
        Ok(v)
    }
    fn string(&mut self) -> Result<PyStr, ParseError> {
        let mut out = Vec::new();
        loop {
            let c = self.peek().ok_or_else(|| self.err("Unterminated string"))?;
            self.i += 1;
            match c {
                '"' => return Ok(PyStr(out)),
                '\\' => {
                    let e = self.peek().ok_or_else(|| self.err("Unterminated string"))?;
                    self.i += 1;
                    let cp = match e {
                        '"' => 0x22,
                        '\\' => 0x5c,
                        '/' => 0x2f,
                        'b' => 0x08,
                        'f' => 0x0c,
                        'n' => 0x0a,
                        'r' => 0x0d,
                        't' => 0x09,
                        'u' => {
                            let mut cp = self.hex4()?;
                            // Join a high surrogate with an immediately following escaped low one.
                            if (0xd800..=0xdbff).contains(&cp)
                                && self.peek() == Some('\\')
                                && self.s.get(self.i + 1) == Some(&'u')
                            {
                                let save = self.i;
                                self.i += 2;
                                let low = self.hex4()?;
                                if (0xdc00..=0xdfff).contains(&low) {
                                    cp = 0x10000 + ((cp - 0xd800) << 10) + (low - 0xdc00);
                                } else {
                                    self.i = save;
                                }
                            }
                            cp
                        }
                        _ => {
                            self.i -= 1;
                            return Err(self.err("Invalid \\escape"));
                        }
                    };
                    out.push(cp);
                }
                c if (c as u32) < 0x20 => {
                    self.i -= 1;
                    return Err(self.err("Invalid control character"));
                }
                c => out.push(c as u32),
            }
        }
    }
    fn object(&mut self, depth: usize) -> Result<Value, ParseError> {
        let mut items: Vec<(PyStr, Value)> = Vec::new();
        self.ws();
        if self.peek() == Some('}') {
            self.i += 1;
            return Ok(Value::Dict(items));
        }
        loop {
            if self.peek() != Some('"') {
                return Err(self.err("Expecting property name enclosed in double quotes"));
            }
            self.i += 1;
            let key = self.string()?;
            self.ws();
            if self.peek() != Some(':') {
                return Err(self.err("Expecting ':' delimiter"));
            }
            self.i += 1;
            self.ws();
            let value = self.value(depth)?;
            match items.iter_mut().find(|(k, _)| *k == key) {
                Some(slot) => slot.1 = value,
                None => items.push((key, value)),
            }
            self.ws();
            match self.peek() {
                Some('}') => {
                    self.i += 1;
                    return Ok(Value::Dict(items));
                }
                Some(',') => {
                    self.i += 1;
                    self.ws();
                }
                _ => return Err(self.err("Expecting ',' delimiter")),
            }
        }
    }
    fn array(&mut self, depth: usize) -> Result<Value, ParseError> {
        let mut items = Vec::new();
        self.ws();
        if self.peek() == Some(']') {
            self.i += 1;
            return Ok(Value::List(items));
        }
        loop {
            items.push(self.value(depth)?);
            self.ws();
            match self.peek() {
                Some(']') => {
                    self.i += 1;
                    return Ok(Value::List(items));
                }
                Some(',') => {
                    self.i += 1;
                    self.ws();
                }
                _ => return Err(self.err("Expecting ',' delimiter")),
            }
        }
    }
}

// ---------------------------------------------------------------- serialising

/// Python's `canonical(value)`: sorted keys, compact separators, ASCII-only output.
pub fn canonical(value: &Value) -> Vec<u8> {
    let mut out = String::new();
    write_value(&mut out, value, None, 0);
    out.into_bytes()
}

/// Python's `json.dumps(value, indent=2)` (default separators become `", "`/`": "`,
/// but with an indent the item separator is `","` followed by a newline).
pub fn dumps_indent2(value: &Value) -> String {
    let mut out = String::new();
    write_value(&mut out, value, Some(2), 0);
    out
}

fn write_value(out: &mut String, value: &Value, indent: Option<usize>, level: usize) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Int { negative, digits } => {
            if *negative {
                out.push('-');
            }
            out.push_str(digits);
        }
        Value::Float(f) => out.push_str(&float_repr(*f)),
        Value::Str(s) => write_str(out, s),
        Value::List(items) => {
            if items.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push('[');
            for (n, item) in items.iter().enumerate() {
                if n > 0 {
                    out.push(',');
                }
                newline(out, indent, level + 1);
                write_value(out, item, indent, level + 1);
            }
            newline(out, indent, level);
            out.push(']');
        }
        Value::Dict(items) => {
            if items.is_empty() {
                out.push_str("{}");
                return;
            }
            let mut sorted: Vec<&(PyStr, Value)> = items.iter().collect();
            if indent.is_none() {
                sorted.sort_by(|a, b| a.0.cmp(&b.0));
            }
            out.push('{');
            for (n, (k, v)) in sorted.into_iter().enumerate() {
                if n > 0 {
                    out.push(',');
                }
                newline(out, indent, level + 1);
                write_str(out, k);
                out.push(':');
                if indent.is_some() {
                    out.push(' ');
                }
                write_value(out, v, indent, level + 1);
            }
            newline(out, indent, level);
            out.push('}');
        }
    }
}

fn newline(out: &mut String, indent: Option<usize>, level: usize) {
    if let Some(n) = indent {
        out.push('\n');
        out.extend(std::iter::repeat_n(' ', n * level));
    }
}

/// `ensure_ascii=True` string escaping, as CPython's `ascii_escape_unichar`.
fn write_str(out: &mut String, s: &PyStr) {
    out.push('"');
    for &c in &s.0 {
        match c {
            0x22 => out.push_str("\\\""),
            0x5c => out.push_str("\\\\"),
            0x08 => out.push_str("\\b"),
            0x0c => out.push_str("\\f"),
            0x0a => out.push_str("\\n"),
            0x0d => out.push_str("\\r"),
            0x09 => out.push_str("\\t"),
            0x20..=0x7e => out.push(c as u8 as char),
            0x10000.. => {
                let v = c - 0x10000;
                let _ = write!(
                    out,
                    "\\u{:04x}\\u{:04x}",
                    0xd800 + (v >> 10),
                    0xdc00 + (v & 0x3ff)
                );
            }
            _ => {
                let _ = write!(out, "\\u{c:04x}");
            }
        }
    }
    out.push('"');
}

/// Python's `float.__repr__` as `json.dumps` uses it, including its special values.
pub fn float_repr(f: f64) -> String {
    if f.is_nan() {
        return "NaN".into();
    }
    if f.is_infinite() {
        return if f > 0.0 {
            "Infinity".into()
        } else {
            "-Infinity".into()
        };
    }
    let sign = if f.is_sign_negative() { "-" } else { "" };
    if f == 0.0 {
        return format!("{sign}0.0");
    }
    // Rust's `{:e}` without a precision prints the shortest digits that round-trip,
    // which is what Python's repr (David Gay's dtoa, mode 0) also chooses.
    let sci = format!("{:e}", f.abs());
    let (mantissa, exponent) = sci.split_once('e').expect("exponent form");
    let exponent: i32 = exponent.parse().expect("exponent");
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    let decpt = exponent + 1; // position of the decimal point relative to the digits
    let n = digits.len() as i32;
    let body = if decpt <= -4 || decpt > 16 {
        let mut m = digits[..1].to_string();
        if n > 1 {
            m.push('.');
            m.push_str(&digits[1..]);
        }
        let e = decpt - 1;
        format!("{m}e{}{:02}", if e < 0 { '-' } else { '+' }, e.abs())
    } else if decpt <= 0 {
        format!("0.{}{digits}", "0".repeat((-decpt) as usize))
    } else if decpt >= n {
        format!("{digits}{}.0", "0".repeat((decpt - n) as usize))
    } else {
        format!(
            "{}.{}",
            &digits[..decpt as usize],
            &digits[decpt as usize..]
        )
    };
    format!("{sign}{body}")
}

// ---------------------------------------------------------------- Python equality

/// Python's `a == b` for values that came out of `json.loads`.
pub fn py_eq(a: &Value, b: &Value) -> bool {
    use Value::*;
    match (a, b) {
        (Null, Null) => true,
        (Str(x), Str(y)) => x == y,
        (List(x), List(y)) => x.len() == y.len() && x.iter().zip(y).all(|(p, q)| py_eq(p, q)),
        (Dict(x), Dict(y)) => {
            x.len() == y.len()
                && x.iter()
                    .all(|(k, v)| y.iter().any(|(k2, v2)| k == k2 && py_eq(v, v2)))
        }
        _ => match (number(a), number(b)) {
            (Some(x), Some(y)) => num_eq(&x, &y),
            _ => false,
        },
    }
}

enum Num<'a> {
    Int(bool, std::borrow::Cow<'a, str>),
    Float(f64),
}

fn number(v: &Value) -> Option<Num<'_>> {
    match v {
        Value::Bool(b) => Some(Num::Int(false, if *b { "1".into() } else { "0".into() })),
        Value::Int { negative, digits } => Some(Num::Int(*negative, digits.as_str().into())),
        Value::Float(f) => Some(Num::Float(*f)),
        _ => None,
    }
}

fn num_eq(a: &Num, b: &Num) -> bool {
    match (a, b) {
        (Num::Int(s1, d1), Num::Int(s2, d2)) => s1 == s2 && d1 == d2,
        (Num::Float(x), Num::Float(y)) => x == y,
        (Num::Int(s, d), Num::Float(f)) | (Num::Float(f), Num::Int(s, d)) => {
            if !f.is_finite() || f.fract() != 0.0 {
                return false;
            }
            let fneg = *f < 0.0;
            let fdigits = integral_digits(f.abs());
            (fdigits == "0" && d == "0") || (fneg == *s && fdigits == *d)
        }
    }
}

/// Exact decimal digits of a finite, integral, non-negative double.
fn integral_digits(f: f64) -> String {
    if f < 1.8e19 {
        return format!("{}", f as u64);
    }
    let bits = f.to_bits();
    let exp = ((bits >> 52) & 0x7ff) as i32 - 1075;
    let mantissa = (bits & ((1u64 << 52) - 1)) | (1u64 << 52);
    // Base 1e9 limbs, little-endian.
    let mut limbs: Vec<u64> = vec![
        mantissa % 1_000_000_000,
        mantissa / 1_000_000_000 % 1_000_000_000,
        mantissa / 1_000_000_000_000_000_000,
    ];
    for _ in 0..exp.max(0) {
        let mut carry = 0;
        for limb in limbs.iter_mut() {
            let v = *limb * 2 + carry;
            *limb = v % 1_000_000_000;
            carry = v / 1_000_000_000;
        }
        if carry > 0 {
            limbs.push(carry);
        }
    }
    while limbs.len() > 1 && *limbs.last().unwrap() == 0 {
        limbs.pop();
    }
    let mut s = format!("{}", limbs.last().unwrap());
    for limb in limbs.iter().rev().skip(1) {
        let _ = write!(s, "{limb:09}");
    }
    s
}

/// Compare an integer value with a length, for `size > len(hashes)`.
pub fn int_cmp_usize(digits: &str, n: usize) -> Ordering {
    let n = n.to_string();
    digits
        .len()
        .cmp(&n.len())
        .then_with(|| digits.cmp(n.as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canon(text: &str) -> String {
        String::from_utf8(canonical(&loads(text).unwrap())).unwrap()
    }

    #[test]
    fn matches_python_canonical_output() {
        // Expected bytes produced by agent_passport.core.canonical on CPython 3.13.
        let input = r#"{"b":"\ud83d\ude00\ud800x\u007f\u00e9\n\"\\/","a":[true,null,-0,1.5e300,2.5e-7,123.456,1e22,9007199254740993.0, 0.1, 100.0, -1e-7, 1793432275.123, 12345678901234567.0, 1e-4]}"#;
        let expected = r#"{"a":[true,null,0,1.5e+300,2.5e-07,123.456,1e+22,9007199254740992.0,0.1,100.0,-1e-07,1793432275.123,1.2345678901234568e+16,0.0001],"b":"\ud83d\ude00\ud800x\u007f\u00e9\n\"\\/"}"#;
        assert_eq!(canon(input), expected);
    }

    #[test]
    fn float_repr_boundaries() {
        for (f, s) in [
            (1e16, "1e+16"),
            (1e15, "1000000000000000.0"),
            (0.0001, "0.0001"),
            (0.00001, "1e-05"),
            (-0.0, "-0.0"),
            (5e-324, "5e-324"),
            (1.7976931348623157e308, "1.7976931348623157e+308"),
            (1.5, "1.5"),
            (1793481089.8423278, "1793481089.8423278"),
        ] {
            assert_eq!(float_repr(f), s);
        }
        assert_eq!(canon("[1e400,-1e400,NaN]"), "[Infinity,-Infinity,NaN]");
    }

    #[test]
    fn python_parse_rules() {
        assert_eq!(canon(r#"{"a":1,"b":2,"a":3}"#), r#"{"a":3,"b":2}"#);
        assert_eq!(
            canon("123456789012345678901234567890"),
            "123456789012345678901234567890"
        );
        assert!(loads(&"1".repeat(4300)).is_ok());
        assert!(loads(&"1".repeat(4301)).is_err());
        for bad in [
            "[1,]",
            "{\"a\":1,}",
            "01",
            "1.",
            "\"\t\"",
            "'a'",
            "\u{feff}1",
            "[1] x",
            "",
        ] {
            assert!(loads(bad).is_err(), "{bad:?} should not parse");
        }
        // Non-ASCII keys sort by code point, after every ASCII key.
        assert_eq!(
            canon(r#"{"é":1,"z":2,"😀":3,"￿":4}"#),
            r#"{"z":2,"\u00e9":1,"\uffff":4,"\ud83d\ude00":3}"#
        );
    }

    #[test]
    fn python_equality() {
        let v = |t: &str| loads(t).unwrap();
        assert!(py_eq(&v("1"), &v("1.0")));
        assert!(py_eq(&v("true"), &v("1")));
        assert!(py_eq(&v("100000000000000000000"), &v("1e20")));
        assert!(!py_eq(&v("100000000000000000001"), &v("1e20")));
        assert!(!py_eq(&v("NaN"), &v("NaN")));
        assert!(py_eq(&v(r#"{"a":[1,2]}"#), &v(r#"{"a":[1.0,2]}"#)));
        assert!(!py_eq(&v(r#""1""#), &v("1")));
    }
}
