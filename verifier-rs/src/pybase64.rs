//! `agent_passport.core.unb64`: `base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))`.
//!
//! Python's decoder is not strict. After mapping `-` to `+` and `_` to `/`, CPython's
//! `binascii.a2b_base64(strict_mode=False)` skips characters outside the alphabet, stops
//! at a completed padding sequence, and accepts non-zero trailing bits. A strict decoder
//! would reject signatures Python accepts, so this follows the CPython loop.

use crate::pyjson::PyStr;

pub fn unb64(value: &PyStr) -> Option<Vec<u8>> {
    let pad = (4 - value.len() % 4) % 4;
    // `_bytes_from_decode_data` rejects non-ASCII strings with ValueError.
    let mut bytes = Vec::with_capacity(value.len() + pad);
    for &c in &value.0 {
        if c > 0x7f {
            return None;
        }
        bytes.push(match c as u8 {
            b'-' => b'+',
            b'_' => b'/',
            b => b,
        });
    }
    bytes.extend(std::iter::repeat_n(b'=', pad));
    a2b_base64(&bytes)
}

fn sextet(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn a2b_base64(data: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(data.len() / 4 * 3);
    let (mut quad_pos, mut left, mut pads) = (0u8, 0u8, 0u8);
    for &ch in data {
        if ch == b'=' {
            if quad_pos >= 2 {
                pads += 1;
                if quad_pos + pads >= 4 {
                    return Some(out);
                }
            }
            continue;
        }
        let Some(v) = sextet(ch) else { continue };
        pads = 0;
        match quad_pos {
            0 => {
                quad_pos = 1;
                left = v;
            }
            1 => {
                quad_pos = 2;
                out.push((left << 2) | (v >> 4));
                left = v & 0x0f;
            }
            2 => {
                quad_pos = 3;
                out.push((left << 4) | (v >> 2));
                left = v & 0x03;
            }
            _ => {
                quad_pos = 0;
                out.push((left << 6) | v);
                left = 0;
            }
        }
    }
    // Leftover data characters: "Incorrect padding" or "1 more than a multiple of 4".
    if quad_pos != 0 { None } else { Some(out) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(s: &str) -> Option<Vec<u8>> {
        unb64(&PyStr::new(s))
    }

    #[test]
    fn decodes_like_python() {
        assert_eq!(d("AQID"), Some(vec![1, 2, 3]));
        assert_eq!(d("AQI"), Some(vec![1, 2]));
        assert_eq!(d("AQ"), Some(vec![1]));
        assert_eq!(d("-_8"), Some(vec![0xfb, 0xff]));
        assert_eq!(d("+/8"), Some(vec![0xfb, 0xff])); // the standard alphabet is accepted too
        assert_eq!(d("A!Q!I!D"), Some(vec![1, 2, 3])); // junk is skipped
        assert_eq!(d("AR"), Some(vec![1])); // non-zero trailing bits are accepted
        assert_eq!(d("A"), None);
        assert_eq!(d("AQ==AQID"), Some(vec![1])); // input after completed padding is ignored
        assert_eq!(d("é"), None);
        assert_eq!(d(""), Some(vec![]));
        assert_eq!(d("AQ=I"), None);
        assert_eq!(d("A=QID"), Some(vec![1, 2, 3])); // "=" before two data characters is skipped
        assert_eq!(d("AQI=D"), Some(vec![1, 2]));
    }
}
