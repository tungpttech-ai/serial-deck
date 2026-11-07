//! UART control-plane v1 codec (uart_client.py): COBS + CRC32 frames and log lines.

use serde_json::Value;

pub const PROTOCOL_VERSION: u8 = 1;
const MAX_DECODED_PAYLOAD: usize = 1536;
const MAX_ENCODED_FRAME: usize = 2048;
const PENDING_LIMIT: usize = MAX_ENCODED_FRAME * 4;
const HEADER_SIZE: usize = 9;

pub const FRAME_HELLO: u8 = 1;
pub const FRAME_COMMAND: u8 = 2;
pub const FRAME_RESPONSE: u8 = 3;
pub const FRAME_EVENT: u8 = 4;
pub const FRAME_ERROR: u8 = 5;

pub fn frame_name(t: u8) -> Option<&'static str> {
    Some(match t {
        FRAME_HELLO => "hello",
        FRAME_COMMAND => "command",
        FRAME_RESPONSE => "response",
        FRAME_EVENT => "event",
        FRAME_ERROR => "error",
        _ => return None,
    })
}

pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xEDB8_8320 & (crc & 1).wrapping_neg());
        }
    }
    !crc
}

pub fn cobs_encode(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8];
    let (mut code_index, mut code) = (0usize, 1u8);
    for &b in data {
        if b == 0 {
            out[code_index] = code;
            code_index = out.len();
            out.push(0);
            code = 1;
        } else {
            out.push(b);
            code += 1;
            if code == 0xFF {
                out[code_index] = code;
                code_index = out.len();
                out.push(0);
                code = 1;
            }
        }
    }
    out[code_index] = code;
    out
}

pub fn cobs_decode(data: &[u8]) -> Option<Vec<u8>> {
    if data.is_empty() {
        return None;
    }
    let mut out = Vec::with_capacity(data.len());
    let mut i = 0;
    while i < data.len() {
        let code = data[i] as usize;
        i += 1;
        if code == 0 || i + code - 1 > data.len() {
            return None;
        }
        out.extend_from_slice(&data[i..i + code - 1]);
        i += code - 1;
        if code != 0xFF && i < data.len() {
            out.push(0);
        }
    }
    Some(out)
}

pub fn encode_frame(frame_type: u8, flags: u8, sequence: u32, payload: &[u8]) -> Result<Vec<u8>, String> {
    if payload.len() > MAX_DECODED_PAYLOAD {
        return Err("payload too large".into());
    }
    let mut raw = vec![PROTOCOL_VERSION, frame_type, flags];
    raw.extend_from_slice(&sequence.to_le_bytes());
    raw.extend_from_slice(&(payload.len() as u16).to_le_bytes());
    raw.extend_from_slice(payload);
    let crc = crc32(&raw);
    raw.extend_from_slice(&crc.to_le_bytes());
    let mut encoded = cobs_encode(&raw);
    encoded.push(0);
    if encoded.len() > MAX_ENCODED_FRAME {
        return Err("encoded frame too large".into());
    }
    Ok(encoded)
}

pub fn decode_frame(frame: &[u8]) -> Option<(u8, u8, u32, Vec<u8>)> {
    let frame = frame.strip_suffix(&[0]).unwrap_or(frame);
    let raw = cobs_decode(frame)?;
    if raw.len() < HEADER_SIZE + 4 || raw[0] != PROTOCOL_VERSION {
        return None;
    }
    let sequence = u32::from_le_bytes(raw[3..7].try_into().ok()?);
    let len = u16::from_le_bytes(raw[7..9].try_into().ok()?) as usize;
    if len > MAX_DECODED_PAYLOAD || raw.len() != HEADER_SIZE + len + 4 {
        return None;
    }
    let crc = u32::from_le_bytes(raw[HEADER_SIZE + len..].try_into().ok()?);
    if crc32(&raw[..HEADER_SIZE + len]) != crc {
        return None;
    }
    Some((raw[1], raw[2], sequence, raw[HEADER_SIZE..HEADER_SIZE + len].to_vec()))
}

pub fn encode_json_frame(frame_type: u8, sequence: u32, message: &Value) -> Result<Vec<u8>, String> {
    encode_frame(frame_type, 0, sequence, serde_json::to_string(message).unwrap_or_default().as_bytes())
}

#[derive(Debug, PartialEq)]
pub enum Rec {
    Log(String),
    Frame(u8, u32, Value),
}

/// Classify complete COBS frames and ordinary console log lines (UartReader).
pub struct Reader {
    frames: bool,
    pending: Vec<u8>,
}

fn lossy(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn rstrip_cr(mut b: &[u8]) -> &[u8] {
    while let Some(rest) = b.strip_suffix(b"\r") {
        b = rest;
    }
    b
}

fn is_text(b: &[u8]) -> bool {
    std::str::from_utf8(b).is_ok_and(|s| s.chars().all(|c| "\t\r\n".contains(c) || c as u32 >= 32))
}

fn find(b: &[u8], byte: u8) -> Option<usize> {
    b.iter().position(|&x| x == byte)
}

impl Reader {
    pub fn new(frames: bool) -> Self {
        Reader { frames, pending: Vec::new() }
    }

    pub fn feed(&mut self, chunk: &[u8]) -> Vec<Rec> {
        let mut records = Vec::new();
        self.pending.extend_from_slice(chunk);
        if !self.frames {
            let mut parts: Vec<&[u8]> = self.pending.split(|&b| b == b'\n').collect();
            let rest = parts.pop().unwrap_or_default();
            for line in parts {
                let line = rstrip_cr(line);
                if !line.is_empty() {
                    records.push(Rec::Log(lossy(line)));
                }
            }
            self.pending = rest[rest.len().saturating_sub(PENDING_LIMIT)..].to_vec();
            return records;
        }
        while let Some(d) = find(&self.pending, 0) {
            let segment: Vec<u8> = self.pending.drain(..=d).take(d).collect();
            if !segment.is_empty() {
                parse_segment(&segment, &mut records);
            }
        }
        while let Some(n) = find(&self.pending, b'\n') {
            if !is_text(&self.pending[..n]) {
                break;
            }
            let line: Vec<u8> = self.pending.drain(..=n).take(n).collect();
            let line = rstrip_cr(&line);
            if !line.is_empty() {
                records.push(Rec::Log(lossy(line)));
            }
        }
        if self.pending.len() > PENDING_LIMIT {
            let dropped: Vec<u8> = self.pending.drain(..self.pending.len() - MAX_ENCODED_FRAME).collect();
            let text = lossy(&dropped[dropped.len().saturating_sub(MAX_ENCODED_FRAME)..]);
            records.push(Rec::Log(format!("[truncated {} undelimited bytes] {text}", dropped.len())));
        }
        records
    }
}

fn append_console(value: &[u8], records: &mut Vec<Rec>) {
    for line in value.split(|&b| b == b'\n') {
        let line = rstrip_cr(line);
        if !line.is_empty() {
            records.push(Rec::Log(lossy(line)));
        }
    }
}

/// A NUL-delimited segment holding logs and/or one frame, possibly with a damaged log prefix.
fn parse_segment(segment: &[u8], records: &mut Vec<Rec>) {
    let window = segment.len().saturating_sub(MAX_ENCODED_FRAME);
    let after_newline = segment[window..].iter().rposition(|&b| b == b'\n').map_or(0, |i| window + i + 1);
    let mut starts: Vec<usize> = Vec::with_capacity(segment.len() - window + 1);
    if after_newline > window {
        starts.push(after_newline);
    }
    starts.extend((window..segment.len()).filter(|&i| !(after_newline > window && i == after_newline)));
    for start in starts {
        if let Some((frame_type, _flags, sequence, payload)) = decode_frame(&segment[start..]) {
            if start > 0 {
                append_console(&segment[..start], records);
            }
            let message = std::str::from_utf8(&payload)
                .ok()
                .and_then(|s| serde_json::from_str(s).ok())
                .unwrap_or_else(|| Value::String(payload.iter().map(|b| format!("{b:02x}")).collect()));
            records.push(Rec::Frame(frame_type, sequence, message));
            return;
        }
    }
    append_console(segment, records);
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn crc_and_golden_frame() {
        assert_eq!(crc32(b"123456789"), 0xCBF43926);
        let frame = encode_frame(FRAME_COMMAND, 0, 0x01020304, br#"{"type":"hello"}"#).unwrap();
        let hex: String = frame.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "030102060403020110157b2274797065223a2268656c6c6f227d1c7ae1a300");
        assert_eq!(decode_frame(&frame).unwrap(), (FRAME_COMMAND, 0, 0x01020304, br#"{"type":"hello"}"#.to_vec()));
        let mut bad = frame.clone();
        let n = bad.len();
        bad[n - 2] ^= 1;
        assert!(decode_frame(&bad).is_none());
    }

    #[test]
    fn cobs_round_trip() {
        let all: Vec<u8> = (0..=255).collect();
        for v in [&b""[..], b"abc", b"a\0b\0c", &all] {
            let e = cobs_encode(v);
            assert!(!e.contains(&0));
            assert_eq!(cobs_decode(&e).unwrap(), v);
        }
    }

    #[test]
    fn reader_splits_logs_and_frames() {
        let frame = encode_json_frame(FRAME_EVENT, 7, &json!({"status": "running"})).unwrap();
        let mut data = b"I (1) boot: hi\r\nnoise".to_vec();
        data.extend_from_slice(&frame);
        data.extend_from_slice(b"W (2) x\n");
        let mut r = Reader::new(true);
        let recs = r.feed(&data);
        assert_eq!(
            recs,
            vec![
                Rec::Log("I (1) boot: hi".into()),
                Rec::Log("noise".into()),
                Rec::Frame(FRAME_EVENT, 7, json!({"status": "running"})),
                Rec::Log("W (2) x".into()),
            ]
        );
        let mut raw = Reader::new(false);
        assert_eq!(raw.feed(b"a\x1b[0m\nb"), vec![Rec::Log("a\x1b[0m".into())]);
        assert_eq!(raw.feed(b"c\n"), vec![Rec::Log("bc".into())]);
        let mut big = Reader::new(true);
        let recs = big.feed(&vec![1u8; PENDING_LIMIT + 1]);
        assert!(matches!(&recs[0], Rec::Log(t) if t.starts_with("[truncated 6145 undelimited bytes]")));
    }
}
