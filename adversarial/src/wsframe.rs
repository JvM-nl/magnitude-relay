//! Raw WebSocket frames, built with nothing checked: any opcode, any reserved
//! bits, masked or not, lengths in any of the three encodings or simply wrong.
//! The fuzz targets' generators and the hostile client both use it.

use crate::rng::Rng;

#[derive(Clone, Debug)]
pub struct Frame {
    pub fin: bool,
    /// RSV1..3 as the top three bits of the low nibble's neighbour: 0x40, 0x20, 0x10.
    pub rsv: u8,
    pub op: u8,
    pub mask: Option<[u8; 4]>,
    pub payload: Vec<u8>,
    /// Length field to write instead of the real one (a lie).
    pub claimed_len: Option<u64>,
    /// Force the 16- or 64-bit length form (126/127) even for short payloads.
    pub wide: Option<u8>,
}

impl Frame {
    pub fn new(op: u8, payload: &[u8]) -> Frame {
        Frame { fin: true, rsv: 0, op, mask: Some([0x12, 0x34, 0x56, 0x78]), payload: payload.to_vec(), claimed_len: None, wide: None }
    }

    pub fn text(s: &str) -> Frame {
        Frame::new(1, s.as_bytes())
    }

    pub fn write(&self, out: &mut Vec<u8>) {
        out.push(u8::from(self.fin) << 7 | (self.rsv & 0x70) | (self.op & 0x0F));
        let len = self.claimed_len.unwrap_or(self.payload.len() as u64);
        let m = if self.mask.is_some() { 0x80 } else { 0 };
        match (self.wide, len) {
            (Some(127), _) | (None, 65_536..) => {
                out.push(m | 127);
                out.extend_from_slice(&len.to_be_bytes());
            }
            (Some(126), _) | (None, 126..=65_535) => {
                out.push(m | 126);
                out.extend_from_slice(&(len as u16).to_be_bytes());
            }
            _ => out.push(m | len as u8),
        }
        match self.mask {
            Some(k) => {
                out.extend_from_slice(&k);
                out.extend(self.payload.iter().enumerate().map(|(i, b)| b ^ k[i % 4]));
            }
            None => out.extend_from_slice(&self.payload),
        }
    }

    pub fn bytes(&self) -> Vec<u8> {
        let mut v = Vec::new();
        self.write(&mut v);
        v
    }
}

/// A random mask, so a server cannot rely on any particular one.
pub fn mask(rng: &mut Rng) -> [u8; 4] {
    let v = rng.next_u64().to_le_bytes();
    [v[0], v[1], v[2], v[3]]
}

/// A compressed message payload as permessage-deflate sends it: a sync-flushed
/// DEFLATE stream without its trailing `00 00 ff ff`.
pub fn deflate_message(payload: &[u8]) -> Vec<u8> {
    let mut z = relay_net::ws::Compressor::new(relay_net::ws::pmd::StreamConfig { context_takeover: false, window_bits: 15 }, 0);
    let mut out = Vec::new();
    z.deflate_payload(payload, &mut out);
    out
}

/// A permessage-deflate payload that inflates to `n` copies of `b`: a bomb when
/// `n` is far past the relay's message limit (about 1000:1).
pub fn deflate_bomb(n: usize, b: u8) -> Vec<u8> {
    let mut z = relay_net::deflate::Deflater::new(15, false);
    let data = vec![b; n];
    let mut out = Vec::new();
    z.deflate(&data, &mut out, relay_net::deflate::Flush::Sync);
    out.truncate(out.len() - 4);
    out
}
