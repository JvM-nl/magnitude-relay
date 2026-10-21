//! Deterministic data generators shared by the codec tests, the WebSocket tests and
//! the benchmark example (which includes this file by path, so it must not name
//! anything else in the crate).

/// xorshift64*: small, fast, reproducible.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Rng {
        // SplitMix64 scramble so adjacent seeds give unrelated streams, never zero.
        let mut z = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        Rng(if z == 0 { 1 } else { z })
    }

    pub fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Uniform in `0..n` (`n > 0`), good enough for tests.
    pub fn below(&mut self, n: u64) -> u64 {
        (self.next() >> 11) % n
    }

    pub fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
}

const HEX: &[u8; 16] = b"0123456789abcdef";
const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn hex(rng: &mut Rng, n: usize) -> Vec<u8> {
    (0..n).map(|_| HEX[rng.below(16) as usize]).collect()
}

pub fn base64(rng: &mut Rng, n: usize) -> Vec<u8> {
    (0..n).map(|_| B64[rng.below(64) as usize]).collect()
}

const WORDS: &[&str] = &[
    "the",
    "nostr",
    "relay",
    "is",
    "fast",
    "gm",
    "good",
    "morning",
    "vector",
    "chat",
    "message",
    "encrypted",
    "hello",
    "world",
    "sats",
    "zap",
    "note",
    "just",
    "shipped",
    "new",
    "release",
    "bitcoin",
    "privacy",
    "freedom",
    "build",
    "open",
    "protocol",
    "network",
    "keys",
    "sign",
    "event",
    "check",
    "this",
    "out",
    "lol",
    "yes",
    "no",
    "maybe",
];

pub fn words(rng: &mut Rng, n: usize) -> String {
    let mut s = String::new();
    for i in 0..n {
        if i > 0 {
            s.push(' ');
        }
        s.push_str(WORDS[rng.below(WORDS.len() as u64) as usize]);
    }
    s
}

/// One plausible `["EVENT","sub",{...}]` message: lowercase-hex id, pubkey (drawn
/// from a small pool so authors repeat the way a real stream's do) and signature,
/// a few tags, and either short text or, for a gift wrap, a 1-2 KB base64 blob.
pub fn nostr_event(rng: &mut Rng, authors: &[Vec<u8>]) -> Vec<u8> {
    let mut s = Vec::with_capacity(700);
    let push = |s: &mut Vec<u8>, b: &[u8]| s.extend_from_slice(b);
    push(&mut s, b"[\"EVENT\",\"sub");
    push(&mut s, rng.below(1000).to_string().as_bytes());
    push(&mut s, b"\",{\"id\":\"");
    let id = hex(rng, 64);
    push(&mut s, &id);
    push(&mut s, b"\",\"pubkey\":\"");
    let author = &authors[rng.below(authors.len() as u64) as usize];
    push(&mut s, author);
    push(&mut s, b"\",\"created_at\":");
    push(&mut s, (1_700_000_000 + rng.below(50_000_000)).to_string().as_bytes());
    let roll = rng.below(100);
    let (kind, content, tags): (u32, Vec<u8>, usize) = if roll < 12 {
        let n = 1000 + rng.below(1000) as usize;
        (1059, base64(rng, n), 1)
    } else if roll < 18 {
        (
            0,
            format!("{{\\\"name\\\":\\\"{}\\\",\\\"about\\\":\\\"{}\\\"}}", words(rng, 1), words(rng, 8)).into_bytes(),
            0,
        )
    } else {
        let n = 3 + rng.below(25) as usize;
        (1, words(rng, n).into_bytes(), rng.below(4) as usize)
    };
    push(&mut s, b",\"kind\":");
    push(&mut s, kind.to_string().as_bytes());
    push(&mut s, b",\"tags\":[");
    for t in 0..tags {
        if t > 0 {
            push(&mut s, b",");
        }
        push(&mut s, if t % 2 == 0 { b"[\"p\",\"" } else { b"[\"e\",\"" });
        if t % 2 == 0 && rng.below(2) == 0 {
            push(&mut s, &authors[rng.below(authors.len() as u64) as usize]);
        } else {
            let h = hex(rng, 64);
            push(&mut s, &h);
        }
        push(&mut s, b"\"]");
    }
    push(&mut s, b"],\"content\":\"");
    push(&mut s, &content);
    push(&mut s, b"\",\"sig\":\"");
    let sig = hex(rng, 128);
    push(&mut s, &sig);
    push(&mut s, b"\"}]");
    s
}

/// `n` events from a pool of 40 authors.
pub fn nostr_corpus(seed: u64, n: usize) -> Vec<Vec<u8>> {
    let mut rng = Rng::new(seed);
    let authors: Vec<Vec<u8>> = (0..40).map(|_| hex(&mut rng, 64)).collect();
    (0..n).map(|_| nostr_event(&mut rng, &authors)).collect()
}

/// A named set of inputs that exercise different match/literal mixes.
pub fn corpora() -> Vec<(&'static str, Vec<u8>)> {
    let mut rng = Rng::new(0xDEF1A7E);
    let mut out: Vec<(&'static str, Vec<u8>)> = vec![
        ("empty", Vec::new()),
        ("one byte", vec![b'x']),
        ("three bytes", b"abc".to_vec()),
        ("zeros", vec![0u8; 5000]),
        ("one letter", vec![b'a'; 70_000]),
        ("random", rng.bytes(3000)),
        ("random big", rng.bytes(150_000)),
        ("hex", hex(&mut rng, 4000)),
        ("hex big", hex(&mut rng, 200_000)),
        ("base64", base64(&mut rng, 5000)),
    ];
    let rep: Vec<u8> = b"the quick brown fox jumps over the lazy dog. ".iter().cycle().take(9000).copied().collect();
    out.push(("repetitive", rep));
    let mut period = Vec::new();
    for _ in 0..40 {
        period.extend_from_slice(&rng.bytes(7));
        period.extend_from_slice(b"..........");
    }
    out.push(("short period", period));
    let mut text = Vec::new();
    for _ in 0..40 {
        text.extend_from_slice(words(&mut rng, 60).as_bytes());
        text.push(b'\n');
    }
    out.push(("text", text));
    let events = nostr_corpus(11, 60);
    out.push(("one event", events[0].clone()));
    out.push(("events", events.concat()));
    out.push(("events big", nostr_corpus(12, 1500).concat()));
    let mut mixed = hex(&mut rng, 300);
    mixed.extend(rng.bytes(300));
    mixed.extend(vec![b'z'; 300]);
    mixed.extend(base64(&mut rng, 300));
    out.push(("mixed", mixed));
    out
}

#[test]
fn generators_are_deterministic_and_look_like_nostr() {
    assert_eq!(nostr_corpus(5, 10), nostr_corpus(5, 10));
    assert_ne!(nostr_corpus(5, 10), nostr_corpus(6, 10));
    let e = &nostr_corpus(1, 200);
    let total: usize = e.iter().map(Vec::len).sum();
    assert!(total / e.len() > 400 && total / e.len() < 1500, "average {}", total / e.len());
    assert!(e.iter().all(|m| std::str::from_utf8(m).is_ok() && m.starts_with(b"[\"EVENT\"")));
    assert!(e.iter().any(|m| m.len() > 1500), "gift wraps present");
}
