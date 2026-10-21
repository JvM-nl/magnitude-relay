//! The other relay, seen as a client sees it: one WebSocket, subscriptions by
//! id, and the negentropy initiator on our side of every NEG-OPEN.

use relay_net::conn::{ClientConn, ClientDeflate, Message};
use relay_net::connector::{Connector, RelayUrl, Stream};
use relay_proto::message::RelayMsg;
use relay_proto::negentropy::{Initiator, VecStorage};
use relay_proto::{hex, kind, Filter};
use std::time::Duration;

/// Our negentropy messages, in bytes before hex. strfry takes websocket
/// messages of up to 128 KiB and ours 256 KiB; hex doubles the size.
pub const FRAME_LIMIT: usize = 60_000;
/// How long a relay may take over one negentropy answer. A relay without a
/// prepared set (strfry outside its `{}` tree) reads the whole set first.
const NEG_WAIT: Duration = Duration::from_secs(120);

/// Why a reconciliation did not finish.
#[derive(Debug)]
pub enum NegFail {
    /// The relay will not compare a set this large: ask about less.
    TooBig(String),
    /// The relay refused, or broke the protocol.
    Refused(String),
    /// The connection failed.
    Io(String),
}

impl std::fmt::Display for NegFail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NegFail::TooBig(m) | NegFail::Refused(m) | NegFail::Io(m) => f.write_str(m),
        }
    }
}

/// What one reconciliation found.
#[derive(Debug, Default)]
pub struct Diff {
    /// Ids only we hold, sorted.
    pub have: Vec<[u8; 32]>,
    /// Ids only they hold, sorted.
    pub need: Vec<[u8; 32]>,
    /// Messages exchanged.
    pub rounds: usize,
}

pub struct Remote {
    conn: ClientConn<Stream>,
    pub url: RelayUrl,
    next_sub: u64,
}

/// Relays word "this set is too large" differently: strfry says "too many
/// query results", we say "too many records". Other refusals are final.
pub fn too_big(message: &str) -> bool {
    let m = message.to_ascii_lowercase();
    (m.contains("too many") && !m.contains("concurrent") && !m.contains("session")) || m.contains("too big") || m.contains("too large")
}

impl Remote {
    /// Connects. Compression is offered except over loopback, where it would
    /// only cost both sides CPU.
    pub async fn connect(connector: &Connector, url: &RelayUrl) -> Result<Remote, String> {
        let deflate = (!url.is_loopback()).then(ClientDeflate::default);
        let conn = connector.connect(url, deflate).await.map_err(|e| format!("cannot connect to {url}: {e}"))?;
        Ok(Remote { conn, url: url.clone(), next_sub: 0 })
    }

    /// A subscription id not used before on this connection.
    pub fn sub(&mut self, prefix: &str) -> String {
        self.next_sub += 1;
        format!("{prefix}{}", self.next_sub)
    }

    pub async fn send(&mut self, text: &str) -> Result<(), String> {
        self.conn.send_text(text).await.map_err(|e| format!("{}: {e}", self.url))
    }

    /// Queues a message, sent by the next `send` or `flush`.
    pub fn queue(&mut self, text: &str) {
        self.conn.queue_text(text);
    }

    pub async fn flush(&mut self) -> Result<(), String> {
        self.conn.flush().await.map_err(|e| format!("{}: {e}", self.url))
    }

    /// The next text message. Cancel-safe: nothing is lost if the caller
    /// drops it to do something else (see `ClientConn`).
    pub async fn next(&mut self) -> Result<String, String> {
        loop {
            match self.conn.recv().await.map_err(|e| format!("{}: {e}", self.url))? {
                Message::Text(t) => return Ok(t),
                Message::Close(c) => {
                    let why = c.map(|(code, r)| format!(" ({code} {r})")).unwrap_or_default();
                    return Err(format!("{} closed the connection{why}", self.url));
                }
                // Pings are answered inside recv; binary is not Nostr.
                _ => {}
            }
        }
    }

    /// [`next`](Self::next), giving up after `wait`.
    pub async fn next_within(&mut self, wait: Duration) -> Result<String, String> {
        match tokio::time::timeout(wait, self.next()).await {
            Ok(r) => r,
            Err(_) => Err(format!("{} sent nothing for {} s", self.url, wait.as_secs())),
        }
    }

    /// Whether this relay leaves gift wraps out of what a filter matches unless
    /// the filter names their author, recipient or id (ours does, to stop bulk
    /// scraping of DM metadata; strfry does not). A sync must compare like with
    /// like: when they leave wraps out of a broad filter, so must we. Asked
    /// with a NEG-OPEN for wraps that matches nothing, which costs a relay that
    /// answers it nothing.
    pub async fn hides_wraps(&mut self) -> Result<bool, String> {
        let sub = self.sub("probe");
        let f = Filter { kinds: Some(vec![kind::GIFT_WRAP]), until: Some(0), ..Filter::default() };
        let first = Initiator::new(VecStorage::new(Vec::new()), FRAME_LIMIT).expect("valid frame limit").initiate();
        self.send(&neg_open(&sub, &f, &first)).await?;
        loop {
            let text = self.next_within(NEG_WAIT).await?;
            match RelayMsg::parse(&text) {
                Ok(RelayMsg::NegMsg { sub_id, .. }) if sub_id == sub => {
                    self.send(&format!("[\"NEG-CLOSE\",\"{sub}\"]")).await?;
                    return Ok(false);
                }
                Ok(RelayMsg::NegErr { sub_id, .. }) if sub_id == sub => return Ok(true),
                Ok(RelayMsg::Notice { message }) if message.to_ascii_lowercase().contains("negentropy") => {
                    return Err(format!("{} does not do negentropy (NIP-77): {message}", self.url));
                }
                _ => {}
            }
        }
    }

    /// Compares our `items` (the set `f` matches here) with theirs, initiating.
    pub async fn reconcile(&mut self, f: &Filter, items: Vec<(u64, [u8; 32])>) -> Result<Diff, NegFail> {
        let init = Initiator::new(VecStorage::new(items), FRAME_LIMIT).expect("valid frame limit");
        let sub = self.sub("neg");
        let mut diff = Diff::default();
        self.send(&neg_open(&sub, f, &init.initiate())).await.map_err(NegFail::Io)?;
        loop {
            let text = self.next_within(NEG_WAIT).await.map_err(NegFail::Io)?;
            match RelayMsg::parse(&text) {
                Ok(RelayMsg::NegMsg { sub_id, msg }) if sub_id == sub => {
                    diff.rounds += 1;
                    match init.reconcile(&msg, &mut diff.have, &mut diff.need) {
                        Ok(Some(next)) => self.send(&neg_msg(&sub, &next)).await.map_err(NegFail::Io)?,
                        Ok(None) => break,
                        Err(e) => {
                            let _ = self.send(&format!("[\"NEG-CLOSE\",\"{sub}\"]")).await;
                            return Err(NegFail::Refused(format!("{} broke the negentropy protocol: {e}", self.url)));
                        }
                    }
                }
                Ok(RelayMsg::NegErr { sub_id, message }) if sub_id == sub => {
                    return Err(if too_big(&message) { NegFail::TooBig(message) } else { NegFail::Refused(format!("{} refused: {message}", self.url)) });
                }
                Ok(RelayMsg::Notice { message }) if message.to_ascii_lowercase().contains("negentropy") => {
                    return Err(NegFail::Refused(format!("{}: {message}", self.url)));
                }
                // Anything else is left over from earlier work on this connection.
                _ => {}
            }
        }
        self.send(&format!("[\"NEG-CLOSE\",\"{sub}\"]")).await.map_err(NegFail::Io)?;
        // An id can be reported twice when a message was cut at its frame limit.
        for v in [&mut diff.have, &mut diff.need] {
            v.sort_unstable();
            v.dedup();
        }
        Ok(diff)
    }

    pub async fn close(self) {
        let _ = tokio::time::timeout(Duration::from_secs(2), self.conn.close()).await;
    }
}

fn neg_open(sub: &str, f: &Filter, msg: &[u8]) -> String {
    let mut b = format!("[\"NEG-OPEN\",\"{sub}\",").into_bytes();
    f.write_json(&mut b);
    b.extend_from_slice(b",\"");
    hex::encode_into(msg, &mut b);
    b.extend_from_slice(b"\"]");
    String::from_utf8(b).expect("ASCII")
}

fn neg_msg(sub: &str, msg: &[u8]) -> String {
    let mut b = format!("[\"NEG-MSG\",\"{sub}\",\"").into_bytes();
    hex::encode_into(msg, &mut b);
    b.extend_from_slice(b"\"]");
    String::from_utf8(b).expect("ASCII")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn what_counts_as_too_big() {
        assert!(too_big("blocked: too many query results"));
        assert!(too_big("blocked: too many records to reconcile, narrow the filter"));
        assert!(too_big("RESULTS TOO BIG"));
        assert!(!too_big("blocked: too many open negentropy sessions"));
        assert!(!too_big("too many concurrent NEG requests"));
        assert!(!too_big("restricted: gift wraps are requested by author, recipient or id"));
        assert!(!too_big("auth-required: requested filter requires authentication"));
    }
}
