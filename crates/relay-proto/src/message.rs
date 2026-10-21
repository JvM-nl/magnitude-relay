//! Client → relay messages (NIP-01, NIP-42, NIP-45, NIP-77).

use crate::event::{EventInfo, EventParser, Reject};
use crate::filter::{Filter, FilterError};
use crate::hex;
use crate::json::{self, Scanner};
use std::fmt;

/// Longest subscription id accepted, as in strfry.
pub const MAX_SUB_ID: usize = 64;

pub enum ClientMsg<'a> {
    /// The record is in the caller's buffer, parsed but **not yet checked**:
    /// look the id up first (a resend costs no hashing), then call
    /// [`EventParser::confirm_id`] with a scanner at `at`, then verify the signature.
    Event { info: EventInfo, at: usize },
    Req { sub_id: &'a str, filters: Vec<Filter> },
    Count { sub_id: &'a str, filters: Vec<Filter> },
    Close { sub_id: &'a str },
    /// As `Event`: the AUTH event is in the caller's buffer, unchecked.
    Auth { info: EventInfo, at: usize },
    NegOpen { sub_id: &'a str, filter: Filter, msg: Vec<u8> },
    NegMsg { sub_id: &'a str, msg: Vec<u8> },
    NegClose { sub_id: &'a str },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MsgError {
    Json(json::Error),
    UnknownCommand,
    BadSubId,
    /// A filter was malformed; the sub id is known, so the answer is CLOSED.
    Filter { sub_id: String, err: FilterError },
    /// The event could not be read far enough to answer with OK.
    Event(Reject),
    BadNegMessage,
}

impl fmt::Display for MsgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MsgError::Json(e) => write!(f, "bad message: {e}"),
            MsgError::UnknownCommand => f.write_str("bad message: unknown command"),
            MsgError::BadSubId => f.write_str("bad message: subscription id must be 1-64 characters"),
            MsgError::Filter { err, .. } => err.fmt(f),
            MsgError::Event(r) => write!(f, "invalid: {r}"),
            MsgError::BadNegMessage => f.write_str("bad message: negentropy message must be hex"),
        }
    }
}

impl From<json::Error> for MsgError {
    fn from(e: json::Error) -> Self {
        MsgError::Json(e)
    }
}

impl<'a> ClientMsg<'a> {
    /// Parses one client message. Events land unchecked in `rec`.
    pub fn parse(text: &'a str, parser: &mut EventParser, rec: &mut Vec<u8>) -> Result<ClientMsg<'a>, MsgError> {
        let mut s = Scanner::new(text);
        s.expect(b'[')?;
        let cmd = s.string()?;
        if cmd.escaped {
            return Err(MsgError::UnknownCommand);
        }
        let msg = match cmd.bytes {
            b"EVENT" => {
                s.expect(b',')?;
                let (info, at) = event(&mut s, parser, rec)?;
                ClientMsg::Event { info, at }
            }
            b"REQ" | b"COUNT" => {
                s.expect(b',')?;
                let sub_id = sub_id(&mut s, text)?;
                let mut filters = Vec::new();
                while s.eat(b',') {
                    filters.push(Filter::parse(&mut s).map_err(|err| MsgError::Filter { sub_id: sub_id.to_owned(), err })?);
                }
                if cmd.bytes == b"REQ" {
                    ClientMsg::Req { sub_id, filters }
                } else {
                    ClientMsg::Count { sub_id, filters }
                }
            }
            b"CLOSE" => {
                s.expect(b',')?;
                ClientMsg::Close { sub_id: sub_id(&mut s, text)? }
            }
            b"AUTH" => {
                s.expect(b',')?;
                let (info, at) = event(&mut s, parser, rec)?;
                ClientMsg::Auth { info, at }
            }
            b"NEG-OPEN" => {
                s.expect(b',')?;
                let sub_id = sub_id(&mut s, text)?;
                s.expect(b',')?;
                let filter = Filter::parse(&mut s).map_err(|err| MsgError::Filter { sub_id: sub_id.to_owned(), err })?;
                s.expect(b',')?;
                let msg = neg_hex(&mut s)?;
                ClientMsg::NegOpen { sub_id, filter, msg }
            }
            b"NEG-MSG" => {
                s.expect(b',')?;
                let sub_id = sub_id(&mut s, text)?;
                s.expect(b',')?;
                ClientMsg::NegMsg { sub_id, msg: neg_hex(&mut s)? }
            }
            b"NEG-CLOSE" => {
                s.expect(b',')?;
                ClientMsg::NegClose { sub_id: sub_id(&mut s, text)? }
            }
            _ => return Err(MsgError::UnknownCommand),
        };
        s.expect(b']')?;
        s.end()?;
        Ok(msg)
    }
}

fn event(s: &mut Scanner<'_>, parser: &mut EventParser, rec: &mut Vec<u8>) -> Result<(EventInfo, usize), MsgError> {
    s.ws();
    let at = s.pos();
    let info = parser.parse_unchecked(s, rec).map_err(MsgError::Event)?;
    Ok((info, at))
}

/// A subscription id, echoed back verbatim. Escapes are refused so the echo
/// needs no re-encoding (strfry refuses `"` and `\` too).
fn sub_id<'a>(s: &mut Scanner<'a>, text: &'a str) -> Result<&'a str, MsgError> {
    let v = s.string()?;
    if v.escaped || v.bytes.is_empty() || v.bytes.len() > MAX_SUB_ID {
        return Err(MsgError::BadSubId);
    }
    // The bytes are a slice of `text` ending just before the closing quote.
    let end = s.pos() - 1;
    Ok(&text[end - v.bytes.len()..end])
}

fn neg_hex(s: &mut Scanner<'_>) -> Result<Vec<u8>, MsgError> {
    let v = s.string()?;
    if v.escaped {
        return Err(MsgError::BadNegMessage);
    }
    hex::decode_any_case(v.bytes).ok_or(MsgError::BadNegMessage)
}

/// Relay → client messages, read by the relay itself when it is the client
/// (syncing from another relay). The other relay is not trusted: anything
/// malformed is an error, and an event is located here but parsed and
/// verified by the caller like any client's.
#[derive(Debug, PartialEq, Eq)]
pub enum RelayMsg<'a> {
    /// `["EVENT", sub, {...}]`. The event object starts at byte `at` of the text.
    Event { sub_id: &'a str, at: usize },
    /// `["OK", id, accepted, message]`.
    Ok { id: [u8; 32], accepted: bool, message: String },
    Eose { sub_id: &'a str },
    Closed { sub_id: &'a str, message: String },
    Notice { message: String },
    NegMsg { sub_id: &'a str, msg: Vec<u8> },
    NegErr { sub_id: &'a str, message: String },
    /// Something a client may ignore (AUTH, COUNT, a command from a later NIP).
    Other,
}

impl<'a> RelayMsg<'a> {
    pub fn parse(text: &'a str) -> Result<RelayMsg<'a>, MsgError> {
        let mut s = Scanner::new(text);
        s.expect(b'[')?;
        let cmd = s.string()?;
        if cmd.escaped {
            return Ok(RelayMsg::Other);
        }
        // The message string is optional in OK, CLOSED and NEG-ERR as some relays send them.
        let message = |s: &mut Scanner<'_>| -> Result<String, MsgError> {
            if s.eat(b',') {
                Ok(s.string()?.to_text())
            } else {
                Ok(String::new())
            }
        };
        let msg = match cmd.bytes {
            b"EVENT" => {
                s.expect(b',')?;
                let sub_id = sub_id(&mut s, text)?;
                s.expect(b',')?;
                s.ws();
                let at = s.pos();
                if s.peek() != Some(b'{') {
                    return Err(MsgError::Json(json::Error { msg: "expected an event object", pos: at }));
                }
                s.skip()?;
                RelayMsg::Event { sub_id, at }
            }
            b"OK" => {
                s.expect(b',')?;
                let id = s.string()?;
                let id = if id.escaped { None } else { hex::decode_32(id.bytes) };
                let id = id.ok_or(MsgError::Event(Reject::BadId))?;
                s.expect(b',')?;
                let accepted = match s.raw_value()? {
                    b"true" => true,
                    b"false" => false,
                    _ => return Err(MsgError::Json(json::Error { msg: "expected true or false", pos: s.pos() })),
                };
                RelayMsg::Ok { id, accepted, message: message(&mut s)? }
            }
            b"EOSE" => {
                s.expect(b',')?;
                RelayMsg::Eose { sub_id: sub_id(&mut s, text)? }
            }
            b"CLOSED" => {
                s.expect(b',')?;
                let sub_id = sub_id(&mut s, text)?;
                RelayMsg::Closed { sub_id, message: message(&mut s)? }
            }
            b"NOTICE" => {
                s.expect(b',')?;
                RelayMsg::Notice { message: s.string()?.to_text() }
            }
            b"NEG-MSG" => {
                s.expect(b',')?;
                let sub_id = sub_id(&mut s, text)?;
                s.expect(b',')?;
                RelayMsg::NegMsg { sub_id, msg: neg_hex(&mut s)? }
            }
            b"NEG-ERR" => {
                s.expect(b',')?;
                let sub_id = sub_id(&mut s, text)?;
                let message = message(&mut s)?;
                // strfry follows the reason with the limit it hit.
                while s.eat(b',') {
                    s.skip()?;
                }
                RelayMsg::NegErr { sub_id, message }
            }
            _ => return Ok(RelayMsg::Other),
        };
        s.expect(b']')?;
        s.end()?;
        Ok(msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_messages() {
        let id = "ab".repeat(32);
        let ev = format!(r#"["EVENT","s1", {{"id":"{id}","kind":1}} ]"#);
        let RelayMsg::Event { sub_id, at } = RelayMsg::parse(&ev).unwrap() else { panic!("not an event") };
        assert_eq!((sub_id, &ev[at..at + 6]), ("s1", r#"{"id":"#));
        let ok = format!(r#"["OK","{id}",false,"rate-limited: slow \"down\""]"#);
        assert_eq!(RelayMsg::parse(&ok).unwrap(), RelayMsg::Ok { id: [0xab; 32], accepted: false, message: "rate-limited: slow \"down\"".into() });
        assert_eq!(RelayMsg::parse(&format!(r#"["OK","{id}",true,""]"#)).unwrap(), RelayMsg::Ok { id: [0xab; 32], accepted: true, message: String::new() });
        assert_eq!(RelayMsg::parse(r#"["EOSE","s1"]"#).unwrap(), RelayMsg::Eose { sub_id: "s1" });
        assert_eq!(RelayMsg::parse(r#"["CLOSED","s1","error: no"]"#).unwrap(), RelayMsg::Closed { sub_id: "s1", message: "error: no".into() });
        assert_eq!(RelayMsg::parse(r#"["CLOSED","s1"]"#).unwrap(), RelayMsg::Closed { sub_id: "s1", message: String::new() });
        assert_eq!(RelayMsg::parse(r#"["NOTICE","hi\nthere"]"#).unwrap(), RelayMsg::Notice { message: "hi\nthere".into() });
        assert_eq!(RelayMsg::parse(r#"["NEG-MSG","n","61ff"]"#).unwrap(), RelayMsg::NegMsg { sub_id: "n", msg: vec![0x61, 0xff] });
        // strfry's NEG-ERR carries the limit it hit after the reason.
        assert_eq!(
            RelayMsg::parse(r#"["NEG-ERR","n","blocked: too many query results",1000000]"#).unwrap(),
            RelayMsg::NegErr { sub_id: "n", message: "blocked: too many query results".into() }
        );
        assert_eq!(RelayMsg::parse(r#"["AUTH","challenge"]"#).unwrap(), RelayMsg::Other);
        assert_eq!(RelayMsg::parse(r#"["COUNT","c",{"count":5}]"#).unwrap(), RelayMsg::Other);
        let bad_ok = format!(r#"["OK","{id}",1,""]"#);
        for bad in ["", "[]", r#"["EVENT","s1"]"#, r#"["EVENT","s1",[]]"#, r#"["OK","zz",true,""]"#, &bad_ok, r#"["EOSE","s1"] x"#, r#"["NEG-MSG","n","zz"]"#] {
            assert!(RelayMsg::parse(bad).is_err(), "{bad}");
        }
    }
}
