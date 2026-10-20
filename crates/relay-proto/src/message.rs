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
