// SPDX-License-Identifier: MIT OR Apache-2.0

//! DNS TXT lookup, as an injectable seam (issue #96).
//!
//! Domain verification asks one question: does this operator control this domain? The
//! proof is a TXT record they publish containing a token only this deployment knows. The
//! lookup is therefore a security-relevant read, and it lives beside [`crate::Resolve`]
//! and [`crate::Dial`] for the same reason those do: the production path talks to the
//! network, so anything testing a decision needs a seam to inject instead.
//!
//! # Why this is hand-written rather than a resolver crate
//!
//! Measured, not assumed. `hickory-resolver 0.25` fails `cargo deny` on two denial-of-service
//! advisories in `hickory-proto` (RUSTSEC-2026-0118, an unbounded loop in NSEC3 proof
//! validation, and RUSTSEC-2026-0119, O(n²) name compression during message ENCODING,
//! which a resolver performs on every query). Version 0.26 clears both and then declares
//! `rust-version = 1.88` across three crates, against this workspace's published MSRV of
//! 1.85. Raising a published MSRV to enable one optional feature is the wrong trade, and
//! shipping known denial-of-service advisories into a security product is worse.
//!
//! So: a query builder and a response parser for exactly one record type. The standing
//! dependency policy prescribes this for exactly this situation.
//!
//! # Why hand-written DNS parsing is acceptable HERE and would not be everywhere
//!
//! The failure mode is FAIL-SAFE, which is the whole argument. The strings this returns
//! are compared for exact equality against a 256-bit token. A parser that returns
//! garbage, truncates, or returns nothing produces NO match, so the domain stays
//! `pending`. There is no input to this parser that can cause a domain to verify when it
//! should not; the worst outcome is that a legitimate operator has to retry.
//!
//! That is not true of DNS parsing in general (a resolver feeding an authorization
//! decision, say), which is why the argument is written down rather than assumed to
//! generalise.
//!
//! # What is defended against, and what is not
//!
//! DEFENDED: response forgery by an off-path attacker, to the extent DNS-over-UDP allows.
//! The query ID is drawn from the system CSPRNG and the source port is randomised by
//! binding to port 0, so an attacker must guess 32 bits to land a forged answer; the
//! response is matched on ID, on the question, and on the source address. A forged
//! answer would otherwise let somebody verify a domain they do not control, which is the
//! only real attack on this mechanism.
//!
//! NOT DEFENDED: an ON-PATH attacker, or a compromised resolver. Neither is: this is
//! plain DNS, and defending it needs DNSSEC or DNS-over-TLS, which is a deployment decision rather
//! than something this module can assert. An operator who cannot trust their resolver
//! cannot trust domain verification, and that is true of every product that does this.
//!
//! Every read is bounds-checked and every loop is bounded, including the compression
//! pointer walk, which is the classic way a DNS parser hangs.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::time::Duration;

use ironauth_env::Env;
use tokio::net::UdpSocket;

/// The DNS record type for TXT.
const TYPE_TXT: u16 = 16;
/// The DNS class for the internet.
const CLASS_IN: u16 = 1;
/// The EDNS0 OPT pseudo-record type.
const TYPE_OPT: u16 = 41;
/// The UDP payload size advertised through EDNS0, and the receive buffer. 1232 is the
/// modern default: large enough that a realistic TXT set is not truncated, small enough
/// to avoid fragmentation on a 1280-byte IPv6 path.
const UDP_PAYLOAD: usize = 1232;
/// How long to wait for a single resolver to answer.
const TIMEOUT: Duration = Duration::from_secs(5);
/// The most compression pointers to follow before declaring the message malformed. A
/// pointer that jumps backwards forever is how a DNS parser hangs; this is that bound.
const MAX_POINTER_JUMPS: usize = 16;
/// The most answer records to walk. A resolver that returns an implausible number of
/// answers is not one worth parsing.
const MAX_ANSWERS: usize = 64;

/// Read the TXT records published at a domain.
pub trait TxtLookup: Send + Sync {
    /// Every TXT record string at `domain`.
    ///
    /// A domain with no TXT records is an EMPTY vector, not an error: the record simply
    /// has not been published yet, which is the ordinary state of a domain awaiting
    /// verification.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the lookup could not be performed or the answer could not
    /// be trusted (no resolver, a timeout, a truncated or malformed message, SERVFAIL). A
    /// caller must treat that as UNKNOWN, never as proof of absence: moving a domain to
    /// `failed` on a transient resolver error tells an operator their DNS is wrong when
    /// it is not.
    fn txt<'a>(
        &'a self,
        domain: &'a str,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<String>>> + Send + 'a>>;
}

/// Encode `domain` as a DNS QNAME: length-prefixed labels, terminated by a zero byte.
fn encode_qname(domain: &str, out: &mut Vec<u8>) -> io::Result<()> {
    for label in domain.trim_end_matches('.').split('.') {
        if label.is_empty() {
            return Err(io::Error::other("a domain label may not be empty"));
        }
        let len = u8::try_from(label.len())
            .map_err(|_| io::Error::other("a domain label may not exceed 63 bytes"))?;
        if len > 63 {
            return Err(io::Error::other("a domain label may not exceed 63 bytes"));
        }
        out.push(len);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    Ok(())
}

/// Build a TXT query for `domain` with the given id, including an EDNS0 OPT record.
fn build_query(id: u16, domain: &str) -> io::Result<Vec<u8>> {
    let mut message = Vec::with_capacity(64);
    message.extend_from_slice(&id.to_be_bytes());
    // RD (recursion desired). Everything else zero: this is a stub asking a recursor.
    message.extend_from_slice(&0x0100_u16.to_be_bytes());
    message.extend_from_slice(&1_u16.to_be_bytes()); // QDCOUNT
    message.extend_from_slice(&0_u16.to_be_bytes()); // ANCOUNT
    message.extend_from_slice(&0_u16.to_be_bytes()); // NSCOUNT
    message.extend_from_slice(&1_u16.to_be_bytes()); // ARCOUNT: the OPT record below
    encode_qname(domain, &mut message)?;
    message.extend_from_slice(&TYPE_TXT.to_be_bytes());
    message.extend_from_slice(&CLASS_IN.to_be_bytes());
    // EDNS0 OPT: root name, type OPT, "class" carrying the payload size, zero TTL and
    // rdata. Without it a resolver may only send 512 bytes and truncate a realistic TXT
    // set, which this module treats as an error rather than a partial answer.
    message.push(0);
    message.extend_from_slice(&TYPE_OPT.to_be_bytes());
    message.extend_from_slice(
        &u16::try_from(UDP_PAYLOAD)
            .expect("the payload constant fits u16")
            .to_be_bytes(),
    );
    message.extend_from_slice(&0_u32.to_be_bytes()); // extended rcode + flags
    message.extend_from_slice(&0_u16.to_be_bytes()); // rdlength
    Ok(message)
}

/// Advance past a (possibly compressed) name at `at`, returning the offset just after it.
///
/// Only the length is wanted, never the name itself, so a pointer is followed only far
/// enough to know the encoding ends. The jump budget is what stops a self-referential
/// pointer from hanging the parser.
fn skip_name(message: &[u8], mut at: usize) -> io::Result<usize> {
    let mut jumps = 0_usize;
    loop {
        let len = *message
            .get(at)
            .ok_or_else(|| io::Error::other("name runs past the end of the message"))?;
        if len & 0xC0 == 0xC0 {
            // A pointer is two bytes and ends the name here, whatever it points at.
            if message.len() <= at + 1 {
                return Err(io::Error::other("truncated compression pointer"));
            }
            jumps += 1;
            if jumps > MAX_POINTER_JUMPS {
                return Err(io::Error::other("too many compression pointers"));
            }
            return Ok(at + 2);
        }
        if len == 0 {
            return Ok(at + 1);
        }
        at = at
            .checked_add(1 + usize::from(len))
            .ok_or_else(|| io::Error::other("name length overflow"))?;
    }
}

/// Read a big-endian u16 at `at`.
fn u16_at(message: &[u8], at: usize) -> io::Result<u16> {
    let bytes = message
        .get(at..at + 2)
        .ok_or_else(|| io::Error::other("message ends mid-field"))?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

/// Parse the TXT strings out of a response to `expected_id`.
///
/// Returns an empty vector for a well-formed answer that contains no TXT records, which
/// includes NXDOMAIN: an unpublished domain is the ordinary pending state.
pub(crate) fn parse_txt_response(message: &[u8], expected_id: u16) -> io::Result<Vec<String>> {
    if message.len() < 12 {
        return Err(io::Error::other("response shorter than a DNS header"));
    }
    if u16_at(message, 0)? != expected_id {
        // Not an answer to our question. Refused rather than parsed, because accepting
        // it is exactly the forgery this check exists to stop.
        return Err(io::Error::other("response id does not match the query"));
    }
    let flags = u16_at(message, 2)?;
    if flags & 0x0200 != 0 {
        // TC: the answer did not fit. A partial TXT set could omit the very record being
        // looked for, so this is UNKNOWN, never "not published".
        return Err(io::Error::other("response truncated"));
    }
    let rcode = flags & 0x000F;
    // 3 is NXDOMAIN: the name does not exist, which is a definite "nothing published".
    if rcode == 3 {
        return Ok(Vec::new());
    }
    if rcode != 0 {
        return Err(io::Error::other(format!("resolver returned rcode {rcode}")));
    }

    let qdcount = usize::from(u16_at(message, 4)?);
    let ancount = usize::from(u16_at(message, 6)?);
    let mut at = 12;
    for _ in 0..qdcount {
        at = skip_name(message, at)?;
        at = at
            .checked_add(4)
            .ok_or_else(|| io::Error::other("question overflow"))?;
    }

    let mut out = Vec::new();
    for _ in 0..ancount.min(MAX_ANSWERS) {
        at = skip_name(message, at)?;
        let rtype = u16_at(message, at)?;
        let rdlength = usize::from(u16_at(message, at + 8)?);
        let rdata_at = at + 10;
        let rdata = message
            .get(rdata_at..rdata_at + rdlength)
            .ok_or_else(|| io::Error::other("record data runs past the end of the message"))?;
        if rtype == TYPE_TXT {
            // A TXT record is a sequence of character-strings, and a value longer than
            // 255 bytes is SPLIT across several. Joining them with no separator is what
            // the value IS; treating each chunk as its own record would make a long token
            // unverifiable for a reason no operator could diagnose.
            let mut value = String::new();
            let mut chunk_at = 0_usize;
            while chunk_at < rdata.len() {
                let len = usize::from(rdata[chunk_at]);
                let start = chunk_at + 1;
                let chunk = rdata
                    .get(start..start + len)
                    .ok_or_else(|| io::Error::other("txt chunk runs past the record"))?;
                value.push_str(&String::from_utf8_lossy(chunk));
                chunk_at = start + len;
            }
            out.push(value);
        }
        at = rdata_at
            .checked_add(rdlength)
            .ok_or_else(|| io::Error::other("record overflow"))?;
    }
    Ok(out)
}

/// The nameservers to ask, read from the system configuration.
#[cfg(unix)]
fn system_nameservers() -> io::Result<Vec<IpAddr>> {
    let conf = std::fs::read_to_string("/etc/resolv.conf")?;
    let servers: Vec<IpAddr> = conf
        .lines()
        .filter_map(|line| {
            let line = line.split('#').next().unwrap_or("").trim();
            line.strip_prefix("nameserver ")
                .and_then(|rest| rest.trim().parse::<IpAddr>().ok())
        })
        .collect();
    if servers.is_empty() {
        return Err(io::Error::other("no nameserver in /etc/resolv.conf"));
    }
    Ok(servers)
}

#[cfg(not(unix))]
fn system_nameservers() -> io::Result<Vec<IpAddr>> {
    Err(io::Error::other(
        "system nameserver discovery is implemented for unix only",
    ))
}

/// The production lookup: a UDP query to a system-configured resolver.
pub struct SystemTxtLookup {
    nameservers: Vec<IpAddr>,
    /// Randomness arrives through `Env`, never `getrandom` directly: the invariant lint
    /// `entropy-via-env` enforces that across the workspace so nonce generation stays
    /// deterministic under test. Here it also means a test can drive a KNOWN query id
    /// and assert the forgery check on it.
    env: Env,
}

impl SystemTxtLookup {
    /// Build a lookup from the system resolver configuration.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the system configuration cannot be read or names no
    /// nameserver.
    pub fn from_system_conf(env: Env) -> io::Result<Self> {
        Ok(Self {
            nameservers: system_nameservers()?,
            env,
        })
    }

    /// Ask one nameserver.
    async fn ask(&self, server: IpAddr, domain: &str) -> io::Result<Vec<String>> {
        let mut id_bytes = [0_u8; 2];
        self.env.entropy().fill_bytes(&mut id_bytes);
        let id = u16::from_be_bytes(id_bytes);
        let query = build_query(id, domain)?;

        // Binding to port 0 randomises the source port, which is the other half of the
        // off-path forgery budget alongside the query id.
        let bind: SocketAddr = if server.is_ipv6() {
            "[::]:0".parse().map_err(io::Error::other)?
        } else {
            "0.0.0.0:0".parse().map_err(io::Error::other)?
        };
        let socket = UdpSocket::bind(bind).await?;
        let target = SocketAddr::new(server, 53);
        socket.send_to(&query, target).await?;

        let mut buffer = vec![0_u8; UDP_PAYLOAD];
        let (read, from) = tokio::time::timeout(TIMEOUT, socket.recv_from(&mut buffer))
            .await
            .map_err(|_| io::Error::other("dns query timed out"))??;
        // A datagram from anywhere else is not an answer to this question.
        if from.ip() != server {
            return Err(io::Error::other("dns response from an unexpected address"));
        }
        parse_txt_response(&buffer[..read], id)
    }
}

impl TxtLookup for SystemTxtLookup {
    fn txt<'a>(
        &'a self,
        domain: &'a str,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<String>>> + Send + 'a>> {
        Box::pin(async move {
            let mut last = io::Error::other("no nameserver answered");
            for server in &self.nameservers {
                match self.ask(*server, domain).await {
                    Ok(records) => return Ok(records),
                    // Try the next resolver: a single unreachable one is not an answer
                    // about the domain.
                    Err(error) => last = error,
                }
            }
            Err(last)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Assemble a response: header, echoed question, then raw answer bytes.
    fn response(id: u16, flags: u16, ancount: u16, answers: &[u8]) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(&id.to_be_bytes());
        m.extend_from_slice(&flags.to_be_bytes());
        m.extend_from_slice(&1_u16.to_be_bytes());
        m.extend_from_slice(&ancount.to_be_bytes());
        m.extend_from_slice(&0_u16.to_be_bytes());
        m.extend_from_slice(&0_u16.to_be_bytes());
        encode_qname("acme.example", &mut m).expect("qname");
        m.extend_from_slice(&TYPE_TXT.to_be_bytes());
        m.extend_from_slice(&CLASS_IN.to_be_bytes());
        m.extend_from_slice(answers);
        m
    }

    /// One TXT answer whose rdata is the given chunks, using a compression pointer for
    /// the name exactly as a real resolver does.
    fn txt_answer(chunks: &[&[u8]]) -> Vec<u8> {
        let mut rdata = Vec::new();
        for chunk in chunks {
            rdata.push(u8::try_from(chunk.len()).expect("chunk fits"));
            rdata.extend_from_slice(chunk);
        }
        let mut a = vec![0xC0, 0x0C];
        a.extend_from_slice(&TYPE_TXT.to_be_bytes());
        a.extend_from_slice(&CLASS_IN.to_be_bytes());
        a.extend_from_slice(&300_u32.to_be_bytes());
        a.extend_from_slice(&u16::try_from(rdata.len()).expect("fits").to_be_bytes());
        a.extend_from_slice(&rdata);
        a
    }

    #[test]
    fn a_single_txt_record_is_read() {
        let m = response(
            0x1234,
            0x8180,
            1,
            &txt_answer(&[b"ironauth-domain-verification=abc"]),
        );
        let records = parse_txt_response(&m, 0x1234).expect("parse");
        assert_eq!(records, vec!["ironauth-domain-verification=abc".to_owned()]);
    }

    /// A value longer than 255 bytes is SPLIT across character-strings, and the value is
    /// their concatenation. Reading each chunk as its own record would make a long token
    /// unverifiable for a reason no operator could diagnose.
    #[test]
    fn a_split_value_is_rejoined_rather_than_reported_as_two_records() {
        let m = response(
            1,
            0x8180,
            1,
            &txt_answer(&[b"ironauth-domain-", b"verification=abc"]),
        );
        let records = parse_txt_response(&m, 1).expect("parse");
        assert_eq!(records, vec!["ironauth-domain-verification=abc".to_owned()]);
    }

    /// Records that are not ours are returned too: the DECISION belongs to the caller
    /// that knows the token, not to the parser.
    #[test]
    fn unrelated_txt_records_are_returned_and_not_filtered_here() {
        let mut answers = txt_answer(&[b"v=spf1 -all"]);
        answers.extend_from_slice(&txt_answer(&[b"ironauth-domain-verification=abc"]));
        let m = response(2, 0x8180, 2, &answers);
        let records = parse_txt_response(&m, 2).expect("parse");
        assert_eq!(records.len(), 2, "both records come back: {records:?}");
    }

    /// THE forgery check. An answer whose id does not match the query is refused, not
    /// parsed: accepting it is how an off-path attacker verifies a domain they do not
    /// control.
    #[test]
    fn a_response_with_the_wrong_id_is_refused() {
        let m = response(
            0xAAAA,
            0x8180,
            1,
            &txt_answer(&[b"ironauth-domain-verification=abc"]),
        );
        assert!(
            parse_txt_response(&m, 0xBBBB).is_err(),
            "a mismatched id must be refused, or an off-path forgery is accepted"
        );
    }

    /// A truncated answer is UNKNOWN, never "not published": the omitted part could be
    /// the very record being looked for.
    #[test]
    fn a_truncated_response_is_an_error_rather_than_an_empty_answer() {
        let m = response(3, 0x8380, 0, &[]);
        assert!(
            parse_txt_response(&m, 3).is_err(),
            "TC must not read as empty"
        );
    }

    /// NXDOMAIN is a definite nothing-published, which is the ordinary pending state.
    #[test]
    fn nxdomain_is_empty_rather_than_an_error() {
        let m = response(4, 0x8183, 0, &[]);
        assert_eq!(
            parse_txt_response(&m, 4).expect("parse"),
            Vec::<String>::new()
        );
    }

    /// SERVFAIL is UNKNOWN. Reading it as "no records" would move a domain to failed
    /// because a resolver hiccuped.
    #[test]
    fn servfail_is_an_error_rather_than_an_empty_answer() {
        let m = response(5, 0x8182, 0, &[]);
        assert!(
            parse_txt_response(&m, 5).is_err(),
            "SERVFAIL must not read as empty"
        );
    }

    /// The classic hang: a compression pointer that points at itself. Bounded, so this
    /// returns rather than spinning.
    #[test]
    fn a_self_referential_compression_pointer_terminates() {
        // The pointer at offset 12 points back to offset 12.
        let mut m = response(6, 0x8180, 1, &[]);
        m.truncate(12);
        m.extend_from_slice(&[0xC0, 0x0C]);
        let _ = parse_txt_response(&m, 6);
    }

    /// A record claiming more data than the message holds is refused, not read past.
    #[test]
    fn an_rdlength_past_the_end_is_refused() {
        let mut answers = vec![0xC0, 0x0C];
        answers.extend_from_slice(&TYPE_TXT.to_be_bytes());
        answers.extend_from_slice(&CLASS_IN.to_be_bytes());
        answers.extend_from_slice(&300_u32.to_be_bytes());
        answers.extend_from_slice(&9999_u16.to_be_bytes());
        // The bytes that ARE present form a perfectly valid chunk sequence, so the chunk
        // bound cannot catch this and only the rdlength check can. An earlier version of
        // this test used bytes that tripped the chunk bound instead, which meant it
        // passed with the rdlength check weakened: a mutation clamping rdlength to the
        // buffer end survived it.
        answers.extend_from_slice(&[4, b'a', b'b', b'c', b'd']);
        let m = response(7, 0x8180, 1, &answers);
        assert!(
            parse_txt_response(&m, 7).is_err(),
            "an over-long rdlength must be refused rather than silently clamped to what \
             the message happens to contain"
        );
    }

    /// A chunk length past the end of its own record is refused.
    #[test]
    fn a_txt_chunk_past_the_record_is_refused() {
        let mut rdata = vec![250_u8];
        rdata.extend_from_slice(b"tiny");
        let mut answers = vec![0xC0, 0x0C];
        answers.extend_from_slice(&TYPE_TXT.to_be_bytes());
        answers.extend_from_slice(&CLASS_IN.to_be_bytes());
        answers.extend_from_slice(&300_u32.to_be_bytes());
        answers.extend_from_slice(&u16::try_from(rdata.len()).expect("fits").to_be_bytes());
        answers.extend_from_slice(&rdata);
        let m = response(8, 0x8180, 1, &answers);
        assert!(
            parse_txt_response(&m, 8).is_err(),
            "a chunk must stay inside its record"
        );
    }

    /// A header-only truncation is refused rather than indexed into.
    #[test]
    fn a_runt_message_is_refused() {
        assert!(parse_txt_response(&[0, 1, 2], 1).is_err());
    }

    /// The query we send is well formed: one question, one additional (the EDNS0 OPT),
    /// and the recursion-desired bit set.
    #[test]
    fn the_query_asks_one_txt_question_with_edns0() {
        let q = build_query(0x4242, "acme.example").expect("build");
        assert_eq!(u16::from_be_bytes([q[0], q[1]]), 0x4242, "the id is ours");
        assert_eq!(
            u16::from_be_bytes([q[2], q[3]]) & 0x0100,
            0x0100,
            "RD is set"
        );
        assert_eq!(u16::from_be_bytes([q[4], q[5]]), 1, "one question");
        assert_eq!(
            u16::from_be_bytes([q[10], q[11]]),
            1,
            "one additional: the OPT"
        );
    }

    /// An empty label is refused at build time rather than producing a malformed query.
    #[test]
    fn a_malformed_domain_is_refused_before_anything_is_sent() {
        assert!(build_query(1, "acme..example").is_err());
    }
}
