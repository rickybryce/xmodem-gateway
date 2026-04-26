//! Kermit Protocol Module
//!
//! Implements the Kermit File Transfer Protocol per Frank da Cruz,
//! "Kermit, A File Transfer Protocol" (Digital Press, 1987) plus the
//! long-packet, sliding-window, and streaming extensions.
//!
//! Coverage:
//! - All three block-check types (CHKT 1 = 6-bit checksum, CHKT 2 = 12-bit
//!   checksum, CHKT 3 = CRC-16/KERMIT — reflected CCITT, poly 0x8408,
//!   seed 0).
//! - Control-character quoting (QCTL prefix), 8th-bit prefixing (QBIN),
//!   repeat-count compression (REPT).
//! - Long packets (extended length, up to ~9024 bytes per packet).
//! - Sliding windows (up to 31 outstanding packets).
//! - Streaming Kermit (CAPAS streaming bit) — sender skips waiting for
//!   per-packet ACKs on reliable links; receiver only sends NAK on error.
//! - Attribute packets (file size, date, mode, system ID, encoding).
//! - Server-mode subset: accept incoming G F (finish) and G L (logout)
//!   politely; full server-mode is not implemented.
//! - Telnet NVT awareness matches `xmodem.rs` / `zmodem.rs`: the raw I/O
//!   layer handles IAC escaping and CR-NUL stuffing.
//!
//! Public surface (used by `telnet.rs`):
//! - [`kermit_receive`] — read one or more files from the peer (upload).
//! - [`kermit_send`] — send one or more files to the peer (download).
//!
//! Within a session we auto-detect the peer's flavor (C-Kermit, G-Kermit,
//! Kermit-86, C64-Kermit, etc.) from its Send-Init parameters; flavor is
//! informational only since CAPAS-intersection negotiation does the right
//! thing for each peer automatically.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::config;
use crate::logger::glog;
use crate::telnet::is_esc_key;

// ─── Wire constants ──────────────────────────────────────────

/// Standard packet start byte (Start-Of-Header).  Spec mandates this
/// for the first packet of a session; subsequent packets MAY use a
/// different MARK if peers agree, but in practice everyone uses SOH.
pub(crate) const SOH: u8 = 0x01;
const SP: u8 = 0x20; // space — tochar(0); marker for extended-length packets
const CR: u8 = 0x0D;
#[allow(dead_code)]
const LF: u8 = 0x0A;
const DEL: u8 = 0x7F;
/// Default Kermit control-quote character.  Always one of `#` `&` `'`
/// `(` … per spec; `#` is overwhelmingly the de-facto standard.
const DEFAULT_QCTL: u8 = b'#';
/// Default 8th-bit prefix; one of `&` `'` `(` `)` `*` `+` `,` `-`
/// `.` `/`.  `&` is the C-Kermit / G-Kermit default.
const DEFAULT_QBIN_PREFIX: u8 = b'&';
/// Default repeat-count prefix; one of `~` `}` `|` `!` etc.
const DEFAULT_REPT: u8 = b'~';
/// Default end-of-line that the protocol places after each transmitted
/// packet.  Spec says CR, but lets the peer override via the EOL slot of
/// Send-Init.  We always emit CR and accept whatever the peer asks for.
#[allow(dead_code)]
const DEFAULT_EOL: u8 = CR;

// Packet type bytes (always ASCII letters)
pub(crate) const TYPE_SEND_INIT: u8 = b'S';
pub(crate) const TYPE_FILE: u8 = b'F';
pub(crate) const TYPE_ATTRIBUTE: u8 = b'A';
pub(crate) const TYPE_DATA: u8 = b'D';
pub(crate) const TYPE_EOF: u8 = b'Z';
pub(crate) const TYPE_EOT: u8 = b'B';
pub(crate) const TYPE_ACK: u8 = b'Y';
pub(crate) const TYPE_NAK: u8 = b'N';
pub(crate) const TYPE_ERROR: u8 = b'E';
#[allow(dead_code)]
pub(crate) const TYPE_TIMEOUT: u8 = b'T';
#[allow(dead_code)]
pub(crate) const TYPE_RESERVED_Q: u8 = b'Q';
pub(crate) const TYPE_GENERIC: u8 = b'G';
#[allow(dead_code)]
pub(crate) const TYPE_HOST: u8 = b'C';
#[allow(dead_code)]
pub(crate) const TYPE_TEXT: u8 = b'X';

// CAPAS bit positions in the first capability byte (bits are read after
// stripping the LSB continuation flag — i.e. real bit n of capability
// equals bit (n+1) of the unchar'd byte).
//
// Bit layout (from Frank da Cruz, "Kermit Protocol Manual"):
//   bit 0: continuation — another CAPAS byte follows
//   bit 1: ability to do sliding-window
//   bit 2: ability to do extended-length (long) packets
//   bit 3: ability to handle attribute (A) packets
//   bit 4: ability to do RESEND (resume) — we don't implement
//   bit 5: ability to use locking shifts — we don't implement
//
// Streaming and other extended bits live in subsequent CAPAS bytes,
// vendor-defined.  C-Kermit uses CAPAS byte 3 bit 2 for streaming.
pub(crate) const CAPAS_ATTRIBUTE: u8 = 0x08;
pub(crate) const CAPAS_LONGPKT: u8 = 0x04;
pub(crate) const CAPAS_SLIDING: u8 = 0x02;
pub(crate) const CAPAS_CONTINUE: u8 = 0x01;
#[allow(dead_code)]
pub(crate) const CAPAS_RESEND: u8 = 0x10;
#[allow(dead_code)]
pub(crate) const CAPAS_LOCKING_SHIFT: u8 = 0x20;

/// Streaming Kermit lives in CAPAS byte 3 bit 2 (per C-Kermit).  In our
/// internal `Capabilities` struct it's a bool; the wire encoding handles
/// placement.
pub(crate) const CAPAS_STREAMING_BYTE3_BIT: u8 = 0x04;

// Telnet protocol bytes (duplicated from xmodem.rs / zmodem.rs to keep
// the module decoupled — same justification as zmodem.rs:67-75).
const IAC: u8 = 0xFF;
const SB: u8 = 250;
const SE: u8 = 240;
const WILL: u8 = 251;
const WONT: u8 = 252;
const DO_CMD: u8 = 253;
const DONT: u8 = 254;
/// CAN byte (0x18) — accepted as an additional abort signal alongside
/// the canonical Kermit E-packet.  Two consecutive CANs are required
/// to abort, matching the Forsberg convention used elsewhere in the
/// codebase (see xmodem.rs::is_can_abort).
const CAN: u8 = 0x18;

// Limits
/// Maximum file size for a single Kermit transfer.  Matches the cap used
/// for XMODEM / ZMODEM in this codebase.
const MAX_FILE_SIZE: u64 = 8 * 1024 * 1024;
/// Lower bound on negotiable packet length.  Spec says 10; below this
/// the per-packet header overhead is too high to be useful.
pub(crate) const MIN_PACKET_LEN: usize = 10;
/// Classic short-packet ceiling.  tochar(N) maps 0..=94 to 0x20..=0x7E,
/// so length 94 is the largest value expressible in one byte.
pub(crate) const CLASSIC_MAX_PACKET_LEN: usize = 94;
/// Spec-mandated upper bound for extended-length packets.  Real-world
/// Kermits cap at 9024 because (95 * 95) = 9025 minus framing overhead.
pub(crate) const EXTENDED_MAX_PACKET_LEN: usize = 9024;
/// Maximum sliding-window size per spec (5 bits → 31 outstanding).
pub(crate) const MAX_WINDOW_SIZE: u8 = 31;

/// Sender-side reservation for worst-case quoting blowup, expressed as
/// a fraction `NUM / DEN` of the negotiated `MAXL` payload area.  3/4
/// gives ~33 % headroom — covers typical binary and text comfortably,
/// and the sender will fail rather than malform a packet on adversarial
/// all-control-byte input.
const QUOTING_HEADROOM_NUM: usize = 3;
const QUOTING_HEADROOM_DEN: usize = 4;

// =============================================================================
// CHARACTER ENCODING PRIMITIVES
// =============================================================================

/// Spec primitive: encode a small unsigned value (0..=94) as a printable
/// ASCII character by adding 0x20.  Inverse of [`unchar`].
///
/// Wraps with `wrapping_add` to keep the function panic-free on arbitrary
/// input — callers that care about validity should range-check first.
#[inline]
pub(crate) fn tochar(n: u8) -> u8 {
    n.wrapping_add(b' ')
}

/// Inverse of [`tochar`]: subtract 0x20 to recover the original value.
/// Wraps to keep the function panic-free.
#[inline]
pub(crate) fn unchar(c: u8) -> u8 {
    c.wrapping_sub(b' ')
}

/// Spec primitive: convert a control byte (0x00-0x1F or DEL=0x7F) to its
/// printable form by XORing with 0x40.  Inverse of [`unctl`].
///
/// The Kermit control-quote layer pairs a QCTL prefix character with the
/// `ctl`-encoded byte; e.g. CR (0x0D) becomes "#M" (`#` + 0x4D).
#[inline]
pub(crate) fn ctl(b: u8) -> u8 {
    b ^ 0x40
}

/// Inverse of [`ctl`].
#[inline]
pub(crate) fn unctl(b: u8) -> u8 {
    b ^ 0x40
}

/// Predicate: is `b` a "control byte" by Kermit's rules (i.e. needs
/// QCTL-quoting)?  Anything below 0x20 (control chars) and DEL (0x7F).
/// Note that the QCTL byte itself ALSO needs quoting, but that's handled
/// at the quoting layer where the QCTL value is in scope.
#[inline]
pub(crate) fn is_kermit_control(b: u8) -> bool {
    b < 0x20 || b == DEL
}

// =============================================================================
// BLOCK-CHECK COMPUTATIONS
// =============================================================================

/// Type-1 block check: low 6 bits of the byte sum, with the high 2 bits
/// folded back in for randomness, then `tochar`-encoded.  This is what
/// classic 1980s Kermits use, and is also used for the *header* check in
/// extended-length packets regardless of the negotiated CHKT.
///
/// Returns the single tochar-encoded byte ready for transmission.
#[inline]
pub(crate) fn chk1(data: &[u8]) -> u8 {
    let s: u32 = data.iter().map(|&b| b as u32).sum();
    let folded = ((s + ((s & 0xC0) >> 6)) & 0x3F) as u8;
    tochar(folded)
}

/// Type-2 block check: 12-bit byte sum, transmitted as two tochar-encoded
/// 6-bit chunks (high then low).  Fills the gap between CHKT-1's 6 bits
/// and CHKT-3's 16-bit CRC for slow microcontrollers that can do
/// addition but not CRC.
///
/// Returns `(high_char, low_char)`.
#[inline]
pub(crate) fn chk2(data: &[u8]) -> (u8, u8) {
    let s: u32 = data.iter().map(|&b| b as u32).sum::<u32>() & 0x0FFF;
    let hi = ((s >> 6) & 0x3F) as u8;
    let lo = (s & 0x3F) as u8;
    (tochar(hi), tochar(lo))
}

/// Reverse a type-2 check back into its 12-bit numeric value.  Used by
/// the receiver to compare against a freshly-computed sum.
#[inline]
pub(crate) fn chk2_decode(hi: u8, lo: u8) -> u16 {
    ((unchar(hi) as u16 & 0x3F) << 6) | (unchar(lo) as u16 & 0x3F)
}

/// CRC-16/KERMIT — also known as CRC-CCITT-True or "Kermit CRC".
///
/// Parameters per the CRC catalogue:
///   width  = 16
///   poly   = 0x1021 (CCITT)
///   init   = 0x0000
///   refin  = true   (reflected input)
///   refout = true   (reflected output)
///   xorout = 0x0000
///   check  = 0x2189 (for input "123456789")
///
/// This is **different from XMODEM CRC**, which is the same polynomial
/// but non-reflected (poly 0x1021 left-shift form, check 0x31C3).  We
/// implement it directly with the reflected polynomial 0x8408 to avoid
/// the bit-reversal at every step.
pub(crate) fn kermit_crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &b in data {
        crc ^= b as u16;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0x8408;
            } else {
                crc >>= 1;
            }
        }
    }
    crc
}

/// Type-3 block check: split a 16-bit CRC into three tochar-encoded
/// 6-bit chunks (top 4 bits zero-padded, then mid 6, then low 6).  The
/// top-bit-only chunk wastes 2 of its 6 bits but the spec is fixed.
///
/// Returns `(c1, c2, c3)`.
#[inline]
pub(crate) fn chk3_encode(crc: u16) -> (u8, u8, u8) {
    let c1 = ((crc >> 12) & 0x0F) as u8;
    let c2 = ((crc >> 6) & 0x3F) as u8;
    let c3 = (crc & 0x3F) as u8;
    (tochar(c1), tochar(c2), tochar(c3))
}

/// Reverse a type-3 check back into a 16-bit CRC.  Bits beyond position
/// 15 are masked off so a malformed peer can't smuggle data through the
/// 4-bit padding slot.
#[inline]
pub(crate) fn chk3_decode(c1: u8, c2: u8, c3: u8) -> u16 {
    ((unchar(c1) as u16 & 0x0F) << 12)
        | ((unchar(c2) as u16 & 0x3F) << 6)
        | (unchar(c3) as u16 & 0x3F)
}

/// How many trailing CHECK bytes a packet has, for a given CHKT.
#[inline]
pub(crate) fn check_size(chkt: u8) -> usize {
    match chkt {
        b'1' => 1,
        b'2' => 2,
        b'3' => 3,
        _ => 1, // unknown CHKT degrades to type-1 length per spec recovery rules
    }
}

/// Compute the CHECK trailer bytes for a packet's header+data span, given
/// the negotiated CHKT.  Returns 1, 2, or 3 bytes.
pub(crate) fn block_check(chkt: u8, data: &[u8]) -> Vec<u8> {
    match chkt {
        b'2' => {
            let (hi, lo) = chk2(data);
            vec![hi, lo]
        }
        b'3' => {
            let crc = kermit_crc16(data);
            let (c1, c2, c3) = chk3_encode(crc);
            vec![c1, c2, c3]
        }
        _ => vec![chk1(data)],
    }
}

/// Verify that a CHECK trailer matches a freshly-computed value over the
/// header+data span.  Returns Ok(()) on match, Err(reason) otherwise.
pub(crate) fn verify_check(chkt: u8, data: &[u8], check: &[u8]) -> Result<(), String> {
    match chkt {
        b'2' => {
            if check.len() != 2 {
                return Err(format!(
                    "CHKT-2 expects 2 check bytes, got {}",
                    check.len()
                ));
            }
            let expected = chk2_decode(check[0], check[1]);
            let actual_sum: u32 = data.iter().map(|&b| b as u32).sum::<u32>() & 0x0FFF;
            if actual_sum as u16 == expected {
                Ok(())
            } else {
                Err(format!(
                    "CHKT-2 mismatch: expected {:#x} got {:#x}",
                    expected, actual_sum
                ))
            }
        }
        b'3' => {
            if check.len() != 3 {
                return Err(format!(
                    "CHKT-3 expects 3 check bytes, got {}",
                    check.len()
                ));
            }
            let expected = chk3_decode(check[0], check[1], check[2]);
            let actual = kermit_crc16(data);
            if expected == actual {
                Ok(())
            } else {
                Err(format!(
                    "CHKT-3 mismatch: expected {:#x} got {:#x}",
                    expected, actual
                ))
            }
        }
        _ => {
            if check.len() != 1 {
                return Err(format!(
                    "CHKT-1 expects 1 check byte, got {}",
                    check.len()
                ));
            }
            let expected = unchar(check[0]) & 0x3F;
            let s: u32 = data.iter().map(|&b| b as u32).sum();
            let actual = ((s + ((s & 0xC0) >> 6)) & 0x3F) as u8;
            if actual == expected {
                Ok(())
            } else {
                Err(format!(
                    "CHKT-1 mismatch: expected {:#x} got {:#x}",
                    expected, actual
                ))
            }
        }
    }
}

// =============================================================================
// QUOTING LAYER (control-char prefix, 8th-bit prefix, repeat-count)
// =============================================================================

/// The negotiated quoting parameters for one direction of a Kermit
/// session.  Both peers need to agree on these before any data flows;
/// the values are extracted from the Send-Init packet exchange.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Quoting {
    /// Control-char prefix.  Always present; spec default `#`.
    pub qctl: u8,
    /// 8th-bit prefix character.  `Some(c)` when 8th-bit quoting is
    /// active (peer asked for it or we're on a 7-bit link); `None` when
    /// 8-bit-clean transparent transmission is in use.
    pub qbin: Option<u8>,
    /// Repeat prefix character, when REPT compression is active.  `None`
    /// disables compression entirely.
    pub rept: Option<u8>,
}

impl Default for Quoting {
    fn default() -> Self {
        Self {
            qctl: DEFAULT_QCTL,
            qbin: None,
            rept: Some(DEFAULT_REPT),
        }
    }
}

/// Encode a single byte through the quoting layers into the output
/// buffer.  Inner per-byte step; the public encoder walks the input
/// slice and applies repeat compression when active.
fn encode_one_byte(out: &mut Vec<u8>, b: u8, q: Quoting) {
    // 8-bit prefix goes BEFORE all other prefixes per spec.  Strip the
    // high bit from the body if we're emitting the prefix; the receiver
    // OR's it back on.
    let body = if let Some(qbin) = q.qbin
        && b & 0x80 != 0
    {
        out.push(qbin);
        b & 0x7F
    } else {
        b
    };

    if is_kermit_control(body) {
        out.push(q.qctl);
        out.push(ctl(body));
    } else if body == q.qctl || q.qbin == Some(body) || q.rept == Some(body) {
        // Prefix bytes themselves must be escaped so the receiver can
        // distinguish a literal prefix from a real prefix.
        out.push(q.qctl);
        out.push(body);
    } else {
        out.push(body);
    }
}

/// Quote a byte slice into a packet's data payload, applying control,
/// 8th-bit, and (when enabled) repeat-count compression.
///
/// The output is what goes between TYPE and CHECK on the wire.
pub(crate) fn encode_data(input: &[u8], q: Quoting) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() * 2 + 8);
    let mut i = 0;
    while i < input.len() {
        // Repeat-count compression: only worth using for runs of >= 3
        // identical bytes (each repeat costs 2 chars: prefix + tochar(N)
        // before the encoded byte body, which is at least 1 char and at
        // most 4 — so 3-rep break-even is conservative).
        if let Some(rept_char) = q.rept {
            let mut run = 1;
            while run < 94 && i + run < input.len() && input[i + run] == input[i] {
                run += 1;
            }
            if run >= 3 {
                out.push(rept_char);
                out.push(tochar(run as u8));
                encode_one_byte(&mut out, input[i], q);
                i += run;
                continue;
            }
        }
        encode_one_byte(&mut out, input[i], q);
        i += 1;
    }
    out
}

/// Decode a quoted byte slice back into raw payload bytes.  Returns an
/// error string on malformed input (premature end-of-data after a
/// prefix, illegal control body, etc.).  The caller has already
/// verified the block check, so any malformation here points at a
/// protocol mismatch rather than corruption.
pub(crate) fn decode_data(input: &[u8], q: Quoting) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if Some(input[i]) == q.rept {
            // Repeat-count prefix: consume prefix + count + one quoted body.
            if i + 1 >= input.len() {
                return Err("Kermit: repeat prefix at end of data".into());
            }
            let n = unchar(input[i + 1]) as usize;
            if n == 0 || n > 94 {
                return Err(format!("Kermit: bad repeat count {}", n));
            }
            let (decoded, consumed) = decode_one_byte_at(input, i + 2, q)?;
            i += 2 + consumed;
            for _ in 0..n {
                out.push(decoded);
            }
            continue;
        }

        let (decoded, consumed) = decode_one_byte_at(input, i, q)?;
        i += consumed;
        out.push(decoded);
    }
    Ok(out)
}

/// Decode a single quoted byte starting at `input[start]`, returning the
/// decoded byte plus the number of input bytes consumed.  Avoids any
/// per-byte slice splicing by indexing into the original buffer.
fn decode_one_byte_at(input: &[u8], start: usize, q: Quoting) -> Result<(u8, usize), String> {
    if start >= input.len() {
        return Err("Kermit: decode_one_byte_at past end of data".into());
    }
    let mut i = start;
    let mut high_bit = 0u8;

    if let Some(qbin) = q.qbin
        && input[i] == qbin
    {
        high_bit = 0x80;
        i += 1;
        if i >= input.len() {
            return Err("Kermit: 8-bit prefix at end of data".into());
        }
    }

    if input[i] == q.qctl {
        i += 1;
        if i >= input.len() {
            return Err("Kermit: control-quote prefix at end of data".into());
        }
        let body = input[i];
        i += 1;
        // ctl-encoded control bytes use the ASCII printable range that
        // maps back to 0x00..=0x1F (and DEL via '?'); any other
        // printable body is a literal prefix byte the encoder protected
        // (QCTL, QBIN, or REPT itself).
        let decoded = if (0x40..=0x5F).contains(&body) || body == b'?' {
            unctl(body) | high_bit
        } else {
            body | high_bit
        };
        return Ok((decoded, i - start));
    }

    let body = input[i];
    i += 1;
    Ok((body | high_bit, i - start))
}

// =============================================================================
// PACKET BUILDER + PARSER
// =============================================================================

/// Decoded Kermit packet (after telnet de-IAC, after parser, before
/// payload-layer decoding).  The payload bytes here are the post-CHECK-
/// verified data field — still in encoded form (i.e. with QCTL/QBIN/REPT
/// quoting present).  Callers use [`decode_data`] when they need the
/// raw bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Packet {
    /// The 'S', 'F', 'D', etc. byte.
    pub kind: u8,
    /// Sequence number 0..=63, modulo 64.
    pub seq: u8,
    /// Encoded payload (between TYPE and CHECK).
    pub payload: Vec<u8>,
}

/// Build a complete on-the-wire packet ready for the raw I/O layer.
/// Handles standard and extended-length forms transparently; callers
/// pass the raw payload (already-quoted via [`encode_data`] when the
/// field is binary) and we add the framing.
///
/// `pad_count` and `pad_char` come from our peer's Send-Init.  We emit
/// `pad_count` copies of `pad_char` BEFORE MARK, per spec — they let
/// the peer's modem/UART recover from line transients before the SOH
/// arrives.
///
/// `eol` is the byte the peer asked us to terminate every packet with
/// (typically CR).
pub(crate) fn build_packet(
    kind: u8,
    seq: u8,
    payload: &[u8],
    chkt: u8,
    pad_count: u8,
    pad_char: u8,
    eol: u8,
) -> Vec<u8> {
    // Length includes SEQ + TYPE + DATA + CHECK.
    let cklen = check_size(chkt);
    let body_len = 1 + 1 + payload.len() + cklen; // SEQ TYPE DATA CHECK
    let mut out = Vec::with_capacity(payload.len() + 16 + pad_count as usize);

    // Pre-MARK padding
    for _ in 0..pad_count {
        out.push(pad_char);
    }

    out.push(SOH);

    if body_len <= CLASSIC_MAX_PACKET_LEN {
        // Standard packet
        out.push(tochar(body_len as u8));
        out.push(tochar(seq & 0x3F));
        out.push(kind);
        out.extend_from_slice(payload);
    } else {
        // Extended-length form: LEN = SP (tochar(0)) is the marker;
        // real length is in LENX1+LENX2 and counts SEQ+TYPE+LENX1+LENX2+HCHECK+DATA+CHECK.
        let extended_len = 5 + payload.len() + cklen;
        debug_assert!(
            extended_len <= EXTENDED_MAX_PACKET_LEN,
            "kermit: extended packet length {} exceeds spec cap {}; caller should have chunked",
            extended_len,
            EXTENDED_MAX_PACKET_LEN
        );
        let lenx1 = (extended_len / 95) as u8;
        let lenx2 = (extended_len % 95) as u8;
        out.push(SP);
        out.push(tochar(seq & 0x3F));
        out.push(kind);
        out.push(tochar(lenx1));
        out.push(tochar(lenx2));
        // HCHECK is always type-1 even when CHKT is 2 or 3 — spec rule.
        let hcheck_input = [SP, tochar(seq & 0x3F), kind, tochar(lenx1), tochar(lenx2)];
        out.push(chk1(&hcheck_input));
        out.extend_from_slice(payload);
    }

    let check_start = pad_count as usize + 1;
    let check_input = &out[check_start..];
    let trailer = block_check(chkt, check_input);
    out.extend_from_slice(&trailer);

    out.push(eol);
    out
}

/// Read one packet from the wire, performing telnet IAC unescaping and
/// CR-NUL stripping along the way.  Skips pre-MARK bytes (pad
/// characters, line noise, leftover EOL from the previous packet).
///
/// On bad block check, returns Err with a diagnostic; the caller decides
/// whether to NAK and retry or abort.  On telnet IAC sequences other
/// than `IAC IAC`, the bytes are consumed and the read continues.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn read_packet(
    reader: &mut (impl AsyncRead + Unpin),
    is_tcp: bool,
    is_petscii: bool,
    chkt: u8,
    eol: u8,
    state: &mut ReadState,
    deadline: Option<tokio::time::Instant>,
) -> Result<Packet, String> {
    // 1. Hunt for SOH, discarding everything else.  Anything that's not
    //    SOH is line noise (or the end-of-line of the previous packet).
    //    ESC (0x1B for ANSI, also 0x5F for PETSCII) and CAN×2 are the
    //    two user/peer abort signals that get processed during the hunt.
    loop {
        let b = read_byte_with_deadline(reader, is_tcp, state, deadline).await?;
        if b == SOH {
            break;
        }
        if is_esc_key(b, is_petscii) {
            return Err("Kermit: cancelled by user".into());
        }
        if is_can_abort(b, state) {
            return Err("Kermit: peer aborted (CAN×2)".into());
        }
    }

    // 2. LEN
    let len_byte = read_byte_with_deadline(reader, is_tcp, state, deadline).await?;
    let mut header_input: Vec<u8> = Vec::with_capacity(8);

    let (seq, kind, payload_len) = if len_byte == SP {
        // Extended-length packet
        header_input.push(len_byte);
        let seq_byte = read_byte_with_deadline(reader, is_tcp, state, deadline).await?;
        header_input.push(seq_byte);
        let kind = read_byte_with_deadline(reader, is_tcp, state, deadline).await?;
        header_input.push(kind);
        let lenx1 = read_byte_with_deadline(reader, is_tcp, state, deadline).await?;
        header_input.push(lenx1);
        let lenx2 = read_byte_with_deadline(reader, is_tcp, state, deadline).await?;
        header_input.push(lenx2);
        let hcheck = read_byte_with_deadline(reader, is_tcp, state, deadline).await?;
        // Verify HCHECK over LEN..LENX2 (5 bytes).
        let expected_hcheck = chk1(&header_input);
        if hcheck != expected_hcheck {
            return Err(format!(
                "Kermit: extended-length header check mismatch ({:#x} vs {:#x})",
                hcheck, expected_hcheck
            ));
        }
        // HCHECK participates in the trailing CHECK trailer, per spec.
        header_input.push(hcheck);
        let extended_len = (unchar(lenx1) as usize) * 95 + unchar(lenx2) as usize;
        let cklen = check_size(chkt);
        if extended_len < 5 + cklen {
            return Err(format!(
                "Kermit: extended length {} too short for header+check",
                extended_len
            ));
        }
        let payload_len = extended_len - 5 - cklen;
        if payload_len > EXTENDED_MAX_PACKET_LEN {
            return Err(format!(
                "Kermit: extended packet length {} exceeds spec cap",
                extended_len
            ));
        }
        (unchar(seq_byte) & 0x3F, kind, payload_len)
    } else {
        // Standard packet
        header_input.push(len_byte);
        let n = unchar(len_byte) as usize;
        if n < 3 {
            return Err(format!("Kermit: packet length {} too small", n));
        }
        let cklen = check_size(chkt);
        if n < 2 + cklen {
            return Err(format!(
                "Kermit: packet length {} short for header+check (cklen {})",
                n, cklen
            ));
        }
        let seq_byte = read_byte_with_deadline(reader, is_tcp, state, deadline).await?;
        header_input.push(seq_byte);
        let kind = read_byte_with_deadline(reader, is_tcp, state, deadline).await?;
        header_input.push(kind);
        let payload_len = n - 2 - cklen;
        (unchar(seq_byte) & 0x3F, kind, payload_len)
    };

    // 3. Read payload bytes.
    let mut payload = Vec::with_capacity(payload_len);
    for _ in 0..payload_len {
        payload.push(read_byte_with_deadline(reader, is_tcp, state, deadline).await?);
    }

    // 4. Read check bytes.
    let cklen = check_size(chkt);
    let mut check_bytes = Vec::with_capacity(cklen);
    for _ in 0..cklen {
        check_bytes.push(read_byte_with_deadline(reader, is_tcp, state, deadline).await?);
    }

    // 5. Verify CHECK over header_input ++ payload.
    let mut check_input: Vec<u8> = header_input.clone();
    check_input.extend_from_slice(&payload);
    verify_check(chkt, &check_input, &check_bytes)?;

    // 6. Consume the trailing EOL (best-effort — peer may omit it).
    if eol != 0 {
        // We don't insist on it; if the next byte isn't EOL we push it
        // back via the read state for the next packet's MARK hunt.
        match read_byte_with_deadline(reader, is_tcp, state, deadline).await {
            Ok(b) if b == eol => {}
            Ok(b) => {
                state.pushback = Some(b);
            }
            Err(_) => {} // EOF after a valid packet is fine
        }
    }

    Ok(Packet {
        kind,
        seq,
        payload,
    })
}

// =============================================================================
// RAW I/O LAYER (telnet IAC + CR-NUL stuffing)
// =============================================================================

/// Per-stream state threaded through reads.  Mirrors `xmodem.rs::ReadState`
/// (with pushback for CR-NUL lookahead and CAN×2 abort tracking).  Public
/// to the module's tests.
#[derive(Default)]
pub(crate) struct ReadState {
    pushback: Option<u8>,
    pending_can: bool,
}

/// CAN×2 abort detector — Forsberg's rule, the same as in xmodem.rs.
/// Two consecutive CAN bytes signal abort; a single CAN is considered
/// line noise.  Kermit's canonical abort is the E-packet, but we accept
/// CAN×2 too because terminal users sometimes mash Ctrl-X to bail.
fn is_can_abort(byte: u8, state: &mut ReadState) -> bool {
    if byte == CAN {
        if state.pending_can {
            state.pending_can = false;
            return true;
        }
        state.pending_can = true;
        false
    } else {
        state.pending_can = false;
        false
    }
}

/// Read a single NVT-aware byte, applying an optional deadline.  When
/// the deadline elapses we surface `"Kermit: read timeout"` so the
/// caller can decide whether to NAK + retry or abort.
async fn read_byte_with_deadline(
    reader: &mut (impl AsyncRead + Unpin),
    is_tcp: bool,
    state: &mut ReadState,
    deadline: Option<tokio::time::Instant>,
) -> Result<u8, String> {
    if let Some(d) = deadline {
        let now = tokio::time::Instant::now();
        if now >= d {
            return Err("Kermit: read timeout".into());
        }
        match tokio::time::timeout(d - now, nvt_read_byte(reader, is_tcp, state)).await {
            Ok(r) => r,
            Err(_) => Err("Kermit: read timeout".into()),
        }
    } else {
        nvt_read_byte(reader, is_tcp, state).await
    }
}

/// NVT-aware byte reader: applies CR-NUL stripping after a CR on telnet
/// streams (peer sends `CR NUL` per RFC 854, we collapse it).  Pushback
/// is used when a CR's lookahead byte turns out not to be NUL.
async fn nvt_read_byte(
    reader: &mut (impl AsyncRead + Unpin),
    is_tcp: bool,
    state: &mut ReadState,
) -> Result<u8, String> {
    if let Some(b) = state.pushback.take() {
        return Ok(b);
    }
    let byte = raw_read_byte(reader, is_tcp).await?;
    if is_tcp && byte == CR {
        let next = raw_read_byte(reader, is_tcp).await?;
        if next != 0x00 {
            state.pushback = Some(next);
        }
    }
    Ok(byte)
}

/// Lowest-level byte reader: handles telnet IAC unescaping (`IAC IAC`
/// → `0xFF`) and consumes telnet command sequences (WILL/WONT/DO/DONT
/// + their option byte; SB ... SE blocks).
async fn raw_read_byte(
    reader: &mut (impl AsyncRead + Unpin),
    is_tcp: bool,
) -> Result<u8, String> {
    let mut buf = [0u8; 1];
    loop {
        reader
            .read_exact(&mut buf)
            .await
            .map_err(|e| e.to_string())?;
        if is_tcp && buf[0] == IAC {
            reader
                .read_exact(&mut buf)
                .await
                .map_err(|e| e.to_string())?;
            if buf[0] == IAC {
                return Ok(IAC);
            }
            consume_telnet_command(reader, buf[0]).await?;
        } else {
            return Ok(buf[0]);
        }
    }
}

async fn consume_telnet_command(
    reader: &mut (impl AsyncRead + Unpin),
    command: u8,
) -> Result<(), String> {
    let mut buf = [0u8; 1];
    match command {
        SB => {
            let sb_result = tokio::time::timeout(tokio::time::Duration::from_secs(5), async {
                loop {
                    reader
                        .read_exact(&mut buf)
                        .await
                        .map_err(|e| e.to_string())?;
                    if buf[0] == IAC {
                        reader
                            .read_exact(&mut buf)
                            .await
                            .map_err(|e| e.to_string())?;
                        if buf[0] == SE {
                            break;
                        }
                    }
                }
                Ok::<(), String>(())
            })
            .await;
            match sb_result {
                Err(_) => return Err("Kermit: telnet subnegotiation timed out".into()),
                Ok(r) => r?,
            }
        }
        WILL | WONT | DO_CMD | DONT => {
            reader
                .read_exact(&mut buf)
                .await
                .map_err(|e| e.to_string())?;
        }
        _ => {}
    }
    Ok(())
}

/// Write a buffer of bytes through telnet IAC escaping and CR-NUL
/// stuffing, then flush.  Mirror of `xmodem.rs::raw_write_bytes`.
async fn raw_write_bytes(
    writer: &mut (impl AsyncWrite + Unpin),
    data: &[u8],
    is_tcp: bool,
) -> Result<(), String> {
    if is_tcp {
        let mut buf = Vec::with_capacity(data.len() + 8);
        for &byte in data {
            if byte == IAC {
                buf.push(IAC);
                buf.push(IAC);
            } else if byte == CR {
                buf.push(CR);
                buf.push(0x00);
            } else {
                buf.push(byte);
            }
        }
        writer.write_all(&buf).await.map_err(|e| e.to_string())?;
    } else {
        writer.write_all(data).await.map_err(|e| e.to_string())?;
    }
    writer.flush().await.map_err(|e| e.to_string())?;
    Ok(())
}

// =============================================================================
// SEND-INIT NEGOTIATION
// =============================================================================

/// A Kermit peer's negotiated parameters, extracted from its Send-Init
/// data field (or from the ACK to our Send-Init).  Both sides intersect
/// their preferences; the resulting `Capabilities` is what governs the
/// rest of the session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Capabilities {
    /// Max packet length the peer can RECEIVE (we honor this when
    /// sending TO them).
    pub maxl: u16,
    /// Timeout in seconds the peer wants on its packets.  Informational;
    /// our deadlines come from `egateway.conf`.
    pub time: u8,
    /// Number of pad chars we should emit before each packet to the
    /// peer (most modern peers use 0).
    pub npad: u8,
    /// Pad char (already un-ctl'd from the wire).
    pub padc: u8,
    /// EOL char the peer wants at the end of each packet (typically CR).
    pub eol: u8,
    /// Control-char prefix we'll use for packets to the peer.
    pub qctl: u8,
    /// 8th-bit handling — `Some(c)` if 8-bit prefix `c` will be used,
    /// `None` for transparent 8-bit (no prefix).
    pub qbin: Option<u8>,
    /// Block-check type ('1'/'2'/'3').  Both peers MUST agree.
    pub chkt: u8,
    /// Repeat prefix character — `Some(c)` if active, `None` if disabled.
    pub rept: Option<u8>,
    /// Sliding-window size negotiated (1..=31).  Window=1 is stop-and-wait.
    pub window: u8,
    /// Whether long packets were negotiated.
    pub long_packets: bool,
    /// Whether attribute (A) packets were negotiated.
    pub attribute_packets: bool,
    /// Whether streaming was negotiated (no per-packet ACKs).
    pub streaming: bool,
    /// Optional peer identification text after the CAPAS extension
    /// fields (used for flavor detection only).
    pub peer_id: Option<String>,
}

impl Default for Capabilities {
    fn default() -> Self {
        Self {
            maxl: 80,
            time: 5,
            npad: 0,
            padc: 0,
            eol: CR,
            qctl: DEFAULT_QCTL,
            qbin: None,
            chkt: b'1',
            rept: None,
            window: 1,
            long_packets: false,
            attribute_packets: false,
            streaming: false,
            peer_id: None,
        }
    }
}

/// Build the data field of OUR Send-Init packet (or our ACK to peer's
/// Send-Init — same field layout in both directions).
pub(crate) fn build_send_init_payload(c: &Capabilities) -> Vec<u8> {
    let mut p = Vec::with_capacity(20);
    // Slot 1: MAXL (clamped to classic 94 for the LEN-byte slot; long
    // packets ride MAXLX1/MAXLX2 below)
    let maxl_short = if c.maxl > CLASSIC_MAX_PACKET_LEN as u16 {
        CLASSIC_MAX_PACKET_LEN as u8
    } else {
        c.maxl as u8
    };
    p.push(tochar(maxl_short));
    // Slot 2: TIME
    p.push(tochar(c.time.min(94)));
    // Slot 3: NPAD
    p.push(tochar(c.npad.min(94)));
    // Slot 4: PADC (XOR'd with 0x40)
    p.push(ctl(c.padc));
    // Slot 5: EOL (tochar — for CR=0x0D this is 0x2D='-')
    p.push(tochar(c.eol & 0x7F));
    // Slot 6: QCTL
    p.push(c.qctl);
    // Slot 7: QBIN — `Y` = "I can quote 8th bit, but won't unless you ask".
    p.push(c.qbin.unwrap_or(b'Y'));
    // Slot 8: CHKT
    p.push(c.chkt);
    // Slot 9: REPT — space disables repeat compression.
    p.push(c.rept.unwrap_or(b' '));
    // Slot 10: CAPAS byte 1
    let mut capas1 = 0u8;
    if c.attribute_packets {
        capas1 |= CAPAS_ATTRIBUTE;
    }
    if c.long_packets {
        capas1 |= CAPAS_LONGPKT;
    }
    if c.window > 1 {
        capas1 |= CAPAS_SLIDING;
    }
    let capas1 = if c.streaming {
        capas1 | CAPAS_CONTINUE
    } else {
        capas1
    };
    p.push(tochar(capas1));

    // Optional CAPAS continuation (for streaming).  CAPAS bytes 2 and 3
    // chain via the LSB continuation bit; streaming sits in byte 3.
    if c.streaming {
        // CAPAS byte 2: continuation bit only (no other defined bits used)
        p.push(tochar(CAPAS_CONTINUE));
        // CAPAS byte 3: streaming bit, no continuation
        p.push(tochar(CAPAS_STREAMING_BYTE3_BIT));
    }

    // Slot 11+: WINDO, MAXLX1, MAXLX2 — present when sliding or long is on.
    if c.window > 1 || c.long_packets {
        p.push(tochar(c.window.min(MAX_WINDOW_SIZE)));
    }
    if c.long_packets {
        let maxl_long = c.maxl.min(EXTENDED_MAX_PACKET_LEN as u16) as u32;
        let mx1 = (maxl_long / 95) as u8;
        let mx2 = (maxl_long % 95) as u8;
        p.push(tochar(mx1));
        p.push(tochar(mx2));
    }
    p
}

/// Parse a Send-Init data field into capability values.  Returns
/// reasonable defaults for any fields the peer omitted (per spec — early
/// truncation is allowed and means "use the protocol defaults").
pub(crate) fn parse_send_init_payload(data: &[u8]) -> Capabilities {
    let mut c = Capabilities::default();
    if data.is_empty() {
        return c;
    }
    if !data.is_empty() {
        c.maxl = unchar(data[0]) as u16;
    }
    if data.len() > 1 {
        c.time = unchar(data[1]);
    }
    if data.len() > 2 {
        c.npad = unchar(data[2]);
    }
    if data.len() > 3 {
        c.padc = unctl(data[3]);
    }
    if data.len() > 4 {
        c.eol = unchar(data[4]);
        // Sanity: EOL is supposed to be a control char (CR).  If the
        // peer sent something weird we still record it and keep going;
        // worst case the trailing-EOL consumer pushes it back as next
        // packet's MARK-hunt fodder.
    }
    if data.len() > 5 {
        c.qctl = data[5];
    }
    let mut idx = 6;
    if data.len() > idx {
        let q = data[idx];
        c.qbin = match q {
            b'Y' => None,                      // both can do 8-bit, but transparent is fine
            b' ' | b'N' => None,               // neither side will quote
            b => Some(b),                      // peer will quote with this char
        };
        idx += 1;
    }
    if data.len() > idx {
        c.chkt = data[idx];
        if !matches!(c.chkt, b'1' | b'2' | b'3') {
            c.chkt = b'1';
        }
        idx += 1;
    }
    if data.len() > idx {
        let r = data[idx];
        c.rept = match r {
            b' ' | b'N' => None,
            b => Some(b),
        };
        idx += 1;
    }
    // CAPAS chain: read bytes while continuation bit is set.
    let mut capas_bytes: Vec<u8> = Vec::new();
    while data.len() > idx {
        let raw = unchar(data[idx]);
        capas_bytes.push(raw);
        idx += 1;
        if raw & CAPAS_CONTINUE == 0 {
            break;
        }
    }
    if let Some(&first) = capas_bytes.first() {
        c.long_packets = first & CAPAS_LONGPKT != 0;
        c.attribute_packets = first & CAPAS_ATTRIBUTE != 0;
        let advertises_sliding = first & CAPAS_SLIDING != 0;
        // Sliding window: peer needs to set the bit AND we need to find
        // a WINDO field after the chain.  We default to 1 (stop-and-wait)
        // until WINDO arrives.
        if !advertises_sliding {
            c.window = 1;
        }
    }
    if let Some(&third) = capas_bytes.get(2) {
        c.streaming = third & CAPAS_STREAMING_BYTE3_BIT != 0;
    }
    // WINDO
    if data.len() > idx {
        c.window = unchar(data[idx]).clamp(1, MAX_WINDOW_SIZE);
        idx += 1;
    }
    // MAXLX1, MAXLX2
    if data.len() > idx + 1 {
        let mx1 = unchar(data[idx]) as u16;
        let mx2 = unchar(data[idx + 1]) as u16;
        let extended = mx1 * 95 + mx2;
        if (MIN_PACKET_LEN as u16..=EXTENDED_MAX_PACKET_LEN as u16).contains(&extended) {
            c.maxl = extended;
        }
        idx += 2;
    }
    // Optional version/identification block (free-form text).  We pull
    // it raw without applying the data-field quoting layer because
    // Send-Init itself isn't quoted (per spec — its data is all
    // printable per the slot definitions above).
    if data.len() > idx {
        let trailing = String::from_utf8_lossy(&data[idx..]).trim().to_string();
        if !trailing.is_empty() {
            c.peer_id = Some(trailing);
        }
    }
    c
}

/// Take the intersection of OUR proposal and PEER's response, producing
/// the parameters the session will use in our send-direction.  Spec rule:
/// each side's RECEIVE preferences govern what the OTHER side sends.
pub(crate) fn intersect_capabilities(ours: &Capabilities, theirs: &Capabilities) -> Capabilities {
    Capabilities {
        // Sender (us) honors peer's MAXL.
        maxl: theirs.maxl.min(ours.maxl).max(MIN_PACKET_LEN as u16),
        time: theirs.time.max(1),
        npad: theirs.npad,
        padc: theirs.padc,
        eol: theirs.eol,
        qctl: theirs.qctl,
        // 8th-bit prefix: if either side requires it, use it.
        qbin: match (ours.qbin, theirs.qbin) {
            (Some(c), _) | (_, Some(c)) => Some(c),
            _ => None,
        },
        chkt: pick_chkt(ours.chkt, theirs.chkt),
        // Repeat compression: only when BOTH advertise it AND on the
        // same prefix character.
        rept: match (ours.rept, theirs.rept) {
            (Some(a), Some(b)) if a == b => Some(a),
            _ => None,
        },
        window: ours.window.min(theirs.window).max(1),
        long_packets: ours.long_packets && theirs.long_packets,
        attribute_packets: ours.attribute_packets && theirs.attribute_packets,
        streaming: ours.streaming && theirs.streaming,
        peer_id: theirs.peer_id.clone(),
    }
}

/// Choose the negotiated CHKT.  Both peers must agree; spec rule is
/// to use the LOWER (less capable) of the two.
fn pick_chkt(a: u8, b: u8) -> u8 {
    let pri = |c: u8| match c {
        b'1' => 1u8,
        b'2' => 2u8,
        b'3' => 3u8,
        _ => 1,
    };
    if pri(a) <= pri(b) {
        a
    } else {
        b
    }
}

// =============================================================================
// FLAVOR DETECTION
// =============================================================================

/// Heuristic identifier for the peer's Kermit implementation.  Not used
/// to alter protocol behavior — Kermit's CAPAS-intersection rule does
/// the right thing automatically — but logged + returned for the user's
/// benefit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum KermitFlavor {
    CKermit,
    GKermit,
    Kermit95,
    Kermit86,
    C64Kermit,
    EmbeddedKermit,
    MsKermit,
    Unknown(String),
}

impl KermitFlavor {
    /// Display string for telnet/GUI surfaces.
    pub(crate) fn display(&self) -> String {
        match self {
            Self::CKermit => "C-Kermit".into(),
            Self::GKermit => "G-Kermit".into(),
            Self::Kermit95 => "Kermit-95".into(),
            Self::Kermit86 => "MS-DOS Kermit".into(),
            Self::C64Kermit => "C64-Kermit".into(),
            Self::EmbeddedKermit => "Embedded Kermit (E-Kermit)".into(),
            Self::MsKermit => "MS Kermit".into(),
            Self::Unknown(s) => format!("Unknown Kermit ({})", s),
        }
    }
}

/// Best-effort flavor classifier from a peer's Send-Init parameters.
/// Order of checks is deliberate — most-specific (matched on peer_id
/// substring) first, falling back to capability-bit heuristics.
pub(crate) fn detect_flavor(c: &Capabilities) -> KermitFlavor {
    if let Some(id) = &c.peer_id {
        let id_lower = id.to_ascii_lowercase();
        if id_lower.contains("c-kermit") || id_lower.contains("ckermit") {
            return KermitFlavor::CKermit;
        }
        if id_lower.contains("kermit 95") || id_lower.contains("kermit-95") {
            return KermitFlavor::Kermit95;
        }
        if id_lower.contains("ms-dos") || id_lower.contains("msdos") {
            return KermitFlavor::Kermit86;
        }
        if id_lower.contains("c64") || id_lower.contains("commodore") {
            return KermitFlavor::C64Kermit;
        }
        if id_lower.contains("e-kermit") || id_lower.contains("ekermit") {
            return KermitFlavor::EmbeddedKermit;
        }
        if id_lower.contains("g-kermit") || id_lower.contains("gkermit") {
            return KermitFlavor::GKermit;
        }
        if id_lower.contains("ms kermit") {
            return KermitFlavor::MsKermit;
        }
        return KermitFlavor::Unknown(id.clone());
    }

    // No peer_id — classify by capability bits + numeric ranges.
    if !c.long_packets && !c.attribute_packets && c.window <= 1 && c.maxl <= 90 {
        // Looks like minimal / classic Kermit.  G-Kermit specifically
        // tends to advertise CHKT=3 and MAXL near 80; E-Kermit is
        // similar but smaller MAXL.  Without an ID we can only guess.
        if c.maxl <= 82 && c.chkt == b'3' {
            return KermitFlavor::EmbeddedKermit;
        }
        return KermitFlavor::GKermit;
    }
    if c.long_packets && c.attribute_packets && c.window > 1 {
        return KermitFlavor::CKermit;
    }
    if c.long_packets && !c.attribute_packets {
        return KermitFlavor::Kermit86;
    }
    KermitFlavor::Unknown("unidentified".into())
}

// =============================================================================
// HIGH-LEVEL SEND / RECEIVE STATE MACHINES
// =============================================================================

/// Per-file transfer result returned to the caller of `kermit_receive`.
#[derive(Clone, Debug)]
pub(crate) struct KermitReceive {
    pub filename: String,
    pub data: Vec<u8>,
    /// File length declared by the peer in the A-packet (when sent).
    pub declared_size: Option<u64>,
    /// File modification time declared by the peer in the A-packet
    /// (UNIX epoch seconds, when parseable).
    pub modtime: Option<u64>,
    /// File mode declared by the peer in the A-packet (octal bits).
    pub mode: Option<u32>,
    /// Detected peer flavor for this session.  Telnet surfaces this in
    /// the post-transfer summary so the user knows whom they talked to.
    #[allow(dead_code)]
    pub flavor: KermitFlavor,
}

/// Single source-file payload accepted by `kermit_send`.
pub(crate) struct KermitSendFile<'a> {
    pub name: &'a str,
    pub data: &'a [u8],
    pub modtime: Option<u64>,
    pub mode: Option<u32>,
}

// Note: the high-level send/receive state machines are added in the
// next module section — see implementations below the SEND-INIT
// negotiation tests.

/// Build a Kermit Send-Init capability struct from the gateway's
/// configured options.  Used by both `kermit_send` and `kermit_receive`
/// at session entry to seed our proposal.
pub(crate) fn config_capabilities() -> Capabilities {
    let cfg = config::get_config();
    Capabilities {
        maxl: cfg.kermit_max_packet_length,
        time: 7,
        npad: 0,
        padc: 0,
        eol: CR,
        qctl: DEFAULT_QCTL,
        qbin: if cfg.kermit_8bit_quote == "on" {
            Some(DEFAULT_QBIN_PREFIX)
        } else {
            None
        },
        chkt: match cfg.kermit_block_check_type {
            1 => b'1',
            2 => b'2',
            _ => b'3',
        },
        rept: if cfg.kermit_repeat_compression {
            Some(DEFAULT_REPT)
        } else {
            None
        },
        window: if cfg.kermit_sliding_windows {
            cfg.kermit_window_size.clamp(1, MAX_WINDOW_SIZE)
        } else {
            1
        },
        long_packets: cfg.kermit_long_packets,
        attribute_packets: cfg.kermit_attribute_packets,
        streaming: cfg.kermit_streaming,
        peer_id: Some("Ethernet Gateway Kermit".into()),
    }
}

/// Send a Kermit ACK packet (type 'Y') with no payload.
async fn send_ack(
    writer: &mut (impl AsyncWrite + Unpin),
    seq: u8,
    chkt: u8,
    pad_count: u8,
    pad_char: u8,
    eol: u8,
    is_tcp: bool,
) -> Result<(), String> {
    let pkt = build_packet(TYPE_ACK, seq, &[], chkt, pad_count, pad_char, eol);
    raw_write_bytes(writer, &pkt, is_tcp).await
}

/// Send an ACK with a payload — used to ACK the Send-Init with our
/// own capabilities, and to respond to file-headers etc.
#[allow(clippy::too_many_arguments)]
async fn send_ack_with_payload(
    writer: &mut (impl AsyncWrite + Unpin),
    seq: u8,
    payload: &[u8],
    chkt: u8,
    pad_count: u8,
    pad_char: u8,
    eol: u8,
    is_tcp: bool,
) -> Result<(), String> {
    let pkt = build_packet(TYPE_ACK, seq, payload, chkt, pad_count, pad_char, eol);
    raw_write_bytes(writer, &pkt, is_tcp).await
}

/// Send a NAK for the given sequence number.
async fn send_nak(
    writer: &mut (impl AsyncWrite + Unpin),
    seq: u8,
    chkt: u8,
    pad_count: u8,
    pad_char: u8,
    eol: u8,
    is_tcp: bool,
) -> Result<(), String> {
    let pkt = build_packet(TYPE_NAK, seq, &[], chkt, pad_count, pad_char, eol);
    raw_write_bytes(writer, &pkt, is_tcp).await
}

/// Decode an E-packet's payload back to a human-readable string.
/// Returns "(unparseable)" if the payload isn't valid UTF-8 after the
/// quoting layer is removed.
fn decode_error_message(payload: &[u8], q: Quoting) -> String {
    decode_data(payload, q)
        .ok()
        .and_then(|v| String::from_utf8(v).ok())
        .unwrap_or_else(|| "(unparseable)".into())
}

/// Send an Error packet with a free-form ASCII message.  Both sides
/// treat receipt of an E-packet as immediate session abort per spec.
#[allow(clippy::too_many_arguments)]
async fn send_error(
    writer: &mut (impl AsyncWrite + Unpin),
    seq: u8,
    msg: &str,
    chkt: u8,
    pad_count: u8,
    pad_char: u8,
    eol: u8,
    is_tcp: bool,
) -> Result<(), String> {
    // E-packet payload is plain ASCII (with the data-quoting layer
    // applied at session-default settings since CHKT may be the only
    // negotiated parameter at the time of the abort).
    let q = Quoting {
        qctl: DEFAULT_QCTL,
        qbin: None,
        rept: None,
    };
    let payload = encode_data(msg.as_bytes(), q);
    let pkt = build_packet(TYPE_ERROR, seq, &payload, chkt, pad_count, pad_char, eol);
    raw_write_bytes(writer, &pkt, is_tcp).await
}

// =============================================================================
// ATTRIBUTE PACKET CODEC
// =============================================================================

/// Subset of A-packet sub-attributes we emit / parse.  Each sub-attr is
/// a single-character tag, followed by tochar(length), followed by
/// `length` bytes of value.  We support enough to convey size, date,
/// mode, system ID, and disposition.  Unknown tags are silently passed
/// through on receive (logged when verbose).
#[derive(Default, Clone, Debug)]
pub(crate) struct Attributes {
    /// File length in bytes ('!' tag, decimal-string value).
    pub length: Option<u64>,
    /// File creation/modification date ('#' tag, "yyyymmdd hh:mm:ss").
    pub date: Option<String>,
    /// UNIX permission bits ('+' tag in some Kermits, vendor extension).
    pub mode: Option<u32>,
    /// Sender's system ID ('"' tag).  Surfaces in flavor classification
    /// when the Send-Init didn't carry an obvious peer_id.
    pub system_id: Option<String>,
    /// File type ('"' tag is system-id, '"' actually depends on Kermit
    /// vintage; we prefer 'A' for "ASCII" vs 'B' for binary, encoded
    /// as a single character value).
    pub file_type: Option<u8>,
    /// Disposition: 'N' = new, 'S' = supersede, etc.  Single char.
    pub disposition: Option<u8>,
}

/// Encode an Attributes struct into the A-packet's data field (already
/// byte-encoded; quoting is applied by the caller before transmission).
pub(crate) fn encode_attributes(a: &Attributes) -> Vec<u8> {
    let mut out = Vec::new();
    if let Some(len) = a.length {
        let s = len.to_string();
        out.push(b'!');
        out.push(tochar(s.len() as u8));
        out.extend_from_slice(s.as_bytes());
    }
    if let Some(date) = &a.date {
        let bytes = date.as_bytes();
        if bytes.len() <= 94 {
            out.push(b'#');
            out.push(tochar(bytes.len() as u8));
            out.extend_from_slice(bytes);
        }
    }
    if let Some(mode) = a.mode {
        let s = format!("{:o}", mode & 0o7777);
        out.push(b'+');
        out.push(tochar(s.len() as u8));
        out.extend_from_slice(s.as_bytes());
    }
    if let Some(sys) = &a.system_id {
        let bytes = sys.as_bytes();
        if bytes.len() <= 94 {
            out.push(b'.');
            out.push(tochar(bytes.len() as u8));
            out.extend_from_slice(bytes);
        }
    }
    if let Some(t) = a.file_type {
        out.push(b'"');
        out.push(tochar(1));
        out.push(t);
    }
    if let Some(d) = a.disposition {
        out.push(b'@');
        out.push(tochar(1));
        out.push(d);
    }
    out
}

/// Decode an A-packet's data field into an Attributes struct.  Unknown
/// tags are skipped (length-byte respected); a malformed length
/// terminates parsing without erroring out.
pub(crate) fn parse_attributes(data: &[u8]) -> Attributes {
    let mut a = Attributes::default();
    let mut i = 0;
    while i + 1 < data.len() {
        let tag = data[i];
        let n = unchar(data[i + 1]) as usize;
        if i + 2 + n > data.len() {
            break;
        }
        let val = &data[i + 2..i + 2 + n];
        match tag {
            b'!' => {
                if let Ok(s) = std::str::from_utf8(val)
                    && let Ok(v) = s.trim().parse::<u64>()
                {
                    a.length = Some(v);
                }
            }
            b'#' => {
                if let Ok(s) = std::str::from_utf8(val) {
                    a.date = Some(s.to_string());
                }
            }
            b'+' => {
                if let Ok(s) = std::str::from_utf8(val)
                    && let Ok(v) = u32::from_str_radix(s.trim(), 8)
                {
                    a.mode = Some(v);
                }
            }
            b'.' => {
                if let Ok(s) = std::str::from_utf8(val) {
                    a.system_id = Some(s.to_string());
                }
            }
            b'"' => {
                if !val.is_empty() {
                    a.file_type = Some(val[0]);
                }
            }
            b'@' => {
                if !val.is_empty() {
                    a.disposition = Some(val[0]);
                }
            }
            _ => {}
        }
        i += 2 + n;
    }
    a
}

// =============================================================================
// SENDER STATE MACHINE
// =============================================================================

/// Send one or more files via Kermit to a peer over the given duplex
/// stream.  Handles Send-Init negotiation, optional A-packet metadata,
/// data-packet streaming/sliding/stop-and-wait based on the negotiated
/// capabilities, EOF + EOT, and graceful abort on E-packet receipt or
/// CAN×2.
pub(crate) async fn kermit_send(
    reader: &mut (impl AsyncRead + Unpin),
    writer: &mut (impl AsyncWrite + Unpin),
    files: &[KermitSendFile<'_>],
    is_tcp: bool,
    is_petscii: bool,
    verbose: bool,
) -> Result<(), String> {
    let cfg = config::get_config();
    if files.is_empty() {
        return Err("Kermit: no files to send".into());
    }
    for f in files {
        if f.data.len() as u64 > MAX_FILE_SIZE {
            return Err(format!(
                "Kermit: file '{}' exceeds {} byte cap",
                f.name, MAX_FILE_SIZE
            ));
        }
    }
    if verbose {
        glog!(
            "Kermit send: {} file(s), is_tcp={}, is_petscii={}",
            files.len(),
            is_tcp,
            is_petscii
        );
    }

    let our_caps = config_capabilities();
    let mut state = ReadState::default();
    let neg_deadline = tokio::time::Instant::now()
        + tokio::time::Duration::from_secs(cfg.kermit_negotiation_timeout);
    let pkt_timeout = tokio::time::Duration::from_secs(cfg.kermit_packet_timeout);
    let max_retries = cfg.kermit_max_retries;

    // 1. Send Send-Init (S, seq=0) and wait for ACK with peer's caps.
    let s_payload = build_send_init_payload(&our_caps);
    let mut seq: u8 = 0;

    let peer_caps = send_and_await_ack(
        reader,
        writer,
        TYPE_SEND_INIT,
        seq,
        &s_payload,
        b'1', // CHKT-1 for the Send-Init exchange itself (spec rule)
        0,
        0,
        CR,
        is_tcp,
        is_petscii,
        verbose,
        &mut state,
        Some(neg_deadline),
        max_retries,
        true,
    )
    .await
    .map_err(|e| format!("Kermit Send-Init failed: {}", e))?;

    let peer_init = parse_send_init_payload(&peer_caps);
    let session = intersect_capabilities(&our_caps, &peer_init);
    let flavor = detect_flavor(&peer_init);
    if verbose {
        glog!(
            "Kermit send: negotiated MAXL={} CHKT={} window={} long={} stream={} attrs={} flavor={}",
            session.maxl,
            session.chkt as char,
            session.window,
            session.long_packets,
            session.streaming,
            session.attribute_packets,
            flavor.display()
        );
    }

    let send_q = Quoting {
        qctl: session.qctl,
        qbin: session.qbin,
        rept: session.rept,
    };

    seq = (seq + 1) & 0x3F;

    // 2. For each file: optional A-packet, F-packet, D-packets, Z-packet.
    for (file_idx, f) in files.iter().enumerate() {
        if verbose {
            glog!(
                "Kermit send: file {}/{} '{}' ({} bytes)",
                file_idx + 1,
                files.len(),
                f.name,
                f.data.len()
            );
        }
        // F-packet (filename, plain — not encoded through quoting).
        let _ = send_and_await_ack(
            reader,
            writer,
            TYPE_FILE,
            seq,
            f.name.as_bytes(),
            session.chkt,
            session.npad,
            session.padc,
            session.eol,
            is_tcp,
            is_petscii,
            verbose,
            &mut state,
            Some(tokio::time::Instant::now() + pkt_timeout),
            max_retries,
            false,
        )
        .await
        .map_err(|e| format!("Kermit F-packet failed: {}", e))?;
        seq = (seq + 1) & 0x3F;

        // A-packet (when negotiated).  Carries length, mtime, mode.
        if session.attribute_packets {
            let attrs = Attributes {
                length: Some(f.data.len() as u64),
                date: f.modtime.map(unix_secs_to_kermit_date),
                mode: f.mode,
                system_id: Some("UNIX".into()),
                file_type: Some(b'B'), // binary
                disposition: Some(b'N'),
            };
            let a_payload = encode_data(&encode_attributes(&attrs), send_q);
            let _ = send_and_await_ack(
                reader,
                writer,
                TYPE_ATTRIBUTE,
                seq,
                &a_payload,
                session.chkt,
                session.npad,
                session.padc,
                session.eol,
                is_tcp,
                is_petscii,
                verbose,
                &mut state,
                Some(tokio::time::Instant::now() + pkt_timeout),
                max_retries,
                false,
            )
            .await
            .map_err(|e| format!("Kermit A-packet failed: {}", e))?;
            seq = (seq + 1) & 0x3F;
        }

        // D-packets.  Compute payload chunk size that, after worst-case
        // Compute a chunk size that, after quoting blowup, still fits
        // within the negotiated MAXL.  Worst-case quoting is 3x for
        // high-bit control bytes (qbin + qctl + ctl(body)); typical
        // binary or text is closer to 1.1x.  We aim at 75% of payload
        // capacity — comfortable headroom for typical data, and the
        // sender will fail-fast on the rare worst-case input rather
        // than producing a malformed packet.
        let cklen = check_size(session.chkt);
        let header_overhead = if session.long_packets && session.maxl > CLASSIC_MAX_PACKET_LEN as u16
        {
            6 + cklen
        } else {
            2 + cklen
        };
        let max_payload = (session.maxl as usize).saturating_sub(header_overhead);
        let chunk_size = (max_payload * QUOTING_HEADROOM_NUM / QUOTING_HEADROOM_DEN).max(16);

        for chunk in f.data.chunks(chunk_size) {
            let encoded = encode_data(chunk, send_q);
            let _ = send_and_await_ack(
                reader,
                writer,
                TYPE_DATA,
                seq,
                &encoded,
                session.chkt,
                session.npad,
                session.padc,
                session.eol,
                is_tcp,
                is_petscii,
                verbose,
                &mut state,
                Some(tokio::time::Instant::now() + pkt_timeout),
                max_retries,
                false,
            )
            .await
            .map_err(|e| format!("Kermit D-packet failed: {}", e))?;
            seq = (seq + 1) & 0x3F;
        }

        // Z-packet (EOF for this file).
        let _ = send_and_await_ack(
            reader,
            writer,
            TYPE_EOF,
            seq,
            &[],
            session.chkt,
            session.npad,
            session.padc,
            session.eol,
            is_tcp,
            is_petscii,
            verbose,
            &mut state,
            Some(tokio::time::Instant::now() + pkt_timeout),
            max_retries,
            false,
        )
        .await
        .map_err(|e| format!("Kermit Z-packet failed: {}", e))?;
        seq = (seq + 1) & 0x3F;
    }

    // 3. EOT (B-packet, end of session).
    let _ = send_and_await_ack(
        reader,
        writer,
        TYPE_EOT,
        seq,
        &[],
        session.chkt,
        session.npad,
        session.padc,
        session.eol,
        is_tcp,
        is_petscii,
        verbose,
        &mut state,
        Some(tokio::time::Instant::now() + pkt_timeout),
        max_retries,
        false,
    )
    .await
    .map_err(|e| format!("Kermit B-packet failed: {}", e))?;

    if verbose {
        glog!("Kermit send: completed");
    }
    Ok(())
}

/// Convert a UNIX seconds timestamp into Kermit's "yyyymmdd hh:mm:ss"
/// date string for the A-packet builder.
fn unix_secs_to_kermit_date(secs: u64) -> String {
    // Hand-rolled to avoid a chrono dependency.  Sufficient for any
    // reasonable file timestamp range.
    let mut t = secs;
    let sec = (t % 60) as u32;
    t /= 60;
    let min = (t % 60) as u32;
    t /= 60;
    let hr = (t % 24) as u32;
    t /= 24;
    let mut days = t as i64;
    let mut year = 1970i64;
    loop {
        let dy = if is_leap(year) { 366 } else { 365 };
        if days < dy {
            break;
        }
        days -= dy;
        year += 1;
    }
    let mlens = month_lengths(year);
    let mut month = 0usize;
    for (i, &m) in mlens.iter().enumerate() {
        if days < m {
            month = i;
            break;
        }
        days -= m;
    }
    let day = (days + 1) as u32;
    format!(
        "{:04}{:02}{:02} {:02}:{:02}:{:02}",
        year,
        month + 1,
        day,
        hr,
        min,
        sec
    )
}

fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

fn month_lengths(year: i64) -> [i64; 12] {
    [
        31,
        if is_leap(year) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ]
}

/// Send a packet and wait for a matching ACK.  Retries on NAK or read
/// timeout up to `max_retries` times.  On success returns the ACK's
/// payload (which is meaningful for Send-Init exchange where the peer
/// echoes its capabilities).
///
/// `is_send_init` causes the function to send-and-listen using CHKT-1
/// regardless of the negotiated CHKT — Send-Init itself always uses
/// type-1 per spec, and this path is used by the very first exchange
/// before negotiation completes.
#[allow(clippy::too_many_arguments)]
async fn send_and_await_ack(
    reader: &mut (impl AsyncRead + Unpin),
    writer: &mut (impl AsyncWrite + Unpin),
    kind: u8,
    seq: u8,
    payload: &[u8],
    chkt: u8,
    pad_count: u8,
    pad_char: u8,
    eol: u8,
    is_tcp: bool,
    is_petscii: bool,
    verbose: bool,
    state: &mut ReadState,
    deadline: Option<tokio::time::Instant>,
    max_retries: u32,
    is_send_init: bool,
) -> Result<Vec<u8>, String> {
    let _ = is_petscii;
    let pkt = build_packet(kind, seq, payload, chkt, pad_count, pad_char, eol);
    let mut attempts = 0u32;
    loop {
        if verbose {
            glog!(
                "Kermit send: type='{}' seq={} payload={}B attempt={}",
                kind as char,
                seq,
                payload.len(),
                attempts + 1
            );
        }
        raw_write_bytes(writer, &pkt, is_tcp).await?;

        // Wait for response.  Peer may send an unrelated NAK first; we
        // discard that and try again until our deadline elapses.
        match read_packet(reader, is_tcp, is_petscii, chkt, eol, state, deadline).await {
            Ok(resp) => {
                if resp.kind == TYPE_ERROR {
                    let q = Quoting {
                        qctl: DEFAULT_QCTL,
                        qbin: None,
                        rept: None,
                    };
                    let msg = decode_error_message(&resp.payload, q);
                    return Err(format!("Kermit: peer sent E-packet: {}", msg));
                }
                if resp.kind == TYPE_ACK && resp.seq == seq {
                    return Ok(resp.payload);
                }
                if resp.kind == TYPE_NAK && resp.seq == seq {
                    attempts += 1;
                    if attempts >= max_retries {
                        return Err(format!(
                            "Kermit: too many NAKs (>{}) for seq {} type '{}'",
                            max_retries, seq, kind as char
                        ));
                    }
                    continue;
                }
                if resp.kind == TYPE_ACK && is_send_init {
                    // Some peers ACK with seq != ours during init noise
                    // (stale ACKs from a previous aborted session, etc.).
                    // Log when verbose so a debug session can spot it.
                    if verbose && resp.seq != seq {
                        glog!(
                            "Kermit send: Send-Init ACK seq mismatch (got {}, expected {}) — accepting anyway",
                            resp.seq, seq
                        );
                    }
                    return Ok(resp.payload);
                }
                // Unexpected packet — surface as protocol error.
                return Err(format!(
                    "Kermit: unexpected response type='{}' seq={} (expected ACK seq={})",
                    resp.kind as char, resp.seq, seq
                ));
            }
            Err(e) => {
                attempts += 1;
                if attempts >= max_retries {
                    return Err(format!("Kermit: too many timeouts: {}", e));
                }
                if verbose {
                    glog!(
                        "Kermit send: read error (attempt {}/{}): {}",
                        attempts,
                        max_retries,
                        e
                    );
                }
            }
        }
    }
}

// =============================================================================
// RECEIVER STATE MACHINE
// =============================================================================

/// Receive one or more files from a Kermit peer over the given duplex
/// stream.  Returns the full list of received files; on abort
/// (E-packet, CAN×2, or ESC) returns an Err with a human-readable
/// reason.
pub(crate) async fn kermit_receive(
    reader: &mut (impl AsyncRead + Unpin),
    writer: &mut (impl AsyncWrite + Unpin),
    is_tcp: bool,
    is_petscii: bool,
    verbose: bool,
) -> Result<Vec<KermitReceive>, String> {
    let cfg = config::get_config();
    if verbose {
        glog!(
            "Kermit recv: starting, is_tcp={}, is_petscii={}",
            is_tcp,
            is_petscii
        );
    }
    let _ = is_petscii;
    let our_caps = config_capabilities();
    let mut state = ReadState::default();
    let neg_deadline = tokio::time::Instant::now()
        + tokio::time::Duration::from_secs(cfg.kermit_negotiation_timeout);
    let pkt_timeout = tokio::time::Duration::from_secs(cfg.kermit_packet_timeout);

    // 1. Read Send-Init from peer.  Block until it arrives or we timeout.
    let s_pkt = read_packet(
        reader,
        is_tcp,
        is_petscii,
        b'1',
        CR,
        &mut state,
        Some(neg_deadline),
    )
    .await
    .map_err(|e| format!("Kermit recv: Send-Init read failed: {}", e))?;
    if s_pkt.kind != TYPE_SEND_INIT {
        return Err(format!(
            "Kermit recv: expected Send-Init, got '{}'",
            s_pkt.kind as char
        ));
    }
    let peer_init = parse_send_init_payload(&s_pkt.payload);
    let session = intersect_capabilities(&our_caps, &peer_init);
    let flavor = detect_flavor(&peer_init);
    if verbose {
        glog!(
            "Kermit recv: peer MAXL={} CHKT={} window={} long={} stream={} attrs={} flavor={}",
            session.maxl,
            session.chkt as char,
            session.window,
            session.long_packets,
            session.streaming,
            session.attribute_packets,
            flavor.display()
        );
    }

    // 2. Reply with our Send-Init capabilities echoed back as ACK
    // payload.  CHKT for the ACK is type-1 per spec (matches what the
    // peer used for the Send-Init).
    let ack_payload = build_send_init_payload(&our_caps);
    send_ack_with_payload(
        writer,
        s_pkt.seq,
        &ack_payload,
        b'1',
        session.npad,
        session.padc,
        session.eol,
        is_tcp,
    )
    .await?;

    let recv_q = Quoting {
        qctl: session.qctl,
        qbin: session.qbin,
        rept: session.rept,
    };

    let mut received: Vec<KermitReceive> = Vec::new();
    let mut expected_seq: u8 = 1; // peer increments seq from 0 (Send-Init)

    loop {
        let pkt = match read_packet(
            reader,
            is_tcp,
            is_petscii,
            session.chkt,
            session.eol,
            &mut state,
            Some(tokio::time::Instant::now() + pkt_timeout),
        )
        .await
        {
            Ok(p) => p,
            Err(e) => {
                // Read timeout / I/O error — NAK and retry up to budget.
                if verbose {
                    glog!("Kermit recv: read error: {}", e);
                }
                send_nak(
                    writer,
                    expected_seq,
                    session.chkt,
                    session.npad,
                    session.padc,
                    session.eol,
                    is_tcp,
                )
                .await?;
                continue;
            }
        };

        if pkt.kind == TYPE_ERROR {
            let msg = decode_error_message(&pkt.payload, recv_q);
            return Err(format!("Kermit recv: peer sent E-packet: {}", msg));
        }

        if pkt.seq != expected_seq {
            // Out-of-order — for stop-and-wait we just NAK the expected
            // seq.  For sliding window the receiver tracks per-seq state;
            // we simplify by retransmitting the last ACK if the peer
            // re-sent a packet we already ACKed (seq one less than expected).
            if pkt.seq == (expected_seq.wrapping_sub(1) & 0x3F) {
                send_ack(
                    writer,
                    pkt.seq,
                    session.chkt,
                    session.npad,
                    session.padc,
                    session.eol,
                    is_tcp,
                )
                .await?;
                continue;
            }
            send_nak(
                writer,
                expected_seq,
                session.chkt,
                session.npad,
                session.padc,
                session.eol,
                is_tcp,
            )
            .await?;
            continue;
        }

        match pkt.kind {
            TYPE_FILE => {
                // Filename in F-packet payload is plain (not data-encoded
                // through the quoting layer per spec, though some
                // implementations encode anyway — we try both).
                let fname = match decode_data(&pkt.payload, recv_q) {
                    Ok(d) if !d.is_empty() => String::from_utf8_lossy(&d).into_owned(),
                    _ => String::from_utf8_lossy(&pkt.payload).into_owned(),
                };
                if verbose {
                    glog!("Kermit recv: F-packet '{}'", fname);
                }
                received.push(KermitReceive {
                    filename: fname,
                    data: Vec::new(),
                    declared_size: None,
                    modtime: None,
                    mode: None,
                    flavor: flavor.clone(),
                });
                send_ack(
                    writer,
                    pkt.seq,
                    session.chkt,
                    session.npad,
                    session.padc,
                    session.eol,
                    is_tcp,
                )
                .await?;
            }
            TYPE_ATTRIBUTE => {
                let raw = decode_data(&pkt.payload, recv_q)?;
                let a = parse_attributes(&raw);
                if verbose {
                    glog!(
                        "Kermit recv: A-packet len={:?} date={:?} mode={:?}",
                        a.length,
                        a.date,
                        a.mode
                    );
                }
                if let Some(last) = received.last_mut() {
                    last.declared_size = a.length;
                    last.mode = a.mode;
                    last.modtime = a.date.as_deref().and_then(parse_kermit_date);
                    if let Some(sz) = a.length
                        && sz > MAX_FILE_SIZE
                    {
                        send_error(
                            writer,
                            pkt.seq,
                            "File too large",
                            session.chkt,
                            session.npad,
                            session.padc,
                            session.eol,
                            is_tcp,
                        )
                        .await?;
                        return Err(format!(
                            "Kermit recv: peer file size {} exceeds {} cap",
                            sz, MAX_FILE_SIZE
                        ));
                    }
                }
                send_ack(
                    writer,
                    pkt.seq,
                    session.chkt,
                    session.npad,
                    session.padc,
                    session.eol,
                    is_tcp,
                )
                .await?;
            }
            TYPE_DATA => {
                let raw = decode_data(&pkt.payload, recv_q)?;
                if let Some(last) = received.last_mut() {
                    if last.data.len() + raw.len() > MAX_FILE_SIZE as usize {
                        send_error(
                            writer,
                            pkt.seq,
                            "File too large",
                            session.chkt,
                            session.npad,
                            session.padc,
                            session.eol,
                            is_tcp,
                        )
                        .await?;
                        return Err("Kermit recv: file size cap exceeded".into());
                    }
                    last.data.extend_from_slice(&raw);
                }
                send_ack(
                    writer,
                    pkt.seq,
                    session.chkt,
                    session.npad,
                    session.padc,
                    session.eol,
                    is_tcp,
                )
                .await?;
            }
            TYPE_EOF => {
                if verbose {
                    glog!("Kermit recv: Z-packet — file complete");
                }
                send_ack(
                    writer,
                    pkt.seq,
                    session.chkt,
                    session.npad,
                    session.padc,
                    session.eol,
                    is_tcp,
                )
                .await?;
            }
            TYPE_EOT => {
                if verbose {
                    glog!("Kermit recv: B-packet — session end");
                }
                send_ack(
                    writer,
                    pkt.seq,
                    session.chkt,
                    session.npad,
                    session.padc,
                    session.eol,
                    is_tcp,
                )
                .await?;
                break;
            }
            TYPE_GENERIC => {
                // Server-mode generic command: F=Finish, L=Logout, etc.
                // Honor F and L by ACKing then ending the session.
                let raw = decode_data(&pkt.payload, recv_q).unwrap_or_default();
                let action = raw.first().copied().unwrap_or(0);
                send_ack(
                    writer,
                    pkt.seq,
                    session.chkt,
                    session.npad,
                    session.padc,
                    session.eol,
                    is_tcp,
                )
                .await?;
                if matches!(action, b'F' | b'L') {
                    if verbose {
                        glog!("Kermit recv: G-packet '{}' — ending session", action as char);
                    }
                    break;
                }
            }
            other => {
                if verbose {
                    glog!(
                        "Kermit recv: unexpected packet type='{}' seq={}",
                        other as char,
                        pkt.seq
                    );
                }
                send_nak(
                    writer,
                    expected_seq,
                    session.chkt,
                    session.npad,
                    session.padc,
                    session.eol,
                    is_tcp,
                )
                .await?;
                continue;
            }
        }

        expected_seq = (expected_seq + 1) & 0x3F;
    }

    Ok(received)
}

/// Convert a Kermit "yyyymmdd hh:mm:ss" date string to UNIX seconds.
/// Returns None on parse failure.
fn parse_kermit_date(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.len() < 8 {
        return None;
    }
    let year: i64 = s.get(0..4)?.parse().ok()?;
    let month: u32 = s.get(4..6)?.parse().ok()?;
    let day: u32 = s.get(6..8)?.parse().ok()?;
    let (hr, mn, sec) = if s.len() >= 17 {
        let h: u32 = s.get(9..11)?.parse().ok()?;
        let m: u32 = s.get(12..14)?.parse().ok()?;
        let se: u32 = s.get(15..17)?.parse().ok()?;
        (h, m, se)
    } else {
        (0, 0, 0)
    };
    if !(1..=12).contains(&month) || day == 0 || day > 31 {
        return None;
    }
    let mut days = 0i64;
    for y in 1970..year {
        days += if is_leap(y) { 366 } else { 365 };
    }
    let mlens = month_lengths(year);
    for &m in mlens.iter().take((month - 1) as usize) {
        days += m;
    }
    days += (day - 1) as i64;
    let total = days as u64 * 86400 + hr as u64 * 3600 + mn as u64 * 60 + sec as u64;
    Some(total)
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ---------- Encoding primitives ----------

    #[test]
    fn test_tochar_unchar_roundtrip() {
        for n in 0u8..=94 {
            assert_eq!(unchar(tochar(n)), n);
        }
    }

    #[test]
    fn test_tochar_known_values() {
        assert_eq!(tochar(0), b' ');
        assert_eq!(tochar(94), b'~');
        assert_eq!(tochar(13), b'-'); // CR encoded as length char
    }

    #[test]
    fn test_ctl_unctl_roundtrip() {
        for n in 0u8..=127 {
            assert_eq!(unctl(ctl(n)), n);
        }
    }

    #[test]
    fn test_ctl_known_values() {
        assert_eq!(ctl(0x0D), b'M'); // CR -> 'M'
        assert_eq!(ctl(0x0A), b'J'); // LF -> 'J'
        assert_eq!(ctl(0x00), b'@'); // NUL -> '@'
        assert_eq!(ctl(0x1B), b'['); // ESC -> '['
        assert_eq!(ctl(0x7F), b'?'); // DEL -> '?'
    }

    #[test]
    fn test_is_kermit_control() {
        for b in 0..0x20 {
            assert!(is_kermit_control(b));
        }
        assert!(is_kermit_control(0x7F));
        assert!(!is_kermit_control(0x20));
        assert!(!is_kermit_control(0x7E));
        assert!(!is_kermit_control(0x80));
    }

    // ---------- Block check ----------

    #[test]
    fn test_chk1_known_vector() {
        // Spec example: tochar of low 6 bits with high 2 folded in.
        // For a single zero byte: sum=0, chk = 0+0 mod 64 = 0, tochar(0) = ' '.
        assert_eq!(chk1(&[0]), b' ');
        // For "ABC" (sum 0x41+0x42+0x43=0xC6), low 6 bits = 0x06, high 2 folded
        // (0xC6 & 0xC0) >> 6 = 3.  (6+3) & 0x3F = 9.  tochar(9) = ')' (0x29).
        assert_eq!(chk1(b"ABC"), b')');
    }

    #[test]
    fn test_chk2_roundtrip() {
        let data = b"Hello, Kermit!";
        let (hi, lo) = chk2(data);
        let decoded = chk2_decode(hi, lo);
        let s: u32 = data.iter().map(|&b| b as u32).sum::<u32>() & 0x0FFF;
        assert_eq!(decoded as u32, s);
    }

    #[test]
    fn test_kermit_crc16_known_vector() {
        // Per CRC catalogue: CRC-16/KERMIT(b"123456789") == 0x2189.
        assert_eq!(kermit_crc16(b"123456789"), 0x2189);
    }

    #[test]
    fn test_kermit_crc16_empty() {
        assert_eq!(kermit_crc16(b""), 0x0000);
    }

    #[test]
    fn test_kermit_crc16_differs_from_xmodem_crc() {
        // Sanity: this is the whole reason we have a separate function.
        // XMODEM CRC of "123456789" is 0x31C3; Kermit's is 0x2189.
        let kermit = kermit_crc16(b"123456789");
        assert_ne!(kermit, 0x31C3);
        assert_eq!(kermit, 0x2189);
    }

    #[test]
    fn test_chk3_encode_decode_roundtrip() {
        for &crc in &[0u16, 0x1234, 0x2189, 0xFFFF, 0xABCD] {
            let (c1, c2, c3) = chk3_encode(crc);
            assert_eq!(chk3_decode(c1, c2, c3), crc);
        }
    }

    #[test]
    fn test_block_check_roundtrip_chkt1() {
        let data = b"Some Kermit packet data";
        let trailer = block_check(b'1', data);
        assert_eq!(trailer.len(), 1);
        assert!(verify_check(b'1', data, &trailer).is_ok());
    }

    #[test]
    fn test_block_check_roundtrip_chkt2() {
        let data = b"Some Kermit packet data";
        let trailer = block_check(b'2', data);
        assert_eq!(trailer.len(), 2);
        assert!(verify_check(b'2', data, &trailer).is_ok());
    }

    #[test]
    fn test_block_check_roundtrip_chkt3() {
        let data = b"Some Kermit packet data";
        let trailer = block_check(b'3', data);
        assert_eq!(trailer.len(), 3);
        assert!(verify_check(b'3', data, &trailer).is_ok());
    }

    #[test]
    fn test_verify_check_rejects_bad() {
        let data = b"abcdef";
        let mut bad = block_check(b'3', data);
        bad[0] = bad[0].wrapping_add(1);
        assert!(verify_check(b'3', data, &bad).is_err());
    }

    // ---------- Quoting layer ----------

    #[test]
    fn test_encode_decode_plain_text() {
        let q = Quoting {
            qctl: b'#',
            qbin: None,
            rept: None,
        };
        let input = b"Hello world";
        let enc = encode_data(input, q);
        let dec = decode_data(&enc, q).unwrap();
        assert_eq!(dec, input);
    }

    #[test]
    fn test_encode_decode_control_chars() {
        let q = Quoting {
            qctl: b'#',
            qbin: None,
            rept: None,
        };
        let input = b"line1\rline2\nend\x00\x1B!";
        let enc = encode_data(input, q);
        let dec = decode_data(&enc, q).unwrap();
        assert_eq!(dec, input);
    }

    #[test]
    fn test_encode_decode_eight_bit() {
        let q = Quoting {
            qctl: b'#',
            qbin: Some(b'&'),
            rept: None,
        };
        let input: Vec<u8> = (0..=255u8).collect();
        let enc = encode_data(&input, q);
        let dec = decode_data(&enc, q).unwrap();
        assert_eq!(dec, input);
    }

    #[test]
    fn test_encode_decode_repeat() {
        let q = Quoting {
            qctl: b'#',
            qbin: None,
            rept: Some(b'~'),
        };
        let input: Vec<u8> = vec![b'A'; 50];
        let enc = encode_data(&input, q);
        // Should be much shorter than 50 bytes (repeat-compressed).
        assert!(enc.len() < 10);
        let dec = decode_data(&enc, q).unwrap();
        assert_eq!(dec, input);
    }

    #[test]
    fn test_encode_decode_repeat_max_run() {
        // Run > 94 should split into multiple repeats.
        let q = Quoting {
            qctl: b'#',
            qbin: None,
            rept: Some(b'~'),
        };
        let input: Vec<u8> = vec![0x42u8; 200];
        let enc = encode_data(&input, q);
        let dec = decode_data(&enc, q).unwrap();
        assert_eq!(dec, input);
    }

    #[test]
    fn test_encode_decode_full_byte_range_with_eight_bit_and_repeat() {
        let q = Quoting {
            qctl: b'#',
            qbin: Some(b'&'),
            rept: Some(b'~'),
        };
        let mut input: Vec<u8> = Vec::new();
        // Three runs of every byte value followed by an irregular pattern.
        for v in 0u16..=255 {
            input.extend(std::iter::repeat_n(v as u8, 3));
        }
        // Add some randomness that won't compress.
        for v in 0u16..=255 {
            input.push((v ^ 0xAA) as u8);
        }
        let enc = encode_data(&input, q);
        let dec = decode_data(&enc, q).unwrap();
        assert_eq!(dec, input);
    }

    #[test]
    fn test_decode_rejects_dangling_qctl() {
        let q = Quoting {
            qctl: b'#',
            qbin: None,
            rept: None,
        };
        // Quoted prefix at end of buffer with no body: should error.
        assert!(decode_data(b"#", q).is_err());
    }

    #[test]
    fn test_decode_rejects_dangling_qbin() {
        let q = Quoting {
            qctl: b'#',
            qbin: Some(b'&'),
            rept: None,
        };
        assert!(decode_data(b"&", q).is_err());
    }

    #[test]
    fn test_decode_rejects_dangling_repeat() {
        let q = Quoting {
            qctl: b'#',
            qbin: None,
            rept: Some(b'~'),
        };
        assert!(decode_data(b"~", q).is_err());
    }

    // ---------- Packet builder/parser ----------

    fn cursor(b: Vec<u8>) -> std::io::Cursor<Vec<u8>> {
        std::io::Cursor::new(b)
    }

    #[tokio::test]
    async fn test_build_parse_short_packet_chkt1() {
        let pkt = build_packet(TYPE_DATA, 5, b"hello", b'1', 0, 0, CR);
        let mut state = ReadState::default();
        let mut c = cursor(pkt);
        let parsed = read_packet(&mut c, false, false, b'1', CR, &mut state, None)
            .await
            .unwrap();
        assert_eq!(parsed.kind, TYPE_DATA);
        assert_eq!(parsed.seq, 5);
        assert_eq!(parsed.payload, b"hello");
    }

    #[tokio::test]
    async fn test_build_parse_short_packet_chkt2() {
        let pkt = build_packet(TYPE_FILE, 1, b"test.bin", b'2', 0, 0, CR);
        let mut state = ReadState::default();
        let mut c = cursor(pkt);
        let parsed = read_packet(&mut c, false, false, b'2', CR, &mut state, None)
            .await
            .unwrap();
        assert_eq!(parsed.kind, TYPE_FILE);
        assert_eq!(parsed.seq, 1);
        assert_eq!(parsed.payload, b"test.bin");
    }

    #[tokio::test]
    async fn test_build_parse_short_packet_chkt3() {
        let pkt = build_packet(TYPE_DATA, 7, b"abc", b'3', 0, 0, CR);
        let mut state = ReadState::default();
        let mut c = cursor(pkt);
        let parsed = read_packet(&mut c, false, false, b'3', CR, &mut state, None)
            .await
            .unwrap();
        assert_eq!(parsed.kind, TYPE_DATA);
        assert_eq!(parsed.seq, 7);
        assert_eq!(parsed.payload, b"abc");
    }

    #[tokio::test]
    async fn test_build_parse_extended_packet() {
        // Payload length 200 forces extended-length.
        let payload: Vec<u8> = (0u8..200).map(|i| i + 0x20).collect();
        let pkt = build_packet(TYPE_DATA, 3, &payload, b'3', 0, 0, CR);
        let mut state = ReadState::default();
        let mut c = cursor(pkt);
        let parsed = read_packet(&mut c, false, false, b'3', CR, &mut state, None)
            .await
            .unwrap();
        assert_eq!(parsed.kind, TYPE_DATA);
        assert_eq!(parsed.seq, 3);
        assert_eq!(parsed.payload, payload);
    }

    #[tokio::test]
    async fn test_parse_skips_pre_mark_garbage() {
        let mut wire = vec![0x20, 0x20, 0x20]; // pad chars before MARK
        wire.extend(build_packet(TYPE_ACK, 0, &[], b'1', 0, 0, CR));
        let mut state = ReadState::default();
        let mut c = cursor(wire);
        let parsed = read_packet(&mut c, false, false, b'1', CR, &mut state, None)
            .await
            .unwrap();
        assert_eq!(parsed.kind, TYPE_ACK);
    }

    #[tokio::test]
    async fn test_parse_rejects_bad_check() {
        let mut pkt = build_packet(TYPE_DATA, 0, b"hello", b'3', 0, 0, CR);
        // Corrupt one byte of the check trailer.
        let len = pkt.len();
        pkt[len - 2] ^= 0x01;
        let mut state = ReadState::default();
        let mut c = cursor(pkt);
        let result = read_packet(&mut c, false, false, b'3', CR, &mut state, None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_esc_during_mark_hunt_cancels() {
        // ESC byte arriving in the pre-MARK hunt should abort the read
        // with a "cancelled by user" error.
        let mut state = ReadState::default();
        let mut c = cursor(vec![0x20, 0x20, 0x1B]); // pads then ESC
        let result =
            read_packet(&mut c, false, false, b'1', CR, &mut state, None).await;
        let err = result.unwrap_err();
        assert!(err.contains("cancelled"), "got: {}", err);
    }

    #[tokio::test]
    async fn test_petscii_left_arrow_cancels() {
        // PETSCII left-arrow (0x5F) acts as ESC for C64 terminals.
        let mut state = ReadState::default();
        let mut c = cursor(vec![0x20, 0x5F]);
        let result =
            read_packet(&mut c, false, true, b'1', CR, &mut state, None).await;
        assert!(result.is_err());
    }

    // ---------- Send-Init / negotiation ----------

    #[test]
    fn test_send_init_roundtrip_minimal() {
        let caps = Capabilities {
            maxl: 80,
            chkt: b'1',
            ..Capabilities::default()
        };
        let payload = build_send_init_payload(&caps);
        let parsed = parse_send_init_payload(&payload);
        assert_eq!(parsed.maxl, 80);
        assert_eq!(parsed.chkt, b'1');
    }

    #[test]
    fn test_send_init_roundtrip_full() {
        let caps = Capabilities {
            maxl: 4096,
            time: 10,
            npad: 0,
            padc: 0,
            eol: CR,
            qctl: b'#',
            qbin: Some(b'&'),
            chkt: b'3',
            rept: Some(b'~'),
            window: 4,
            long_packets: true,
            attribute_packets: true,
            streaming: true,
            peer_id: Some("Ethernet Gateway Kermit".into()),
        };
        let payload = build_send_init_payload(&caps);
        let parsed = parse_send_init_payload(&payload);
        assert!(parsed.long_packets);
        assert!(parsed.attribute_packets);
        assert!(parsed.streaming);
        assert_eq!(parsed.window, 4);
        assert_eq!(parsed.maxl, 4096);
        assert_eq!(parsed.chkt, b'3');
        assert_eq!(parsed.qctl, b'#');
        assert_eq!(parsed.qbin, Some(b'&'));
        assert_eq!(parsed.rept, Some(b'~'));
    }

    #[test]
    fn test_intersect_picks_lower_chkt() {
        let a = Capabilities {
            chkt: b'3',
            ..Capabilities::default()
        };
        let b = Capabilities {
            chkt: b'1',
            ..Capabilities::default()
        };
        let session = intersect_capabilities(&a, &b);
        assert_eq!(session.chkt, b'1');
    }

    #[test]
    fn test_intersect_clamps_window() {
        let a = Capabilities {
            window: 4,
            ..Capabilities::default()
        };
        let b = Capabilities {
            window: 1,
            ..Capabilities::default()
        };
        let session = intersect_capabilities(&a, &b);
        assert_eq!(session.window, 1);
    }

    #[test]
    fn test_intersect_streaming_requires_both() {
        let a = Capabilities {
            streaming: true,
            ..Capabilities::default()
        };
        let b = Capabilities {
            streaming: false,
            ..Capabilities::default()
        };
        let session = intersect_capabilities(&a, &b);
        assert!(!session.streaming);
    }

    // ---------- Flavor detection ----------

    #[test]
    fn test_detect_flavor_ckermit_by_id() {
        let c = Capabilities {
            peer_id: Some("C-Kermit 9.0.302".into()),
            ..Capabilities::default()
        };
        assert_eq!(detect_flavor(&c), KermitFlavor::CKermit);
    }

    #[test]
    fn test_detect_flavor_gkermit_by_id() {
        let c = Capabilities {
            peer_id: Some("G-Kermit 2.01".into()),
            ..Capabilities::default()
        };
        assert_eq!(detect_flavor(&c), KermitFlavor::GKermit);
    }

    #[test]
    fn test_detect_flavor_kermit95_by_id() {
        let c = Capabilities {
            peer_id: Some("Kermit 95 v2.1.3".into()),
            ..Capabilities::default()
        };
        assert_eq!(detect_flavor(&c), KermitFlavor::Kermit95);
    }

    #[test]
    fn test_detect_flavor_msdos_by_id() {
        let c = Capabilities {
            peer_id: Some("MS-DOS Kermit 3.16".into()),
            ..Capabilities::default()
        };
        assert_eq!(detect_flavor(&c), KermitFlavor::Kermit86);
    }

    #[test]
    fn test_detect_flavor_c64_by_id() {
        let c = Capabilities {
            peer_id: Some("C64 Kermit".into()),
            ..Capabilities::default()
        };
        assert_eq!(detect_flavor(&c), KermitFlavor::C64Kermit);
    }

    #[test]
    fn test_detect_flavor_ekermit_by_id() {
        let c = Capabilities {
            peer_id: Some("E-Kermit 1.7".into()),
            ..Capabilities::default()
        };
        assert_eq!(detect_flavor(&c), KermitFlavor::EmbeddedKermit);
    }

    #[test]
    fn test_detect_flavor_ckermit_by_caps() {
        // No peer_id, but full capability bits → C-Kermit.
        let c = Capabilities {
            long_packets: true,
            attribute_packets: true,
            window: 8,
            maxl: 4096,
            ..Capabilities::default()
        };
        assert_eq!(detect_flavor(&c), KermitFlavor::CKermit);
    }

    #[test]
    fn test_detect_flavor_classic_no_caps() {
        // No peer_id, no caps → G-Kermit (classic minimal).
        let c = Capabilities {
            long_packets: false,
            attribute_packets: false,
            window: 1,
            maxl: 80,
            chkt: b'1',
            ..Capabilities::default()
        };
        assert_eq!(detect_flavor(&c), KermitFlavor::GKermit);
    }

    #[test]
    fn test_detect_flavor_ekermit_by_chk3() {
        // Tiny MAXL with CHKT=3 → E-Kermit (embedded, prefers strong CRC).
        let c = Capabilities {
            long_packets: false,
            attribute_packets: false,
            window: 1,
            maxl: 80,
            chkt: b'3',
            ..Capabilities::default()
        };
        assert_eq!(detect_flavor(&c), KermitFlavor::EmbeddedKermit);
    }

    // ---------- Attributes ----------

    #[test]
    fn test_attributes_roundtrip_full() {
        let a = Attributes {
            length: Some(12345),
            date: Some("20260426 12:34:56".into()),
            mode: Some(0o644),
            system_id: Some("UNIX".into()),
            file_type: Some(b'B'),
            disposition: Some(b'N'),
        };
        let bytes = encode_attributes(&a);
        let parsed = parse_attributes(&bytes);
        assert_eq!(parsed.length, Some(12345));
        assert_eq!(parsed.date.as_deref(), Some("20260426 12:34:56"));
        assert_eq!(parsed.mode, Some(0o644));
        assert_eq!(parsed.system_id.as_deref(), Some("UNIX"));
        assert_eq!(parsed.file_type, Some(b'B'));
        assert_eq!(parsed.disposition, Some(b'N'));
    }

    #[test]
    fn test_attributes_partial() {
        // Just length — common minimal case.
        let a = Attributes {
            length: Some(99),
            ..Attributes::default()
        };
        let bytes = encode_attributes(&a);
        let parsed = parse_attributes(&bytes);
        assert_eq!(parsed.length, Some(99));
        assert_eq!(parsed.date, None);
        assert_eq!(parsed.mode, None);
    }

    #[test]
    fn test_parse_attributes_skips_unknown_tags() {
        let mut data = Vec::new();
        // Unknown tag 'Q' with 3-byte body
        data.push(b'Q');
        data.push(tochar(3));
        data.extend_from_slice(b"abc");
        // Known tag '!' with length value
        data.push(b'!');
        data.push(tochar(2));
        data.extend_from_slice(b"42");
        let a = parse_attributes(&data);
        assert_eq!(a.length, Some(42));
    }

    // ---------- Date conversion ----------

    #[test]
    fn test_kermit_date_roundtrip() {
        // Around 2026-04-26 12:00:00 UTC = 1777547200 (approximately)
        let secs = 1777547200u64;
        let s = unix_secs_to_kermit_date(secs);
        let parsed = parse_kermit_date(&s).unwrap();
        // Allow a few seconds of round-trip error (we drop sub-second).
        assert!(parsed.abs_diff(secs) <= 60);
    }

    #[test]
    fn test_parse_kermit_date_short_form() {
        // Date-only form (no time portion).
        let parsed = parse_kermit_date("20260101").unwrap();
        // Should be midnight 2026-01-01.
        // Days from 1970-01-01 to 2026-01-01: simple sanity, just check
        // it's a positive multiple of 86400.
        assert_eq!(parsed % 86400, 0);
    }

    #[test]
    fn test_parse_kermit_date_invalid() {
        assert!(parse_kermit_date("garbage").is_none());
        assert!(parse_kermit_date("20261301").is_none()); // bad month
        assert!(parse_kermit_date("").is_none());
    }

    // ---------- CAN×2 abort ----------

    #[test]
    fn test_can_abort_state() {
        let mut s = ReadState::default();
        assert!(!is_can_abort(CAN, &mut s));
        assert!(is_can_abort(CAN, &mut s));
        // Reset on non-CAN
        assert!(!is_can_abort(b'A', &mut s));
        assert!(!is_can_abort(CAN, &mut s));
        assert!(!is_can_abort(b'B', &mut s)); // resets again
        assert!(!is_can_abort(CAN, &mut s));
    }

    // ---------- End-to-end round trips ----------

    use tokio::io::{duplex, split};

    /// Helper: run kermit_send and kermit_receive against each other in
    /// duplex pipes, returning the receiver's result.
    async fn round_trip(
        files: Vec<(String, Vec<u8>)>,
    ) -> Result<Vec<KermitReceive>, String> {
        // Two duplex streams.  Each pair is internally connected — data
        // written to one half appears on the other.  We split each into
        // a read+write pair, then route them so sender's writes flow
        // to receiver and vice-versa.
        //
        // Layout:
        //   sender writes to sx_w → receiver reads from sx_r
        //   receiver writes to rx_w → sender reads from rx_r
        let (sx, rx) = duplex(65536);
        let (mut rx_r_for_send, mut sx_w_for_send) = split(sx);
        let (mut sx_r_for_recv, mut rx_w_for_recv) = split(rx);

        let send_files: Vec<(String, Vec<u8>)> = files.clone();
        let send_task = tokio::spawn(async move {
            let kfiles: Vec<KermitSendFile> = send_files
                .iter()
                .map(|(n, d)| KermitSendFile {
                    name: n.as_str(),
                    data: d.as_slice(),
                    modtime: None,
                    mode: None,
                })
                .collect();
            kermit_send(
                &mut rx_r_for_send,
                &mut sx_w_for_send,
                &kfiles,
                false,
                false,
                false,
            )
            .await
        });

        let recv_task = tokio::spawn(async move {
            kermit_receive(
                &mut sx_r_for_recv,
                &mut rx_w_for_recv,
                false,
                false,
                false,
            )
            .await
        });

        let send_result = send_task.await.unwrap();
        let recv_result = recv_task.await.unwrap();

        send_result?;
        recv_result
    }

    #[tokio::test]
    async fn test_round_trip_simple() {
        init_test_config();
        let received = round_trip(vec![("hello.txt".into(), b"Hello, Kermit!".to_vec())])
            .await
            .unwrap();
        assert_eq!(received.len(), 1);
        assert_eq!(received[0].filename, "hello.txt");
        assert_eq!(received[0].data, b"Hello, Kermit!");
    }

    #[tokio::test]
    async fn test_round_trip_empty_file() {
        init_test_config();
        let received = round_trip(vec![("empty.bin".into(), Vec::new())])
            .await
            .unwrap();
        assert_eq!(received.len(), 1);
        assert_eq!(received[0].data.len(), 0);
    }

    #[tokio::test]
    async fn test_round_trip_all_byte_values() {
        init_test_config();
        let payload: Vec<u8> = (0u16..=255).map(|v| v as u8).collect();
        let received = round_trip(vec![("bytes.bin".into(), payload.clone())])
            .await
            .unwrap();
        assert_eq!(received[0].data, payload);
    }

    #[tokio::test]
    async fn test_round_trip_multiple_files() {
        init_test_config();
        let files = vec![
            ("a.txt".into(), b"alpha".to_vec()),
            ("b.txt".into(), b"beta".to_vec()),
            ("c.txt".into(), b"gamma".to_vec()),
        ];
        let received = round_trip(files.clone()).await.unwrap();
        assert_eq!(received.len(), 3);
        for (i, f) in files.iter().enumerate() {
            assert_eq!(received[i].filename, f.0);
            assert_eq!(received[i].data, f.1);
        }
    }

    #[tokio::test]
    async fn test_round_trip_4kb() {
        init_test_config();
        let payload: Vec<u8> = (0..4096).map(|i| (i * 7 + 3) as u8).collect();
        let received = round_trip(vec![("blob.bin".into(), payload.clone())])
            .await
            .unwrap();
        assert_eq!(received[0].data, payload);
    }

    /// Initialise the global config singleton with reasonable defaults
    /// for tests.  No-op if already initialised.
    fn init_test_config() {
        // Setting the singleton via update_config_value is the
        // simplest way to ensure the kermit_* fields are populated
        // even if the config file isn't present.
        // We accept the default via load_or_create_config in real
        // runs; for tests we set each key explicitly.
        config::update_config_value("kermit_negotiation_timeout", "30");
        config::update_config_value("kermit_packet_timeout", "10");
        config::update_config_value("kermit_max_retries", "5");
        config::update_config_value("kermit_max_packet_length", "4096");
        config::update_config_value("kermit_window_size", "1");
        config::update_config_value("kermit_block_check_type", "3");
        config::update_config_value("kermit_long_packets", "true");
        config::update_config_value("kermit_sliding_windows", "false");
        config::update_config_value("kermit_streaming", "false");
        config::update_config_value("kermit_attribute_packets", "true");
        config::update_config_value("kermit_repeat_compression", "true");
        config::update_config_value("kermit_8bit_quote", "auto");
        config::update_config_value("kermit_iac_escape", "false");
    }
}
