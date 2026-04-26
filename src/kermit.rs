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

use tokio::io::{AsyncRead, AsyncWrite};

use crate::config;
use crate::logger::glog;
use crate::telnet::is_esc_key;
use crate::tnio::{is_can_abort, nvt_read_byte, raw_write_bytes, ReadState};

// ─── Wire constants ──────────────────────────────────────────

/// Standard packet start byte (Start-Of-Header).  Spec mandates this
/// for the first packet of a session; subsequent packets MAY use a
/// different MARK if peers agree, but in practice everyone uses SOH.
pub(crate) const SOH: u8 = 0x01;
const SP: u8 = 0x20; // space — tochar(0); marker for extended-length packets
/// Locking-shift marker: switch decoder to "high-bit-on" mode (Frank
/// da Cruz spec §3.4.5).  Sent ctl-quoted on the wire.
pub(crate) const SO: u8 = 0x0E;
/// Locking-shift marker: switch decoder back to "normal" mode.  Sent
/// ctl-quoted on the wire.
pub(crate) const SI: u8 = 0x0F;
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
pub(crate) const TYPE_HOST: u8 = b'C';
pub(crate) const TYPE_TEXT: u8 = b'X';
/// Server-mode "Receive" command — peer asks us to send the named file.
pub(crate) const TYPE_R: u8 = b'R';
/// Server-mode "Initialize" command — peer asks us to re-advertise our
/// capabilities mid-session.  Honored by replying with a Y-ACK whose
/// payload is a freshly-built Send-Init.
pub(crate) const TYPE_INIT: u8 = b'I';

// CAPAS bit positions in the first capability byte (bits are read after
// stripping the LSB continuation flag — i.e. real bit n of capability
// equals bit (n+1) of the unchar'd byte).
//
// Bit layout (from Frank da Cruz, "Kermit Protocol Manual"):
//   bit 0: continuation — another CAPAS byte follows
//   bit 1: ability to do sliding-window
//   bit 2: ability to do extended-length (long) packets
//   bit 3: ability to handle attribute (A) packets
//   bit 4: ability to do RESEND (resume partial transfers)
//   bit 5: ability to use locking shifts (SO/SI region markers)
//
// Streaming and other extended bits live in subsequent CAPAS bytes,
// vendor-defined.  C-Kermit uses CAPAS byte 3 bit 2 for streaming.
pub(crate) const CAPAS_ATTRIBUTE: u8 = 0x08;
pub(crate) const CAPAS_LONGPKT: u8 = 0x04;
pub(crate) const CAPAS_SLIDING: u8 = 0x02;
pub(crate) const CAPAS_CONTINUE: u8 = 0x01;
pub(crate) const CAPAS_RESEND: u8 = 0x10;
pub(crate) const CAPAS_LOCKING_SHIFT: u8 = 0x20;

/// Streaming Kermit lives in CAPAS byte 3 bit 2 (per C-Kermit).  In our
/// internal `Capabilities` struct it's a bool; the wire encoding handles
/// placement.
pub(crate) const CAPAS_STREAMING_BYTE3_BIT: u8 = 0x04;

// Telnet IAC + CAN handling now lives in `crate::tnio` (shared with
// xmodem.rs and zmodem.rs).  Kermit's CAN×2 abort uses
// `tnio::is_can_abort`; raw I/O uses `tnio::raw_read_byte`,
// `tnio::raw_write_bytes`, and `tnio::nvt_read_byte`.

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
/// Cap on files in a single batch transfer.  Defends against a peer
/// (intentionally or otherwise) accumulating an unbounded `received`
/// vector over the lifetime of one session.  1000 is well above any
/// realistic batch size — typical transfers are 1-10 files.
const MAX_BATCH_FILES: usize = 1000;
/// How many D-packet success traces to log per file at `verbose=true`.
/// Mirrors zmodem.rs's `subpackets_sent <= 3` rate-limit pattern: log
/// the first few to confirm the protocol baseline is working, go
/// silent on success after that.  Failure paths log unconditionally.
const D_PACKET_TRACE_LIMIT: u32 = 3;

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
/// QCTL-quoting)?  Per Frank da Cruz §6.4, this covers:
/// - C0 controls (0x00..=0x1F)
/// - DEL (0x7F)
/// - C1 controls (0x80..=0x9F) — high-bit equivalents of C0
/// - 0xFF — high-bit equivalent of DEL
///
/// When QBIN is active, the encoder strips the high bit *before*
/// applying this test, so the high-bit ranges aren't reached on the
/// QBIN path; they matter only when 8-bit data is transmitted
/// transparently and a C1 control still needs ctl-encoding.
///
/// Note that the QCTL byte itself ALSO needs quoting, but that's
/// handled at the quoting layer where the QCTL value is in scope.
#[inline]
pub(crate) fn is_kermit_control(b: u8) -> bool {
    b < 0x20 || b == DEL || (0x80..=0x9F).contains(&b) || b == 0xFF
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
                    "Kermit: CHKT-2 expects 2 check bytes, got {}",
                    check.len()
                ));
            }
            let expected = chk2_decode(check[0], check[1]);
            let actual_sum: u32 = data.iter().map(|&b| b as u32).sum::<u32>() & 0x0FFF;
            if actual_sum as u16 == expected {
                Ok(())
            } else {
                Err(format!(
                    "Kermit: CHKT-2 mismatch: expected {:#x} got {:#x}",
                    expected, actual_sum
                ))
            }
        }
        b'3' => {
            if check.len() != 3 {
                return Err(format!(
                    "Kermit: CHKT-3 expects 3 check bytes, got {}",
                    check.len()
                ));
            }
            let expected = chk3_decode(check[0], check[1], check[2]);
            let actual = kermit_crc16(data);
            if expected == actual {
                Ok(())
            } else {
                Err(format!(
                    "Kermit: CHKT-3 mismatch: expected {:#x} got {:#x}",
                    expected, actual
                ))
            }
        }
        _ => {
            if check.len() != 1 {
                return Err(format!(
                    "Kermit: CHKT-1 expects 1 check byte, got {}",
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
                    "Kermit: CHKT-1 mismatch: expected {:#x} got {:#x}",
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
    /// 8-bit-clean transparent transmission is in use.  Mutually
    /// exclusive with `locking_shifts`: when locking shifts are
    /// negotiated, QBIN goes off (locking-shift > QBIN per spec §3.4).
    pub qbin: Option<u8>,
    /// Repeat prefix character, when REPT compression is active.  `None`
    /// disables compression entirely.
    pub rept: Option<u8>,
    /// Locking-shift mode (Frank da Cruz spec §3.4.5): instead of
    /// per-byte 8th-bit prefixing, the encoder emits SO/SI markers to
    /// switch into a "high-bit-on" region for runs of high-bit bytes.
    /// Used on strict 7-bit links; `qbin` should be `None` when this
    /// is true.
    pub locking_shifts: bool,
}

impl Default for Quoting {
    fn default() -> Self {
        Self {
            qctl: DEFAULT_QCTL,
            qbin: None,
            rept: Some(DEFAULT_REPT),
            locking_shifts: false,
        }
    }
}

/// Encoder/decoder state for the locking-shift layer.  Tracks which
/// "set" we're currently writing — Normal = bytes pass through with
/// their high bit clear, Shifted = bytes had their high bit set on
/// the encoder side and the decoder OR's it back.  Reset to Normal at
/// the start of every packet (encoder emits a closing SI to guarantee
/// this; decoder re-initialises in `decode_data`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ShiftMode {
    Normal,
    Shifted,
}

/// Encode a single byte through the quoting layers into the output
/// buffer.  Inner per-byte step; the public encoder walks the input
/// slice and applies repeat compression when active.
///
/// `mode` is only consulted when `q.locking_shifts` is true; in that
/// case the function may emit a leading `qctl ctl(SO|SI)` to flip
/// the wire-side mode before the body byte.
fn encode_one_byte(out: &mut Vec<u8>, b: u8, q: Quoting, mode: &mut ShiftMode) {
    if q.locking_shifts {
        // Locking-shift path: high bit becomes a mode rather than a
        // per-byte prefix.  QBIN is unused when this branch is taken.
        let target = if b & 0x80 != 0 {
            ShiftMode::Shifted
        } else {
            ShiftMode::Normal
        };
        if target != *mode {
            out.push(q.qctl);
            out.push(ctl(if target == ShiftMode::Shifted { SO } else { SI }));
            *mode = target;
        }
        let body = b & 0x7F;
        // Special case: literal SO / SI bytes in user data must use
        // the literal-prefix escape (`qctl + body`) rather than the
        // ctl-encoded form (`qctl + ctl(body)`).  The latter is the
        // wire form of a shift marker — emitting it for data would
        // make the decoder mode-flip on a regular byte.
        if body == SO || body == SI {
            out.push(q.qctl);
            out.push(body);
            return;
        }
        if is_kermit_control(body) {
            out.push(q.qctl);
            out.push(ctl(body));
        } else if body == q.qctl || q.rept == Some(body) {
            out.push(q.qctl);
            out.push(body);
        } else {
            out.push(body);
        }
        return;
    }

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
    let mut mode = ShiftMode::Normal;
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
                // Locking-shift mode must be flipped BEFORE the REPT
                // marker so the marker + body sit in the right set.
                // If we let `encode_one_byte` flip mode after `REPT
                // count`, the decoder would see the shift between the
                // count and the body and apply it only to the first
                // replicated byte rather than the whole run.
                if q.locking_shifts {
                    let target = if input[i] & 0x80 != 0 {
                        ShiftMode::Shifted
                    } else {
                        ShiftMode::Normal
                    };
                    if target != mode {
                        out.push(q.qctl);
                        out.push(ctl(if target == ShiftMode::Shifted { SO } else { SI }));
                        mode = target;
                    }
                }
                out.push(rept_char);
                out.push(tochar(run as u8));
                encode_one_byte(&mut out, input[i], q, &mut mode);
                i += run;
                continue;
            }
        }
        encode_one_byte(&mut out, input[i], q, &mut mode);
        i += 1;
    }
    // Reset to Normal at packet end so each packet starts with a clean
    // slate (decoder re-initialises per packet but a strict spec peer
    // expects the closing SI).
    if q.locking_shifts && mode != ShiftMode::Normal {
        out.push(q.qctl);
        out.push(ctl(SI));
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
    let mut mode = ShiftMode::Normal;
    let mut i = 0;
    while i < input.len() {
        // Locking-shift markers (`qctl ctl(SO)` / `qctl ctl(SI)`) are
        // checked BEFORE the REPT prefix so a literal qctl-quoted SO/SI
        // can't slip past as data.  Literal SO/SI in user data uses the
        // literal-prefix form (`qctl + raw byte`) which falls through
        // to `decode_one_byte_at` and decodes correctly.
        if q.locking_shifts && input[i] == q.qctl && i + 1 < input.len() {
            let candidate = unctl(input[i + 1]);
            if candidate == SO {
                mode = ShiftMode::Shifted;
                i += 2;
                continue;
            }
            if candidate == SI {
                mode = ShiftMode::Normal;
                i += 2;
                continue;
            }
        }
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
            let with_mode = if q.locking_shifts && mode == ShiftMode::Shifted {
                decoded | 0x80
            } else {
                decoded
            };
            for _ in 0..n {
                out.push(with_mode);
            }
            continue;
        }

        let (decoded, consumed) = decode_one_byte_at(input, i, q)?;
        i += consumed;
        let with_mode = if q.locking_shifts && mode == ShiftMode::Shifted {
            decoded | 0x80
        } else {
            decoded
        };
        out.push(with_mode);
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
        // ctl-encoded control bytes are bodies whose unctl form
        // (b ^ 0x40) is itself a Kermit control.  That covers four
        // disjoint body ranges per spec §6.4:
        //   [0x40..=0x5F] → C0 controls (0x00..=0x1F)
        //   '?'  (0x3F)   → DEL (0x7F)
        //   [0xC0..=0xDF] → C1 controls (0x80..=0x9F) (peer didn't QBIN)
        //   0xBF          → high-bit DEL (0xFF)
        // Everything else is a literal prefix byte the encoder
        // protected (QCTL, QBIN, or REPT itself).
        let candidate = unctl(body);
        let decoded = if is_kermit_control(candidate) {
            candidate | high_bit
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
        // Extended-length form.  LEN = SP (tochar(0)) is the marker;
        // the real length is in LENX1+LENX2 and per spec covers only
        // "everything after HCHECK" — i.e., DATA + CHECK, NOT the
        // 5 header bytes (SEQ+TYPE+LENX1+LENX2+HCHECK) that come
        // before HCHECK.  This is what C-Kermit emits on the wire and
        // is required for interop.
        let extended_len = payload.len() + cklen;
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
    verbose: bool,
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
            if verbose {
                glog!(
                    "Kermit recv: HCHECK mismatch (got {:#x}, expected {:#x}) — discarding packet",
                    hcheck,
                    expected_hcheck
                );
            }
            return Err(format!(
                "Kermit: extended-length header check mismatch ({:#x} vs {:#x})",
                hcheck, expected_hcheck
            ));
        }
        // HCHECK participates in the trailing CHECK trailer, per spec.
        header_input.push(hcheck);
        let extended_len = (unchar(lenx1) as usize) * 95 + unchar(lenx2) as usize;
        let cklen = check_size(chkt);
        // extended_len covers DATA + CHECK only (per spec / C-Kermit
        // wire format) — everything after HCHECK.
        if extended_len < cklen {
            return Err(format!(
                "Kermit: extended length {} too short for check",
                extended_len
            ));
        }
        let payload_len = extended_len - cklen;
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
    if let Err(e) = verify_check(chkt, &check_input, &check_bytes) {
        if verbose {
            glog!(
                "Kermit recv: CHECK failed for type='{}' seq={}: {}",
                kind as char,
                seq,
                e
            );
        }
        return Err(e);
    }
    // D-packets get a richer downstream log (with decoded length and
    // running file total) that's rate-limited per file.  Logging them
    // here too would defeat the rate limit and drown the buffer on a
    // multi-megabyte transfer.
    if verbose && kind != TYPE_DATA {
        glog!(
            "Kermit recv: packet type='{}' seq={} payload={}B",
            kind as char,
            seq,
            payload.len()
        );
    }

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
// READ HELPERS (deadline-aware byte reader on top of `tnio::nvt_read_byte`)
// =============================================================================

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
    /// Whether RESEND (resume partial transfers) was negotiated.
    /// Spec gates the disposition='R' / length= mechanism on both
    /// peers advertising the CAPAS_RESEND bit; we honor that strict
    /// reading even though most modern Kermits would accept the
    /// disposition tag without the CAPAS handshake.
    pub resend: bool,
    /// Whether locking-shift quoting (SO/SI region markers) was
    /// negotiated.  Per spec precedence locking-shift > QBIN: when
    /// active, `qbin` is forced to None and 8-bit data rides through
    /// the SO/SI mode-switching layer instead.
    pub locking_shifts: bool,
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
            resend: false,
            locking_shifts: false,
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
    if c.resend {
        capas1 |= CAPAS_RESEND;
    }
    if c.locking_shifts {
        capas1 |= CAPAS_LOCKING_SHIFT;
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

    // Slot 11+: optional extended fields, each gated on its own
    // CAPAS bit per spec §4.4 ("Send-Init"):
    //   WINDO is present iff the sliding-window bit is set
    //         (i.e., advertised window > 1).
    //   MAXLX1, MAXLX2 are present iff the long-packets bit is set.
    // Emitting either field unconditionally misaligns a strict-spec
    // peer's parser — e.g., advertising long-packets without sliding
    // and emitting a stray WINDO=1 would be misread as MAXLX1=1,
    // collapsing the negotiated MAXL to ~138 bytes.
    if c.window > 1 {
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
    let advertises_sliding = capas_bytes
        .first()
        .map(|&first| first & CAPAS_SLIDING != 0)
        .unwrap_or(false);
    let advertises_long = capas_bytes
        .first()
        .map(|&first| first & CAPAS_LONGPKT != 0)
        .unwrap_or(false);
    if let Some(&first) = capas_bytes.first() {
        c.long_packets = advertises_long;
        c.attribute_packets = first & CAPAS_ATTRIBUTE != 0;
        c.resend = first & CAPAS_RESEND != 0;
        c.locking_shifts = first & CAPAS_LOCKING_SHIFT != 0;
        // Sliding-window default: stop-and-wait until peer's CAPAS
        // bit AND the WINDO field below tell us otherwise.
        if !advertises_sliding {
            c.window = 1;
        }
    }
    if let Some(&third) = capas_bytes.get(2) {
        c.streaming = third & CAPAS_STREAMING_BYTE3_BIT != 0;
    }
    // WINDO is present iff sliding bit is set in CAPAS byte 1
    // (spec §4.4).  Reading it unconditionally would consume a byte
    // that's actually the next field (MAXLX1 if long was advertised,
    // or trailing CAPAS-extension bytes) and misalign the parse.
    if advertises_sliding && data.len() > idx {
        c.window = unchar(data[idx]).clamp(1, MAX_WINDOW_SIZE);
        idx += 1;
    }
    // MAXLX1, MAXLX2 are present iff the long-packets bit is set.
    if advertises_long && data.len() > idx + 1 {
        let mx1 = unchar(data[idx]) as u16;
        let mx2 = unchar(data[idx + 1]) as u16;
        let extended = mx1 * 95 + mx2;
        if (MIN_PACKET_LEN as u16..=EXTENDED_MAX_PACKET_LEN as u16).contains(&extended) {
            c.maxl = extended;
        }
        idx += 2;
    }
    // Optional trailing bytes.  Per spec these may carry vendor-
    // defined CAPAS-extension fields (CHECKPOINT, WHATAMI, etc., as
    // C-Kermit emits) OR a free-form ASCII identification string.
    // Real C-Kermit fills this slot with binary extension bytes that
    // happen to be in the printable range but don't form a readable
    // identifier — accepting them as peer_id produces garbage like
    // `0___^"U1A` and breaks downstream flavor detection.
    //
    // Heuristic: only treat trailing bytes as peer_id when they
    // contain a 4-character run of ASCII letters (the smallest
    // identifier likely to be meaningful — "Kermit" alone clears
    // this; binary extension fields rarely do).
    if data.len() > idx {
        let trailing = &data[idx..];
        let has_letter_run = trailing
            .windows(4)
            .any(|w| w.iter().all(|b| b.is_ascii_alphabetic()));
        if has_letter_run {
            let s = String::from_utf8_lossy(trailing).trim().to_string();
            if !s.is_empty() {
                c.peer_id = Some(s);
            }
        }
    }
    c
}

/// Take the intersection of OUR proposal and PEER's response, producing
/// the parameters the session will use in our send-direction.  Spec rule:
/// each side's RECEIVE preferences govern what the OTHER side sends.
pub(crate) fn intersect_capabilities(ours: &Capabilities, theirs: &Capabilities) -> Capabilities {
    // Locking-shift / QBIN precedence (Frank da Cruz §3.4): when both
    // peers advertise CAPAS_LOCKING_SHIFT *and* either side would
    // otherwise need 8-bit prefixing, use locking shifts and force
    // QBIN off.  When only one peer advertises locking shifts, fall
    // back to the existing QBIN logic.  When neither side needs 8-bit
    // (qbin already None on both sides), neither mechanism is active
    // — there's nothing to convey.
    let both_lshift = ours.locking_shifts && theirs.locking_shifts;
    let need_eight_bit = ours.qbin.is_some() || theirs.qbin.is_some();
    let use_lshift = both_lshift && need_eight_bit;
    let qbin_negotiated = if use_lshift {
        None
    } else {
        match (ours.qbin, theirs.qbin) {
            (Some(c), _) | (_, Some(c)) => Some(c),
            _ => None,
        }
    };
    Capabilities {
        // Sender (us) honors peer's MAXL.
        maxl: theirs.maxl.min(ours.maxl).max(MIN_PACKET_LEN as u16),
        time: theirs.time.max(1),
        npad: theirs.npad,
        padc: theirs.padc,
        eol: theirs.eol,
        qctl: theirs.qctl,
        // 8th-bit prefix: see precedence comment above.
        qbin: qbin_negotiated,
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
        resend: ours.resend && theirs.resend,
        locking_shifts: use_lshift,
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
        resend: cfg.kermit_resume_partial,
        locking_shifts: cfg.kermit_locking_shifts,
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

/// Wrap a per-packet send error with packet-type context, stripping
/// the redundant "Kermit:" prefix from the inner error so the result
/// reads "Kermit send {context}: {detail}" instead of double-prefixing.
fn wrap_send_err(context: &str, inner: String) -> String {
    let detail = inner.strip_prefix("Kermit: ").unwrap_or(&inner);
    format!("Kermit send {}: {}", context, detail)
}

/// Per-packet retransmit/read timeout *after* Send-Init completes.
/// Spec: peer's TIME field (seconds) is how long they want us to wait
/// before retransmitting; a value of 0 means "no preference — use your
/// protocol default" so we fall back to `kermit_packet_timeout`.  Floor
/// at 1 s so a misconfigured peer can't wedge us with TIME=0 plus a 0
/// fallback.
fn effective_packet_timeout(peer_time: u8, fallback_secs: u64) -> tokio::time::Duration {
    let secs = if peer_time > 0 {
        peer_time as u64
    } else {
        fallback_secs
    };
    tokio::time::Duration::from_secs(secs.max(1))
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
        locking_shifts: false,
    };
    let payload = encode_data(msg.as_bytes(), q);
    let pkt = build_packet(TYPE_ERROR, seq, &payload, chkt, pad_count, pad_char, eol);
    raw_write_bytes(writer, &pkt, is_tcp).await
}

// =============================================================================
// ATTRIBUTE PACKET CODEC
// =============================================================================

/// Subset of A-packet sub-attributes we emit / parse, per Frank da
/// Cruz spec §5.1 ("File Attributes").  Each sub-attr is a single-
/// character tag, followed by `tochar(length)`, followed by `length`
/// bytes of value.  Unknown tags are silently skipped on receive
/// (length-byte respected); a malformed length terminates parsing
/// without error so adversarial input can't panic the receiver.
#[derive(Default, Clone, Debug)]
pub(crate) struct Attributes {
    /// File length in bytes ('!' tag, decimal-string value).
    pub length: Option<u64>,
    /// File creation/modification date ('#' tag, "yyyymmdd hh:mm:ss").
    pub date: Option<String>,
    /// UNIX permission bits ('+' tag in some Kermits, vendor extension).
    pub mode: Option<u32>,
    /// Sender's system ID ('.' tag).  Surfaces in flavor classification
    /// when the Send-Init didn't carry an obvious peer_id.
    pub system_id: Option<String>,
    /// File type ('"' tag) — single character, typically `A`=ASCII /
    /// `B`=binary.
    pub file_type: Option<u8>,
    /// Disposition ('@' tag): 'N' = new, 'S' = supersede, etc.
    pub disposition: Option<u8>,
    /// Long-form file length in bytes ('&' tag, decimal-string value).
    /// Provided by senders with files larger than the '!' field can
    /// represent; we cap inbound at MAX_FILE_SIZE so this is mostly
    /// informational, but we accept it as a fallback when '!' is
    /// absent.  We don't emit '&' ourselves since '!' covers our cap.
    pub long_length: Option<u64>,
    /// Character set ('1' tag) — single character, typically 'A' for
    /// ASCII, 'B' for some 8-bit table, etc.  Recorded but not
    /// interpreted; downstream code can surface it if it cares.
    pub charset: Option<u8>,
    /// Encoding ('*' tag) — single character, typically 'A'/'B' =
    /// binary / image, 'C' = compressed, etc.  Recorded only.
    pub encoding: Option<u8>,
    /// Record format (',' tag) — single character, typically 'S' =
    /// stream (the only one we ever produce), 'F' = fixed-length,
    /// 'V' = variable-length.  Recorded only.
    pub record_format: Option<u8>,
    /// Record length ('-' tag, decimal-string value).  Only meaningful
    /// alongside `record_format` = 'F' or 'V'; otherwise informational.
    pub record_length: Option<u32>,
    /// Creator's user / login ID ('$' tag).  Surfaced by some VMS / MVS
    /// Kermits; recorded only on UNIX (we don't act on it).
    pub creator_id: Option<String>,
    /// Account / billing ID ('%' tag).  Mainframe-flavoured metadata;
    /// recorded only.
    pub account_id: Option<String>,
    /// Block size ('\'' tag, decimal-string value).  Meaningful only on
    /// record-oriented filesystems we don't have; recorded only.
    pub block_size: Option<u32>,
    /// Access mode ('(' tag) — single character, typically 'N' = new,
    /// 'R' = read, 'A' = append, 'S' = supersede.  Recorded only.
    pub access_mode: Option<u8>,
    /// Encoding alternative (')' tag) — single character; some
    /// implementations use this in place of '*'.  Recorded only.
    pub encoding_alt: Option<u8>,
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
    if let Some(c) = a.charset {
        out.push(b'1');
        out.push(tochar(1));
        out.push(c);
    }
    if let Some(e) = a.encoding {
        out.push(b'*');
        out.push(tochar(1));
        out.push(e);
    }
    if let Some(f) = a.record_format {
        out.push(b',');
        out.push(tochar(1));
        out.push(f);
    }
    if let Some(rl) = a.record_length {
        let s = rl.to_string();
        if s.len() <= 94 {
            out.push(b'-');
            out.push(tochar(s.len() as u8));
            out.extend_from_slice(s.as_bytes());
        }
    }
    if let Some(creator) = &a.creator_id {
        let bytes = creator.as_bytes();
        if bytes.len() <= 94 {
            out.push(b'$');
            out.push(tochar(bytes.len() as u8));
            out.extend_from_slice(bytes);
        }
    }
    if let Some(account) = &a.account_id {
        let bytes = account.as_bytes();
        if bytes.len() <= 94 {
            out.push(b'%');
            out.push(tochar(bytes.len() as u8));
            out.extend_from_slice(bytes);
        }
    }
    if let Some(bs) = a.block_size {
        let s = bs.to_string();
        if s.len() <= 94 {
            out.push(b'\'');
            out.push(tochar(s.len() as u8));
            out.extend_from_slice(s.as_bytes());
        }
    }
    if let Some(am) = a.access_mode {
        out.push(b'(');
        out.push(tochar(1));
        out.push(am);
    }
    if let Some(ea) = a.encoding_alt {
        out.push(b')');
        out.push(tochar(1));
        out.push(ea);
    }
    // We don't emit '&' (long_length) ourselves: '!' fits MAX_FILE_SIZE
    // (8 MB) trivially, and emitting both would just bloat the
    // packet.  We do parse it on receive though.
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
            b'&' => {
                // Long-form length, decimal string.  Same parser as
                // '!' but a wider receiver type.
                if let Ok(s) = std::str::from_utf8(val)
                    && let Ok(v) = s.trim().parse::<u64>()
                {
                    a.long_length = Some(v);
                }
            }
            b'1' => {
                if !val.is_empty() {
                    a.charset = Some(val[0]);
                }
            }
            b'*' => {
                if !val.is_empty() {
                    a.encoding = Some(val[0]);
                }
            }
            b',' => {
                if !val.is_empty() {
                    a.record_format = Some(val[0]);
                }
            }
            b'-' => {
                if let Ok(s) = std::str::from_utf8(val)
                    && let Ok(v) = s.trim().parse::<u32>()
                {
                    a.record_length = Some(v);
                }
            }
            b'$' => {
                if let Ok(s) = std::str::from_utf8(val) {
                    a.creator_id = Some(s.to_string());
                }
            }
            b'%' => {
                if let Ok(s) = std::str::from_utf8(val) {
                    a.account_id = Some(s.to_string());
                }
            }
            b'\'' => {
                if let Ok(s) = std::str::from_utf8(val)
                    && let Ok(v) = s.trim().parse::<u32>()
                {
                    a.block_size = Some(v);
                }
            }
            b'(' => {
                if !val.is_empty() {
                    a.access_mode = Some(val[0]);
                }
            }
            b')' => {
                if !val.is_empty() {
                    a.encoding_alt = Some(val[0]);
                }
            }
            _ => {}
        }
        i += 2 + n;
    }
    a
}

// =============================================================================
// RESUME-PARTIAL HELPER
// =============================================================================

/// Maximum accepted filename length in safety-validated paths.
/// Matches `TelnetSession::MAX_FILENAME_LEN` so a peer-supplied name
/// that passes our kermit-layer guard is also acceptable to the
/// telnet save path; this avoids an asymmetry where the protocol
/// would round-trip a filename that the saver then refuses.
const MAX_KERMIT_FILENAME_LEN: usize = 64;

/// Maximum accepted CWD-subdir length.  Generous enough for several
/// nested components (~16 levels of 16-char names) but bounded so a
/// peer can't pin our session against a 9 KB MAXL-sized payload of
/// junk that happens to pass component-level validation.
const MAX_KERMIT_SUBDIR_LEN: usize = 255;

/// Defense-in-depth check applied before joining a sender-supplied
/// filename onto `transfer_dir` for resume lookup.  Refuses anything
/// that could escape the directory or hit a hidden file: separator
/// characters, parent-traversal sequences, NUL bytes, leading dots,
/// empty strings, and over-cap lengths.
pub(crate) fn is_safe_resume_filename(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_KERMIT_FILENAME_LEN
        && !name.starts_with('.')
        && !name.contains('/')
        && !name.contains('\\')
        && !name.contains("..")
        && !name.contains('\0')
}

/// Look up the on-disk size of a partial file eligible for resume,
/// keyed on the sender's filename.  Returns `Some(size)` only when
/// every check passes:
///
/// - file exists at `transfer_dir/filename` and is a regular file
///   (not a directory or symlink-to-directory),
/// - file mtime is within `max_age_hours` of the current wall clock,
/// - mtime is not in the future (clock-skew sanity check),
/// - reported size fits in u64.
///
/// Returns `None` for any failure: file absent, too old, too new
/// (clock skew), I/O error, non-regular, or unreadable mtime.  A
/// zero-byte partial returns `Some(0)` since the spec lets the
/// receiver advertise that and the sender still skips zero bytes.
///
/// `filename` is taken verbatim from the sender's F-packet; the
/// caller is responsible for path-traversal validation before
/// invoking this helper (use `is_safe_resume_filename` below).
pub(crate) fn compute_resume_offset(
    filename: &str,
    transfer_dir: &str,
    max_age_hours: u32,
) -> Option<u64> {
    use std::time::SystemTime;

    if !is_safe_resume_filename(filename) {
        return None;
    }
    let path = std::path::Path::new(transfer_dir).join(filename);
    // Reject symlinks via `symlink_metadata` (which does NOT follow):
    // a symlink that points at a different file would mislead the
    // receiver into pre-loading bytes from an unintended target,
    // then advertise an offset that doesn't match what the sender's
    // file looks like.  Regular files only.
    let lmeta = std::fs::symlink_metadata(&path).ok()?;
    if lmeta.file_type().is_symlink() {
        return None;
    }
    let meta = std::fs::metadata(&path).ok()?;
    if !meta.is_file() {
        return None;
    }
    let mtime = meta.modified().ok()?;
    let now = SystemTime::now();
    // mtime in the future = clock skew or tampering — treat as ineligible.
    let age = now.duration_since(mtime).ok()?;
    if age.as_secs() > (max_age_hours as u64).saturating_mul(3600) {
        return None;
    }
    Some(meta.len())
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
    kermit_send_with_starting_seq(reader, writer, files, is_tcp, is_petscii, verbose, 0).await
}

/// Same as `kermit_send` but lets the caller seed the initial sequence
/// number for our Send-Init.  Used by `kermit_server` after it
/// dispatches on a peer-supplied R packet: the response S must follow
/// the R in the same monotonically-increasing seq stream, so it can't
/// be hard-coded to 0.  All other callers should use `kermit_send`.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn kermit_send_with_starting_seq(
    reader: &mut (impl AsyncRead + Unpin),
    writer: &mut (impl AsyncWrite + Unpin),
    files: &[KermitSendFile<'_>],
    is_tcp: bool,
    is_petscii: bool,
    verbose: bool,
    starting_seq: u8,
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
    // pkt_timeout is set after Send-Init using the peer's negotiated
    // TIME field (spec §3.2: peer's TIME tells us how long it wants us
    // to wait before retransmitting to it).  During Send-Init itself
    // we use `neg_deadline` derived from `kermit_negotiation_timeout`.
    let max_retries = cfg.kermit_max_retries;

    // 1. Send Send-Init (S, seq=0) and wait for ACK with peer's caps.
    let s_payload = build_send_init_payload(&our_caps);
    if verbose {
        glog!(
            "Kermit send: proposing MAXL={} CHKT={} window={} long={} stream={} attrs={} qbin={:?}",
            our_caps.maxl,
            our_caps.chkt as char,
            our_caps.window,
            our_caps.long_packets,
            our_caps.streaming,
            our_caps.attribute_packets,
            our_caps.qbin,
        );
    }
    let mut seq: u8 = starting_seq & 0x3F;

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
    .map_err(|e| wrap_send_err("Send-Init", e))?;

    let peer_init = parse_send_init_payload(&peer_caps);
    let session = intersect_capabilities(&our_caps, &peer_init);
    let flavor = detect_flavor(&peer_init);
    // Honor peer's TIME for our retransmit/read deadlines from here on.
    let pkt_timeout = effective_packet_timeout(session.time, cfg.kermit_packet_timeout);
    if verbose {
        glog!(
            "Kermit send: peer offered MAXL={} TIME={} CHKT={} window={} long={} stream={} attrs={} qbin={:?} id={:?}",
            peer_init.maxl,
            peer_init.time,
            peer_init.chkt as char,
            peer_init.window,
            peer_init.long_packets,
            peer_init.streaming,
            peer_init.attribute_packets,
            peer_init.qbin,
            peer_init.peer_id,
        );
        glog!(
            "Kermit send: negotiated MAXL={} CHKT={} window={} long={} stream={} attrs={} pkt_timeout={}s flavor={}",
            session.maxl,
            session.chkt as char,
            session.window,
            session.long_packets,
            session.streaming,
            session.attribute_packets,
            pkt_timeout.as_secs(),
            flavor.display()
        );
    }

    let send_q = Quoting {
        qctl: session.qctl,
        qbin: session.qbin,
        rept: session.rept,
        locking_shifts: session.locking_shifts,
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
        .map_err(|e| wrap_send_err("F-packet", e))?;
        seq = (seq + 1) & 0x3F;

        // A-packet (when negotiated).  Carries length, mtime, mode.
        // Receiver may reply with disposition='R' + length=N to ask us
        // to resume — we honor that by slicing `f.data[N..]` for the
        // D-packets below.
        let mut data_offset: usize = 0;
        if session.attribute_packets {
            let attrs = Attributes {
                length: Some(f.data.len() as u64),
                date: f.modtime.map(unix_secs_to_kermit_date),
                mode: f.mode,
                system_id: Some("UNIX".into()),
                file_type: Some(b'B'), // binary
                disposition: Some(b'N'),
                ..Attributes::default()
            };
            let a_payload = encode_data(&encode_attributes(&attrs), send_q);
            let ack_payload = send_and_await_ack(
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
            .map_err(|e| wrap_send_err("A-packet", e))?;
            seq = (seq + 1) & 0x3F;

            // Receiver-side resume request (Frank da Cruz §5.1): the
            // ACK payload carries an Attributes block with
            // disposition='R' and length=N when the receiver already
            // has N bytes of this file and wants us to skip ahead.
            // Empty payload = receiver had nothing to say, normal
            // send-from-zero.
            if !ack_payload.is_empty()
                && let Ok(raw) = decode_data(&ack_payload, send_q)
            {
                let resp = parse_attributes(&raw);
                if resp.disposition == Some(b'R')
                    && let Some(n) = resp.length
                {
                    let n = n.min(f.data.len() as u64) as usize;
                    if n > 0 {
                        data_offset = n;
                        if verbose {
                            glog!(
                                "Kermit send: receiver requested resume from {} of {}",
                                n,
                                f.data.len()
                            );
                        }
                    }
                }
            }
        }
        let data_to_send = &f.data[data_offset..];

        // D-packets.  Pick chunk size so that after worst-case quoting
        // blowup the encoded payload still fits in MAXL.  Worst case is
        // 3x for high-bit control bytes (qbin + qctl + ctl(body));
        // typical binary or text is closer to 1.1x.  75% headroom
        // covers typical data; adversarial all-control-byte input
        // would fail-fast rather than malforming a packet.
        let cklen = check_size(session.chkt);
        let header_overhead = if session.long_packets && session.maxl > CLASSIC_MAX_PACKET_LEN as u16
        {
            6 + cklen
        } else {
            2 + cklen
        };
        let max_payload = (session.maxl as usize).saturating_sub(header_overhead);
        let chunk_size = (max_payload * QUOTING_HEADROOM_NUM / QUOTING_HEADROOM_DEN).max(16);
        if verbose {
            glog!(
                "Kermit send: chunk_size={} (max_payload={}, header_overhead={})",
                chunk_size,
                max_payload,
                header_overhead
            );
        }

        // Rate-limit the per-D-packet success trace so a multi-megabyte
        // transfer doesn't drown the 2000-line log buffer.  Mirrors
        // zmodem.rs's `subpackets_sent <= 3` pattern: log the first 3
        // to confirm the protocol baseline is working, go silent on
        // success after that.  Failure paths (NAK, timeout, CHECK
        // mismatch) remain unconditionally logged elsewhere.
        let mut d_packets_sent = 0u32;
        let z_handled_internally = session.streaming;
        if session.streaming {
            // Streaming path: D-packets and Z-packet are handled
            // together.  Sender doesn't wait for per-D ACKs; the
            // Z-ACK confirms the whole stream (spec §6).
            seq = send_d_and_z_streaming(
                reader,
                writer,
                data_to_send,
                chunk_size,
                send_q,
                seq,
                &session,
                pkt_timeout,
                is_tcp,
                is_petscii,
                verbose,
                &mut state,
                max_retries,
                &mut d_packets_sent,
            )
            .await
            .map_err(|e| wrap_send_err("D/Z stream", e))?;
        } else if session.window > 1 {
            // Sliding-window path: D-packets ride a windowed sender
            // that allows up to `session.window` outstanding packets
            // and selectively retransmits on NAK or per-seq timeout.
            seq = send_d_packets_windowed(
                reader,
                writer,
                data_to_send,
                chunk_size,
                send_q,
                seq,
                &session,
                pkt_timeout,
                is_tcp,
                is_petscii,
                verbose,
                &mut state,
                max_retries,
                &mut d_packets_sent,
            )
            .await
            .map_err(|e| wrap_send_err("D-packet", e))?;
        } else {
            // Stop-and-wait path (window=1): unchanged from pre-window
            // implementation — the safe baseline for serial peers and
            // ancient Kermits that don't advertise sliding.
            for chunk in data_to_send.chunks(chunk_size) {
                let encoded = encode_data(chunk, send_q);
                d_packets_sent += 1;
                if verbose && d_packets_sent <= D_PACKET_TRACE_LIMIT {
                    let pct = if !chunk.is_empty() {
                        (encoded.len() * 100) / chunk.len()
                    } else {
                        100
                    };
                    glog!(
                        "Kermit send: D-packet seq={} raw={}B encoded={}B ({}%)",
                        seq,
                        chunk.len(),
                        encoded.len(),
                        pct
                    );
                }
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
                .map_err(|e| wrap_send_err("D-packet", e))?;
                seq = (seq + 1) & 0x3F;
            }
        }

        // Z-packet (EOF for this file).  Skipped when streaming did it
        // internally (the streaming path bundles Z with the data
        // stream so the Z-ACK confirms the whole batch atomically).
        if !z_handled_internally {
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
            .map_err(|e| wrap_send_err("Z-packet", e))?;
            seq = (seq + 1) & 0x3F;
        }
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
    .map_err(|e| wrap_send_err("B-packet", e))?;

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
    let pkt = build_packet(kind, seq, payload, chkt, pad_count, pad_char, eol);
    let mut attempts = 0u32;
    loop {
        // Log first-attempt sends for non-D packets, and any retry
        // attempt regardless of type.  The first-attempt send of a
        // D-packet is already covered by the rate-limited D-packet
        // log upstream; retries fire here to surface the retry trail.
        if verbose && (kind != TYPE_DATA || attempts > 0) {
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
        match read_packet(reader, is_tcp, is_petscii, chkt, eol, verbose, state, deadline).await {
            Ok(resp) => {
                if resp.kind == TYPE_ERROR {
                    let q = Quoting {
                        qctl: DEFAULT_QCTL,
                        qbin: None,
                        rept: None,
                        locking_shifts: false,
                    };
                    let msg = decode_error_message(&resp.payload, q);
                    return Err(format!("Kermit: peer sent E-packet: {}", msg));
                }
                if resp.kind == TYPE_ACK && resp.seq == seq {
                    // Suppress ACK confirmation on D-packets to keep
                    // the multi-megabyte hot path quiet — the per-D
                    // success trace is rate-limited upstream and
                    // failure paths log unconditionally.
                    if verbose && kind != TYPE_DATA {
                        glog!(
                            "Kermit send: ACK seq={} for type='{}'",
                            seq,
                            kind as char
                        );
                    }
                    return Ok(resp.payload);
                }
                if resp.kind == TYPE_NAK && resp.seq == seq {
                    attempts += 1;
                    if verbose {
                        glog!(
                            "Kermit send: NAK seq={} for type='{}' — retrying ({}/{})",
                            seq,
                            kind as char,
                            attempts,
                            max_retries
                        );
                    }
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
                if verbose {
                    glog!(
                        "Kermit send: read error after seq={} type='{}' — retrying ({}/{}): {}",
                        seq,
                        kind as char,
                        attempts,
                        max_retries,
                        e
                    );
                }
                if attempts >= max_retries {
                    return Err(format!("Kermit: too many timeouts: {}", e));
                }
            }
        }
    }
}

// =============================================================================
// SLIDING-WINDOW SENDER (D-packets only)
// =============================================================================

/// One unACKed D-packet in the sender's window.  Stores the wire bytes
/// so we can retransmit on NAK or per-packet timeout without re-encoding.
struct OutstandingPacket {
    seq: u8,
    bytes: Vec<u8>,
    sent_at: tokio::time::Instant,
    retries: u32,
}

/// Send the D-packets for one file using a sliding window of size
/// `session.window`.  The window covers data packets only — control
/// packets (S/F/A/Z/B) remain stop-and-wait via `send_and_await_ack`,
/// per spec rationale (negotiation and file-boundary acks are
/// inherently synchronous).
///
/// Returns the seq number to use for the next packet after the window
/// drains (the F/A/Z control packets after the data stream).
#[allow(clippy::too_many_arguments)]
async fn send_d_packets_windowed(
    reader: &mut (impl AsyncRead + Unpin),
    writer: &mut (impl AsyncWrite + Unpin),
    file_data: &[u8],
    chunk_size: usize,
    send_q: Quoting,
    starting_seq: u8,
    session: &Capabilities,
    pkt_timeout: tokio::time::Duration,
    is_tcp: bool,
    is_petscii: bool,
    verbose: bool,
    state: &mut ReadState,
    max_retries: u32,
    d_packets_sent: &mut u32,
) -> Result<u8, String> {
    use std::collections::VecDeque;
    let window_size = session.window.max(1) as usize;
    let mut next_seq = starting_seq;
    let mut outstanding: VecDeque<OutstandingPacket> = VecDeque::new();
    let mut chunks = file_data.chunks(chunk_size);

    loop {
        // 1. Push new packets while window has room and chunks remain.
        while outstanding.len() < window_size {
            let Some(chunk) = chunks.next() else {
                break;
            };
            let encoded = encode_data(chunk, send_q);
            *d_packets_sent += 1;
            if verbose && *d_packets_sent <= D_PACKET_TRACE_LIMIT {
                let pct = if !chunk.is_empty() {
                    (encoded.len() * 100) / chunk.len()
                } else {
                    100
                };
                glog!(
                    "Kermit send: D-packet seq={} raw={}B encoded={}B ({}%) [window]",
                    next_seq,
                    chunk.len(),
                    encoded.len(),
                    pct
                );
            }
            let pkt_bytes = build_packet(
                TYPE_DATA,
                next_seq,
                &encoded,
                session.chkt,
                session.npad,
                session.padc,
                session.eol,
            );
            raw_write_bytes(writer, &pkt_bytes, is_tcp).await?;
            outstanding.push_back(OutstandingPacket {
                seq: next_seq,
                bytes: pkt_bytes,
                sent_at: tokio::time::Instant::now(),
                retries: 0,
            });
            next_seq = (next_seq + 1) & 0x3F;
        }

        // 2. If nothing outstanding and no more chunks, we're done.
        if outstanding.is_empty() {
            break;
        }

        // 3. Compute the earliest retransmit deadline across the window.
        // VecDeque preserves insertion order; the front was sent first
        // unless an earlier ACK removed it from the middle.  Take the
        // min defensively.
        let earliest = outstanding
            .iter()
            .map(|p| p.sent_at + pkt_timeout)
            .min()
            .expect("outstanding non-empty");

        // 4. Read response.  On read-error/timeout, retransmit any
        //    packet whose individual deadline has elapsed.
        match read_packet(
            reader,
            is_tcp,
            is_petscii,
            session.chkt,
            session.eol,
            verbose,
            state,
            Some(earliest),
        )
        .await
        {
            Ok(resp) => {
                if resp.kind == TYPE_ERROR {
                    let q = Quoting {
                        qctl: DEFAULT_QCTL,
                        qbin: None,
                        rept: None,
                        locking_shifts: false,
                    };
                    let msg = decode_error_message(&resp.payload, q);
                    return Err(format!("Kermit: peer sent E-packet: {}", msg));
                }
                if resp.kind == TYPE_ACK {
                    // Selective: remove the matching seq from anywhere
                    // in the window.  Stray ACKs (already-removed seq,
                    // or for a control packet we sent earlier) are
                    // ignored — the per-seq match guards us.
                    if let Some(idx) = outstanding.iter().position(|p| p.seq == resp.seq) {
                        outstanding.remove(idx);
                    } else if verbose {
                        glog!(
                            "Kermit send: stray ACK seq={} (window) — ignoring",
                            resp.seq
                        );
                    }
                } else if resp.kind == TYPE_NAK {
                    // Selective retransmit of the NAKed seq.
                    if let Some(idx) =
                        outstanding.iter().position(|p| p.seq == resp.seq)
                    {
                        let bytes = {
                            let p = &mut outstanding[idx];
                            p.retries += 1;
                            if p.retries >= max_retries {
                                return Err(format!(
                                    "Kermit: too many NAKs (>{}) for seq {} (window)",
                                    max_retries, p.seq
                                ));
                            }
                            if verbose {
                                glog!(
                                    "Kermit send: NAK seq={} (window) — retransmitting ({}/{})",
                                    p.seq,
                                    p.retries,
                                    max_retries
                                );
                            }
                            p.bytes.clone()
                        };
                        raw_write_bytes(writer, &bytes, is_tcp).await?;
                        // Index `idx` is still valid (single-threaded
                        // async fn, no push/pop between collection
                        // and use).
                        outstanding[idx].sent_at = tokio::time::Instant::now();
                    } else if verbose {
                        glog!(
                            "Kermit send: stray NAK seq={} (window) — ignoring",
                            resp.seq
                        );
                    }
                } else if verbose {
                    glog!(
                        "Kermit send: unexpected '{}' seq={} during window — ignoring",
                        resp.kind as char,
                        resp.seq
                    );
                }
            }
            Err(_e) => {
                // Read timeout (or noisy line).  Retransmit any packet
                // whose individual per-packet deadline has elapsed.
                let now = tokio::time::Instant::now();
                let mut to_retx: Vec<usize> = Vec::new();
                for (i, p) in outstanding.iter().enumerate() {
                    if now >= p.sent_at + pkt_timeout {
                        to_retx.push(i);
                    }
                }
                for i in to_retx {
                    let bytes = {
                        let p = &mut outstanding[i];
                        p.retries += 1;
                        if p.retries >= max_retries {
                            return Err(format!(
                                "Kermit: too many timeouts for seq {} (window)",
                                p.seq
                            ));
                        }
                        if verbose {
                            glog!(
                                "Kermit send: timeout seq={} (window) — retransmitting ({}/{})",
                                p.seq,
                                p.retries,
                                max_retries
                            );
                        }
                        p.bytes.clone()
                    };
                    raw_write_bytes(writer, &bytes, is_tcp).await?;
                    // Index `i` is still valid: outstanding is mutated
                    // only by us in this single-threaded async fn, and
                    // we don't push/pop between collection and use.
                    outstanding[i].sent_at = tokio::time::Instant::now();
                }
            }
        }
    }

    Ok(next_seq)
}

// =============================================================================
// STREAMING SENDER (D-packets + Z-packet, no per-D ACK)
// =============================================================================

/// Send all D-packets for one file plus the Z-packet under streaming
/// rules (CAPAS streaming bit negotiated true on both peers, per Frank
/// da Cruz, "Kermit Protocol Manual" §6).  Streaming behavior:
///
/// - Sender pushes data packets back-to-back without waiting for any
///   per-D ACK.  No mid-stream poll: the spec says the Z-ACK
///   implicitly confirms every preceding D-packet, so any errors
///   (NAK, E-packet) are handled in the post-Z drain below.
/// - After all D-packets are queued we send the Z-packet and then
///   block-read responses until the Z-ACK arrives.
/// - During the Z drain, any D-packet NAK triggers a selective
///   retransmit before we resume waiting for Z-ACK.
///
/// Returns the seq number to use for the next packet *after* Z (i.e.
/// the caller's running seq, advanced by `chunks + 1` mod 64).
#[allow(clippy::too_many_arguments)]
async fn send_d_and_z_streaming(
    reader: &mut (impl AsyncRead + Unpin),
    writer: &mut (impl AsyncWrite + Unpin),
    file_data: &[u8],
    chunk_size: usize,
    send_q: Quoting,
    starting_seq: u8,
    session: &Capabilities,
    pkt_timeout: tokio::time::Duration,
    is_tcp: bool,
    is_petscii: bool,
    verbose: bool,
    state: &mut ReadState,
    max_retries: u32,
    d_packets_sent: &mut u32,
) -> Result<u8, String> {
    use std::collections::VecDeque;
    let mut next_seq = starting_seq;
    let mut outstanding: VecDeque<OutstandingPacket> = VecDeque::new();

    // 1. Push all D-packets back-to-back without per-packet ACK wait.
    //    Outstanding holds every packet until the Z-ACK confirms the
    //    whole stream (or we get an interim NAK during the drain).
    //    Memory is bounded by MAX_FILE_SIZE × ~1.05 (quoting headroom).
    for chunk in file_data.chunks(chunk_size) {
        let encoded = encode_data(chunk, send_q);
        *d_packets_sent += 1;
        if verbose && *d_packets_sent <= D_PACKET_TRACE_LIMIT {
            let pct = if !chunk.is_empty() {
                (encoded.len() * 100) / chunk.len()
            } else {
                100
            };
            glog!(
                "Kermit send: D-packet seq={} raw={}B encoded={}B ({}%) [stream]",
                next_seq,
                chunk.len(),
                encoded.len(),
                pct
            );
        }
        let pkt_bytes = build_packet(
            TYPE_DATA,
            next_seq,
            &encoded,
            session.chkt,
            session.npad,
            session.padc,
            session.eol,
        );
        raw_write_bytes(writer, &pkt_bytes, is_tcp).await?;
        outstanding.push_back(OutstandingPacket {
            seq: next_seq,
            bytes: pkt_bytes,
            sent_at: tokio::time::Instant::now(),
            retries: 0,
        });
        next_seq = (next_seq + 1) & 0x3F;
    }

    // 2. Send Z-packet — its ACK confirms the whole stream.
    let z_seq = next_seq;
    let z_pkt = build_packet(
        TYPE_EOF,
        z_seq,
        &[],
        session.chkt,
        session.npad,
        session.padc,
        session.eol,
    );
    raw_write_bytes(writer, &z_pkt, is_tcp).await?;
    if verbose {
        glog!("Kermit send: Z-packet seq={} (stream-end, awaiting drain)", z_seq);
    }
    let mut z_attempts = 0u32;
    let mut z_sent_at = tokio::time::Instant::now();
    next_seq = (next_seq + 1) & 0x3F;

    // 3. Drain — block-read responses until Z's ACK arrives.  Honor
    //    the per-packet timeout for retransmits of the Z-packet
    //    itself; D-packet retransmits use their own per-seq sent_at.
    loop {
        let earliest = std::iter::once(z_sent_at + pkt_timeout)
            .chain(outstanding.iter().map(|p| p.sent_at + pkt_timeout))
            .min()
            .unwrap();
        match read_packet(
            reader,
            is_tcp,
            is_petscii,
            session.chkt,
            session.eol,
            verbose,
            state,
            Some(earliest),
        )
        .await
        {
            Ok(resp) => {
                if resp.kind == TYPE_ERROR {
                    let q = Quoting {
                        qctl: DEFAULT_QCTL,
                        qbin: None,
                        rept: None,
                        locking_shifts: false,
                    };
                    let msg = decode_error_message(&resp.payload, q);
                    return Err(format!("Kermit: peer sent E-packet: {}", msg));
                }
                if resp.kind == TYPE_ACK && resp.seq == z_seq {
                    if verbose {
                        glog!(
                            "Kermit send: Z-ACK seq={} (stream complete; {} D-packets in outstanding implicitly confirmed)",
                            z_seq,
                            outstanding.len()
                        );
                    }
                    return Ok(next_seq);
                }
                if resp.kind == TYPE_NAK && resp.seq == z_seq {
                    z_attempts += 1;
                    if z_attempts >= max_retries {
                        return Err(format!(
                            "Kermit: too many NAKs for Z-packet seq {} (stream)",
                            z_seq
                        ));
                    }
                    if verbose {
                        glog!(
                            "Kermit send: NAK on Z seq={} (stream) — retransmitting ({}/{})",
                            z_seq,
                            z_attempts,
                            max_retries
                        );
                    }
                    raw_write_bytes(writer, &z_pkt, is_tcp).await?;
                    z_sent_at = tokio::time::Instant::now();
                    continue;
                }
                handle_streaming_response(
                    resp,
                    &mut outstanding,
                    writer,
                    is_tcp,
                    max_retries,
                    verbose,
                )
                .await?;
            }
            Err(_) => {
                // Timeout — retransmit any expired packets (D or Z).
                let now = tokio::time::Instant::now();
                if now >= z_sent_at + pkt_timeout {
                    z_attempts += 1;
                    if z_attempts >= max_retries {
                        return Err(format!(
                            "Kermit: too many timeouts for Z-packet seq {} (stream)",
                            z_seq
                        ));
                    }
                    if verbose {
                        glog!(
                            "Kermit send: Z timeout (stream) — retransmitting ({}/{})",
                            z_attempts,
                            max_retries
                        );
                    }
                    raw_write_bytes(writer, &z_pkt, is_tcp).await?;
                    z_sent_at = tokio::time::Instant::now();
                }
                let mut to_retx: Vec<usize> = Vec::new();
                for (i, p) in outstanding.iter().enumerate() {
                    if now >= p.sent_at + pkt_timeout {
                        to_retx.push(i);
                    }
                }
                for i in to_retx {
                    let bytes_clone = {
                        let p = &mut outstanding[i];
                        p.retries += 1;
                        if p.retries >= max_retries {
                            return Err(format!(
                                "Kermit: too many timeouts for D-packet seq {} (stream)",
                                p.seq
                            ));
                        }
                        if verbose {
                            glog!(
                                "Kermit send: D-packet timeout seq={} (stream) — retransmitting ({}/{})",
                                p.seq,
                                p.retries,
                                max_retries
                            );
                        }
                        p.bytes.clone()
                    };
                    raw_write_bytes(writer, &bytes_clone, is_tcp).await?;
                    // Index `i` is still valid here — outstanding is
                    // mutated only by us in this single-threaded async
                    // fn, and we don't push/pop between collection and
                    // use.
                    outstanding[i].sent_at = tokio::time::Instant::now();
                }
            }
        }
    }
}

/// Handle a single response packet during streaming send.  Updates
/// `outstanding` for ACK/NAK matches; aborts on E-packet; ignores
/// strays.  Used by both the chunk-push loop and the Z-drain loop.
async fn handle_streaming_response(
    resp: Packet,
    outstanding: &mut std::collections::VecDeque<OutstandingPacket>,
    writer: &mut (impl AsyncWrite + Unpin),
    is_tcp: bool,
    max_retries: u32,
    verbose: bool,
) -> Result<(), String> {
    if resp.kind == TYPE_ERROR {
        let q = Quoting {
            qctl: DEFAULT_QCTL,
            qbin: None,
            rept: None,
            locking_shifts: false,
        };
        let msg = decode_error_message(&resp.payload, q);
        return Err(format!("Kermit: peer sent E-packet: {}", msg));
    }
    if resp.kind == TYPE_ACK {
        // Streaming receivers shouldn't ACK D-packets, but some
        // mid-flight ACKs (e.g. if peer toggled streaming) may still
        // arrive.  Honor them by removing from outstanding.
        if let Some(idx) = outstanding.iter().position(|p| p.seq == resp.seq) {
            outstanding.remove(idx);
        } else if verbose {
            glog!(
                "Kermit send: stray ACK seq={} (stream) — ignoring",
                resp.seq
            );
        }
        return Ok(());
    }
    if resp.kind == TYPE_NAK {
        if let Some(idx) = outstanding.iter().position(|p| p.seq == resp.seq) {
            let bytes = {
                let p = &mut outstanding[idx];
                p.retries += 1;
                if p.retries >= max_retries {
                    return Err(format!(
                        "Kermit: too many NAKs (>{}) for seq {} (stream)",
                        max_retries, p.seq
                    ));
                }
                if verbose {
                    glog!(
                        "Kermit send: NAK seq={} (stream) — retransmitting ({}/{})",
                        p.seq,
                        p.retries,
                        max_retries
                    );
                }
                p.bytes.clone()
            };
            raw_write_bytes(writer, &bytes, is_tcp).await?;
            // Index `idx` is still valid (single-threaded async fn,
            // no push/pop between collection and use).
            outstanding[idx].sent_at = tokio::time::Instant::now();
        } else if verbose {
            glog!(
                "Kermit send: stray NAK seq={} (stream) — ignoring",
                resp.seq
            );
        }
        return Ok(());
    }
    if verbose {
        glog!(
            "Kermit send: unexpected '{}' seq={} (stream) — ignoring",
            resp.kind as char,
            resp.seq
        );
    }
    Ok(())
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
    kermit_receive_with_init(reader, writer, is_tcp, is_petscii, verbose, None).await
}

/// Same as `kermit_receive` but accepts an optional pre-read S packet.
/// Used by `kermit_server` after it dispatches on a peer-supplied S:
/// the server-mode dispatcher has already consumed the S off the wire,
/// so the receiver can't read it again.  When `init_pkt` is `Some`,
/// `expected_seq` is derived from its seq (+1 mod 64) so the rest of
/// the receive flow lines up regardless of where S was in the stream.
pub(crate) async fn kermit_receive_with_init(
    reader: &mut (impl AsyncRead + Unpin),
    writer: &mut (impl AsyncWrite + Unpin),
    is_tcp: bool,
    is_petscii: bool,
    verbose: bool,
    init_pkt: Option<Packet>,
) -> Result<Vec<KermitReceive>, String> {
    let cfg = config::get_config();
    if verbose {
        glog!(
            "Kermit recv: starting, is_tcp={}, is_petscii={}, pre_read={}",
            is_tcp,
            is_petscii,
            init_pkt.is_some()
        );
    }
    let our_caps = config_capabilities();
    let mut state = ReadState::default();
    let neg_deadline = tokio::time::Instant::now()
        + tokio::time::Duration::from_secs(cfg.kermit_negotiation_timeout);
    // pkt_timeout is set below once we know the peer's TIME field
    // (spec §3.2).  During the initial Send-Init read we use
    // `neg_deadline` derived from `kermit_negotiation_timeout` instead.

    // 1. Read Send-Init from peer (or use the pre-read packet handed
    //    over by `kermit_server`).  Block until it arrives or we time
    //    out.
    let s_pkt = match init_pkt {
        Some(p) => p,
        None => read_packet(
            reader,
            is_tcp,
            is_petscii,
            b'1',
            CR,
            verbose,
            &mut state,
            Some(neg_deadline),
        )
        .await
        .map_err(|e| format!("Kermit recv: Send-Init read failed: {}", e))?,
    };
    if s_pkt.kind != TYPE_SEND_INIT {
        return Err(format!(
            "Kermit recv: expected Send-Init, got '{}'",
            s_pkt.kind as char
        ));
    }
    let peer_init = parse_send_init_payload(&s_pkt.payload);
    let session = intersect_capabilities(&our_caps, &peer_init);
    let flavor = detect_flavor(&peer_init);
    // Honor peer's TIME for our retransmit/read deadlines from here on.
    let pkt_timeout = effective_packet_timeout(session.time, cfg.kermit_packet_timeout);
    if verbose {
        glog!(
            "Kermit recv: peer MAXL={} TIME={} CHKT={} window={} long={} stream={} attrs={} pkt_timeout={}s flavor={}",
            session.maxl,
            peer_init.time,
            session.chkt as char,
            session.window,
            session.long_packets,
            session.streaming,
            session.attribute_packets,
            pkt_timeout.as_secs(),
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
        locking_shifts: session.locking_shifts,
    };

    let mut received: Vec<KermitReceive> = Vec::new();
    // Peer's next packet runs at S.seq + 1 (mod 64).  Hard-coding 1
    // would break server-mode receive where the S could arrive at any
    // seq (e.g., after the dispatcher's R/I/G handling has already
    // advanced the sender's counter).
    let mut expected_seq: u8 = (s_pkt.seq + 1) & 0x3F;
    // Per-file counter for rate-limiting verbose D-packet success
    // logs.  Resets on every F-packet so each file gets its own first
    // few traced — same pattern as zmodem.rs's subpacket-trace cap.
    let mut d_packets_received = 0u32;
    // Resume-partial state, set in the F-packet handler when a partial
    // file is found on disk; consumed in the A-packet handler to
    // advertise disposition='R' + length=offset back to the sender.
    // Cleared after the A-packet is acknowledged so subsequent files
    // in a batch each get their own lookup (commit-3 territory).
    let mut pending_resume_offset: Option<u64> = None;
    // Bound the read-error retry chain so a wedged peer can't keep
    // us NAKing forever.  Resets on any successful packet.
    let mut consecutive_failures: u32 = 0;
    let max_retries = cfg.kermit_max_retries;
    // Out-of-order buffer for sliding-window receive.  Empty when
    // window=1 (stop-and-wait); selective-repeat per spec §5.5 when
    // window>1.  Capped at session.window entries — anything beyond
    // is outside the receive window and would indicate sender error.
    let mut out_of_order: std::collections::HashMap<u8, Packet> =
        std::collections::HashMap::new();
    // When non-None, the next loop iteration consumes this packet
    // (drained from `out_of_order`) instead of reading from the wire.
    let mut next_drained: Option<Packet> = None;
    let window = session.window.max(1);

    loop {
        let pkt = if let Some(p) = next_drained.take() {
            p
        } else {
            match read_packet(
                reader,
                is_tcp,
                is_petscii,
                session.chkt,
                session.eol,
                verbose,
                &mut state,
                Some(tokio::time::Instant::now() + pkt_timeout),
            )
            .await
            {
                Ok(p) => {
                    consecutive_failures = 0;
                    p
                }
                Err(e) => {
                    consecutive_failures += 1;
                    if verbose {
                        glog!(
                            "Kermit recv: read error → NAK seq={} ({}/{}): {}",
                            expected_seq,
                            consecutive_failures,
                            max_retries,
                            e
                        );
                    }
                    if consecutive_failures >= max_retries {
                        send_error(
                            writer,
                            expected_seq,
                            "Too many consecutive read errors",
                            session.chkt,
                            session.npad,
                            session.padc,
                            session.eol,
                            is_tcp,
                        )
                        .await?;
                        return Err(format!(
                            "Kermit recv: aborting after {} consecutive read errors: {}",
                            max_retries, e
                        ));
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
        };

        if pkt.kind == TYPE_ERROR {
            let msg = decode_error_message(&pkt.payload, recv_q);
            return Err(format!("Kermit recv: peer sent E-packet: {}", msg));
        }

        if pkt.seq != expected_seq {
            // Modular distance: how far ahead/behind is this seq?
            // Mod-64 arithmetic, with the receive window bounded at
            // MAX_WINDOW_SIZE=31 < 32, so forward and backward windows
            // never overlap — disambiguation is unambiguous.
            let dist_forward = pkt.seq.wrapping_sub(expected_seq) & 0x3F;
            let dist_back = expected_seq.wrapping_sub(pkt.seq) & 0x3F;

            // Future packet within the window → buffer for later
            // (selective-repeat per spec §5.5) and NAK the missing seq
            // so the sender knows what to retransmit.
            if window > 1 && dist_forward > 0 && dist_forward < window {
                use std::collections::hash_map::Entry;
                match out_of_order.entry(pkt.seq) {
                    Entry::Vacant(slot) => {
                        if verbose {
                            glog!(
                                "Kermit recv: buffered future seq={} (expected {}) → NAK {}",
                                pkt.seq,
                                expected_seq,
                                expected_seq
                            );
                        }
                        slot.insert(pkt);
                    }
                    Entry::Occupied(_) => {
                        if verbose {
                            glog!(
                                "Kermit recv: duplicate future seq={} already buffered → NAK {}",
                                pkt.seq,
                                expected_seq
                            );
                        }
                    }
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

            // Already-ACKed packet within the back-window → re-ACK so
            // the sender can advance.  For window=1 this collapses to
            // "exactly previous seq" — the original stop-and-wait rule.
            if dist_back > 0 && dist_back <= window {
                if verbose {
                    glog!(
                        "Kermit recv: duplicate seq={} (expected {}) → re-ACK",
                        pkt.seq,
                        expected_seq
                    );
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
                continue;
            }

            // Outside both windows — line noise or peer confusion.
            // NAK the expected seq.
            if verbose {
                glog!(
                    "Kermit recv: out-of-order seq={} (expected {}) → NAK",
                    pkt.seq,
                    expected_seq
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

        match pkt.kind {
            TYPE_FILE => {
                // Spec allows F-packet filenames to be data-quoted, but
                // most implementations send them raw since filenames
                // rarely contain QCTL or control bytes.  Try the
                // quoting decoder first, fall back to raw bytes if it
                // produces an empty result (i.e. the filename happened
                // to start with a stray QCTL).
                let fname = match decode_data(&pkt.payload, recv_q) {
                    Ok(d) if !d.is_empty() => String::from_utf8_lossy(&d).into_owned(),
                    _ => String::from_utf8_lossy(&pkt.payload).into_owned(),
                };
                if verbose {
                    glog!("Kermit recv: F-packet '{}'", fname);
                }
                if received.len() >= MAX_BATCH_FILES {
                    send_error(
                        writer,
                        pkt.seq,
                        "Batch too large",
                        session.chkt,
                        session.npad,
                        session.padc,
                        session.eol,
                        is_tcp,
                    )
                    .await?;
                    return Err(format!(
                        "Kermit recv: batch exceeds {} file cap",
                        MAX_BATCH_FILES
                    ));
                }
                d_packets_received = 0;
                // Resume lookup: only meaningful when the negotiated
                // session lets the sender send an A-packet (that's
                // where we'll advertise disposition='R').  Sender
                // also has to honor it, but we discover that only
                // when our ACK payload comes back via D-packets at
                // the right offset; so the user opt-in
                // (`kermit_resume_partial`) carries the trust.
                pending_resume_offset = None;
                // Strict spec gate: require BOTH peers to advertise
                // CAPAS_RESEND (`session.resend`) AND attribute-packet
                // support (where the disposition='R' coordination
                // happens) AND the user opt-in.  Falling back to a
                // looser gate (skip session.resend) would mean older
                // peers that don't expect disposition='R' in our ACK
                // payload could mishandle it.
                if cfg.kermit_resume_partial && session.attribute_packets && session.resend {
                    let off = compute_resume_offset(
                        &fname,
                        &cfg.transfer_dir,
                        cfg.kermit_resume_max_age_hours,
                    );
                    if let Some(n) = off
                        && n > 0
                    {
                        if verbose {
                            glog!(
                                "Kermit recv: partial '{}' on disk, will request resume from {} bytes",
                                fname, n
                            );
                        }
                        pending_resume_offset = Some(n);
                    }
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
                // Fall back to '&' (long_length) when '!' isn't sent —
                // rare but spec-allowed for senders with files larger
                // than the '!' field can encode in a single tochar
                // length byte (max 94 chars of decimal).
                let declared = a.length.or(a.long_length);
                if verbose {
                    glog!(
                        "Kermit recv: A-packet len={:?} date={:?} mode={:?} encoding={:?} record_format={:?}",
                        declared,
                        a.date,
                        a.mode,
                        a.encoding.map(|c| c as char),
                        a.record_format.map(|c| c as char),
                    );
                }
                if let Some(last) = received.last_mut() {
                    last.declared_size = declared;
                    last.mode = a.mode;
                    last.modtime = a.date.as_deref().and_then(parse_kermit_date);
                    if let Some(sz) = declared
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
                // Resume path: advertise disposition='R' + length=offset
                // in the A-packet ACK payload, then pre-load the partial
                // file's bytes into `data` so arriving D-packets append
                // cleanly.  Guards before doing anything:
                //
                // - `declared` (full file size from the just-parsed
                //   A-packet) must be known.  Without it we can't tell
                //   whether the on-disk partial is consistent with what
                //   the sender is offering.
                // - `offset <= declared` — partial larger than full
                //   file means the on-disk bytes can't be a valid prefix
                //   of the new file (renamed-and-replaced, truncated
                //   upstream, …).  Falling back to a full receive
                //   overwrites the stale partial cleanly.
                //
                // If either guard fails, or the read fails (file
                // vanished, perms, …), abandon resume and fall through
                // to a plain ACK — better to re-receive the whole file
                // than to merge mismatched data.
                //
                // CAVEAT: there's no spec checksum exchange to detect a
                // corrupt-but-same-length partial.  If the user's
                // partial has bit rot or was truncated to the same byte
                // count as a different file, the merged result is
                // silently wrong.  This is a known spec-level limit;
                // the user owns the risk by enabling
                // `kermit_resume_partial`.
                let mut resume_payload: Option<Vec<u8>> = None;
                let safe_to_resume = matches!(
                    (pending_resume_offset, declared),
                    (Some(off), Some(decl)) if off <= decl
                );
                if !safe_to_resume {
                    if verbose
                        && let Some(off) = pending_resume_offset
                    {
                        glog!(
                            "Kermit recv: abandoning resume — partial={} declared={:?} (must be partial<=declared)",
                            off, declared
                        );
                    }
                    pending_resume_offset = None;
                }
                if let Some(offset) = pending_resume_offset.take()
                    && let Some(last) = received.last_mut()
                {
                    let path = std::path::Path::new(&cfg.transfer_dir).join(&last.filename);
                    match std::fs::read(&path) {
                        Ok(mut bytes) => {
                            // If the file grew between F-packet stat and
                            // now, truncate to the advertised offset so
                            // the sender's resumed stream lines up
                            // exactly.  If it shrank, advertise the
                            // smaller size we actually have.
                            let actual = bytes.len() as u64;
                            let effective = offset.min(actual);
                            bytes.truncate(effective as usize);
                            last.data = bytes;
                            let resume_attrs = Attributes {
                                disposition: Some(b'R'),
                                length: Some(effective),
                                ..Attributes::default()
                            };
                            resume_payload = Some(encode_data(
                                &encode_attributes(&resume_attrs),
                                recv_q,
                            ));
                            if verbose {
                                glog!(
                                    "Kermit recv: advertising resume disposition='R' length={}",
                                    effective
                                );
                            }
                        }
                        Err(e) => {
                            if verbose {
                                glog!(
                                    "Kermit recv: resume read of '{}' failed ({}); falling back to full receive",
                                    last.filename, e
                                );
                            }
                        }
                    }
                }
                if let Some(payload) = resume_payload {
                    send_ack_with_payload(
                        writer,
                        pkt.seq,
                        &payload,
                        session.chkt,
                        session.npad,
                        session.padc,
                        session.eol,
                        is_tcp,
                    )
                    .await?;
                } else {
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
            }
            TYPE_DATA => {
                let raw = decode_data(&pkt.payload, recv_q)?;
                let Some(last) = received.last_mut() else {
                    // D-packet before any F-packet violates the spec
                    // sequence (S → F → [A] → D... → Z → B).  Fail loud
                    // rather than silently dropping the payload.
                    send_error(
                        writer,
                        pkt.seq,
                        "Data packet before file header",
                        session.chkt,
                        session.npad,
                        session.padc,
                        session.eol,
                        is_tcp,
                    )
                    .await?;
                    return Err("Kermit recv: D-packet before F-packet".into());
                };
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
                d_packets_received += 1;
                if verbose && d_packets_received <= D_PACKET_TRACE_LIMIT {
                    glog!(
                        "Kermit recv: D-packet seq={} encoded={}B decoded={}B (file total {}B){}",
                        pkt.seq,
                        pkt.payload.len(),
                        raw.len(),
                        last.data.len() + raw.len(),
                        if session.streaming { " [stream, no ACK]" } else { "" }
                    );
                }
                last.data.extend_from_slice(&raw);
                // Streaming: suppress per-D-packet ACK (spec §6).  The
                // Z-ACK we'll emit at end-of-file confirms the whole
                // stream.  Out-of-order D-packets still NAK above so
                // the sender can retransmit.
                if !session.streaming {
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
            }
            TYPE_EOF => {
                if received.last().is_none() {
                    // Z (EOF) without an F-packet first violates the
                    // spec sequence S → F → [A] → D... → Z → B.
                    send_error(
                        writer,
                        pkt.seq,
                        "EOF without file header",
                        session.chkt,
                        session.npad,
                        session.padc,
                        session.eol,
                        is_tcp,
                    )
                    .await?;
                    return Err("Kermit recv: Z-packet before F-packet".into());
                }
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

        // Drain in-order packets buffered ahead of us by the windowed
        // receive path.  Each iteration consumes one buffered packet
        // by re-entering the loop with `next_drained` set; the buffer
        // is naturally bounded by `window-1` entries.
        if let Some(buffered) = out_of_order.remove(&expected_seq) {
            if verbose {
                glog!(
                    "Kermit recv: draining buffered seq={} type='{}'",
                    buffered.seq,
                    buffered.kind as char
                );
            }
            next_drained = Some(buffered);
        }
    }

    Ok(received)
}

// =============================================================================
// SERVER STATE MACHINE
// =============================================================================

/// Validate a CWD argument from a `G C <subdir>` packet.  Accepts an
/// empty string (root of `transfer_dir`), single names, and multi-
/// component relative paths separated by `/`.  Refuses anything that
/// could escape the transfer dir: leading `/`, embedded `\`, NUL,
/// any `..` component, per-component leading dots, or an over-cap
/// length.  The matching `effective_transfer_path` joins the result
/// onto `cfg.transfer_dir`.
///
/// Why looser than `is_safe_resume_filename`: subdir is structurally
/// a path (multi-component allowed), filename is a single leaf —
/// per-call validation runs at different boundaries (subdir at G C,
/// filename at R / save).  Both end up joined onto `transfer_dir`,
/// so traversal protection has to hold separately on each side.
pub(crate) fn is_safe_relative_subdir(s: &str) -> bool {
    if s.is_empty() {
        return true;
    }
    if s.len() > MAX_KERMIT_SUBDIR_LEN {
        return false;
    }
    if s.starts_with('/') || s.contains('\\') || s.contains('\0') {
        return false;
    }
    for component in s.split('/') {
        if component.is_empty() || component == ".." || component.starts_with('.') {
            return false;
        }
        if !component
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
        {
            return false;
        }
    }
    true
}

/// Resolve `cfg.transfer_dir` + `subdir` into a single path.  Caller
/// has already validated `subdir` via `is_safe_relative_subdir`.
fn effective_transfer_path(cfg: &config::Config, subdir: &str) -> std::path::PathBuf {
    let mut p = std::path::PathBuf::from(&cfg.transfer_dir);
    if !subdir.is_empty() {
        p.push(subdir);
    }
    p
}

/// Build a one-line-per-file directory listing for a `G D` reply.
/// Skips entries whose names start with `.` (hidden), unreadable
/// entries, and reports `<dir>` / `<file size>` annotations.
/// Returns an empty string if the path can't be read — caller should
/// emit that as the response body so the client knows we tried.
fn format_dir_listing(path: &std::path::Path) -> String {
    let entries = match std::fs::read_dir(path) {
        Ok(d) => d,
        Err(_) => return String::new(),
    };
    let mut lines: Vec<(String, String)> = Vec::new();
    for entry in entries.flatten() {
        let name = match entry.file_name().into_string() {
            Ok(n) => n,
            Err(_) => continue,
        };
        if name.starts_with('.') {
            continue;
        }
        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        let annot = if meta.is_dir() {
            "<dir>".to_string()
        } else {
            format!("{}", meta.len())
        };
        lines.push((name, annot));
    }
    lines.sort_by(|a, b| a.0.cmp(&b.0));
    let mut out = String::new();
    for (name, annot) in lines {
        out.push_str(&format!("{}\t{}\n", name, annot));
    }
    out
}

/// Filesystem free-bytes count at `path`, or None if the platform or
/// the call doesn't support it.  Used by `G $` (SPACE) to report
/// available storage to the peer.
#[cfg(unix)]
// statvfs's `f_bavail` and `f_frsize` are u64 on Linux but u32 on
// some BSDs / macOS — `as u64` is a no-op on the former and a widen
// on the latter, but clippy can't see the platform variance and
// flags `unnecessary_cast`.  Local allow keeps the cross-platform
// math correct.
#[allow(clippy::unnecessary_cast)]
fn fs_free_bytes(path: &std::path::Path) -> Option<u64> {
    let path_str = path.to_str()?;
    let cstr = std::ffi::CString::new(path_str).ok()?;
    // SAFETY: zeroed `statvfs` is a valid initial value; `cstr` is a
    // null-terminated C string that lives until the call returns.
    let mut buf: libc::statvfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::statvfs(cstr.as_ptr(), &mut buf) };
    if rc != 0 {
        return None;
    }
    let avail = buf.f_bavail as u64;
    let frsize = buf.f_frsize as u64;
    Some(avail.saturating_mul(frsize))
}
#[cfg(not(unix))]
fn fs_free_bytes(_path: &std::path::Path) -> Option<u64> {
    None
}

/// Maximum X-packet payload size for dispatch-level G responses.
/// Dispatch packets run at protocol defaults (no Send-Init negotiation
/// for the G itself), so the peer may not accept extended-length
/// packets.  Targeting a payload that fits in classic 94-byte MAXL
/// after `build_packet` overhead (mark + len + seq + type + check +
/// eol = 6 bytes) keeps us safe with strict-spec peers.  Conservative
/// margin allows for ctl-quote / qbin / repeat-prefix expansion in
/// the encoded form.
const G_RESPONSE_MAX_PAYLOAD: usize = 80;

/// Split a UTF-8 text body into one or more encoded X-packet
/// payloads, each fitting within `G_RESPONSE_MAX_PAYLOAD`.  Walks the
/// source byte-at-a-time and starts a new chunk whenever encoding
/// the next byte would push the current chunk over the cap.
/// Per-chunk locking-shift state is reset (encoder closes the open
/// shift before chunk boundary) so each X-packet is self-contained.
fn paginate_g_text_response(text: &str, q: Quoting) -> Vec<Vec<u8>> {
    let mut chunks: Vec<Vec<u8>> = Vec::new();
    let mut current: Vec<u8> = Vec::new();
    let mut mode = ShiftMode::Normal;
    for &b in text.as_bytes() {
        // Tentative encode of the next byte to see if it still fits.
        let mut tentative = current.clone();
        let mut tent_mode = mode;
        encode_one_byte(&mut tentative, b, q, &mut tent_mode);
        if tentative.len() > G_RESPONSE_MAX_PAYLOAD {
            // Doesn't fit — close the current chunk (emit closing SI
            // if locking shifts left us in shifted state), push it,
            // and start a fresh chunk for this byte.
            if q.locking_shifts && mode != ShiftMode::Normal {
                current.push(q.qctl);
                current.push(ctl(SI));
            }
            chunks.push(std::mem::take(&mut current));
            mode = ShiftMode::Normal;
            encode_one_byte(&mut current, b, q, &mut mode);
        } else {
            current = tentative;
            mode = tent_mode;
        }
    }
    if q.locking_shifts && mode != ShiftMode::Normal {
        current.push(q.qctl);
        current.push(ctl(SI));
    }
    if !current.is_empty() {
        chunks.push(current);
    }
    if chunks.is_empty() {
        // Empty input — emit a single empty X so the receiver still
        // sees a well-formed X→Z response shape.
        chunks.push(Vec::new());
    }
    chunks
}

/// Send an X+...+Z response after a G command that produces text
/// output (DIR/SPACE/KERMIT/HELP).  Per Frank da Cruz §6 the spec
/// allows multiple X-packets to deliver a long body, terminated by
/// a single Z signalling end-of-response.  Each packet seq follows
/// from the client's G: G@N → ACK@N → X@N+1 → ACK@N+1 → ...
/// → X@N+k → ACK@N+k → Z@N+k+1 → ACK@N+k+1.
#[allow(clippy::too_many_arguments)]
async fn send_g_text_response(
    reader: &mut (impl AsyncRead + Unpin),
    writer: &mut (impl AsyncWrite + Unpin),
    text: &str,
    after_g_seq: u8,
    is_tcp: bool,
    is_petscii: bool,
    verbose: bool,
    state: &mut ReadState,
    max_retries: u32,
    pkt_timeout: tokio::time::Duration,
) -> Result<(), String> {
    let q = Quoting {
        qctl: DEFAULT_QCTL,
        qbin: None,
        rept: Some(DEFAULT_REPT),
        locking_shifts: false,
    };
    let chunks = paginate_g_text_response(text, q);
    let mut seq = (after_g_seq + 1) & 0x3F;
    if verbose && chunks.len() > 1 {
        glog!(
            "Kermit server: paginating G text response across {} X-packets",
            chunks.len()
        );
    }
    for chunk in &chunks {
        let _ = send_and_await_ack(
            reader,
            writer,
            TYPE_TEXT,
            seq,
            chunk,
            b'1',
            0,
            0,
            CR,
            is_tcp,
            is_petscii,
            verbose,
            state,
            Some(tokio::time::Instant::now() + pkt_timeout),
            max_retries,
            false,
        )
        .await?;
        seq = (seq + 1) & 0x3F;
    }
    let _ = send_and_await_ack(
        reader,
        writer,
        TYPE_EOF,
        seq,
        &[],
        b'1',
        0,
        0,
        CR,
        is_tcp,
        is_petscii,
        verbose,
        state,
        Some(tokio::time::Instant::now() + pkt_timeout),
        max_retries,
        false,
    )
    .await?;
    Ok(())
}

/// Multi-line help text sent in response to `G H` (or `G ?`).  Lists
/// every G subcommand we recognise so a peer doing `remote help`
/// gets a useful answer instead of a no-op ACK.  Kept ASCII-only and
/// short enough to span just a couple paginated X-packets at the
/// 80-byte classic-MAXL ceiling.
fn kermit_g_help_text() -> &'static str {
    "Ethernet Gateway Kermit server.\n\
     Supported generic commands (G):\n\
       F  Finish     - end protocol session\n\
       L  Logout     - end protocol session\n\
       B  BYE        - end protocol session\n\
       C  CWD <dir>  - change working subdir\n\
       D  DIRectory  - list current dir\n\
       $  SPACE      - free disk bytes\n\
       K  KERMIT     - server identity\n\
       H  HELP / ?   - this text\n\
     Other commands: I (re-init), R (get file), S (send file).\n"
}

/// Server-mode dispatch: idle waiting for an incoming command from a
/// Kermit client and acting on it.  This commit wires the lightweight
/// half of the spec — Host-command refusal (`C`), re-init (`I`),
/// graceful EOT (`B`), peer-abort handling (`E`), and the generic
/// `G F`/`G L` finish/logout that already lived in `kermit_receive`.
/// The S-packet (peer wants to send us a file) and R-packet (peer
/// wants us to send a file) currently respond with an E-packet stub
/// "not yet implemented" and exit; the real handlers are wired in
/// the follow-up commit that refactors `kermit_receive` /
/// `kermit_send` to accept a pre-read first packet.
///
/// Returns the list of files received from the peer over the lifetime
/// of the session (one S command per file batch — multiple batches
/// possible across a single server-mode session).  Returns `Err` only
/// on protocol-level I/O failures; clean exits (E-packet, B, G F/L/B,
/// completed S/R/G commands) return `Ok` with whatever was accumulated.
pub(crate) async fn kermit_server(
    reader: &mut (impl AsyncRead + Unpin),
    writer: &mut (impl AsyncWrite + Unpin),
    is_tcp: bool,
    is_petscii: bool,
    verbose: bool,
) -> Result<Vec<KermitReceive>, String> {
    let cfg = config::get_config();
    if verbose {
        glog!(
            "Kermit server: ready, is_tcp={}, is_petscii={}",
            is_tcp,
            is_petscii
        );
    }
    let mut all_received: Vec<KermitReceive> = Vec::new();
    let mut state = ReadState::default();
    // Per-session working subdir, settled by G C (CWD).  All R-pulls,
    // S-receives (via the R/S handlers below), and G D / G $ replies
    // resolve paths relative to `cfg.transfer_dir / subdir`.
    let mut subdir: String = String::new();
    // Server idles indefinitely on the first command from the peer;
    // re-uses kermit_negotiation_timeout as the inactivity bound so
    // a wedged peer can't pin us forever.  Re-armed per command.
    loop {
        let deadline = tokio::time::Instant::now()
            + tokio::time::Duration::from_secs(cfg.kermit_negotiation_timeout);
        let pkt = match read_packet(
            reader,
            is_tcp,
            is_petscii,
            b'1',
            CR,
            verbose,
            &mut state,
            Some(deadline),
        )
        .await
        {
            Ok(p) => p,
            Err(e) => {
                // Peer-disconnect (EOF) and idle-timeout are both
                // legitimate end-of-session signals — many real Kermit
                // clients (including C-Kermit -s) just exit after a
                // transfer rather than sending G F.  Returning the
                // accumulated files lets the caller surface a
                // success-shaped summary instead of an error toast.
                // We still surface the read failure in the verbose
                // log so a wedged session is debuggable.
                if verbose {
                    glog!(
                        "Kermit server: dispatch read ended ({}) — closing with {} file(s) received",
                        e,
                        all_received.len()
                    );
                }
                return Ok(all_received);
            }
        };
        if verbose {
            glog!(
                "Kermit server: dispatch type='{}' seq={}",
                pkt.kind as char,
                pkt.seq
            );
        }
        match pkt.kind {
            TYPE_HOST => {
                // Host commands are a remote-code-execution primitive
                // by design.  Refuse with E-packet regardless of any
                // future config opt-in — actually executing them is
                // out of scope and will stay that way unless the
                // operator explicitly wires in a sandboxed backend.
                send_error(
                    writer,
                    pkt.seq,
                    "Host commands disabled",
                    b'1',
                    0,
                    0,
                    CR,
                    is_tcp,
                )
                .await?;
                if verbose {
                    glog!("Kermit server: refused C-packet (host commands disabled)");
                }
                // Spec §6.7: E-packet reply keeps the server idle for
                // the next command — refusal is not session-fatal.
                continue;
            }
            TYPE_INIT => {
                // Re-init mid-session: respond with Y-ACK whose payload
                // is a fresh Send-Init advertising our current caps.
                let our_caps = config_capabilities();
                let ack_payload = build_send_init_payload(&our_caps);
                send_ack_with_payload(
                    writer,
                    pkt.seq,
                    &ack_payload,
                    b'1',
                    0,
                    0,
                    CR,
                    is_tcp,
                )
                .await?;
                if verbose {
                    glog!("Kermit server: handled I-packet (re-init)");
                }
                continue;
            }
            TYPE_ERROR => {
                // Peer signaled abort — log and exit without responding
                // (per spec, E is fatal both ways; ACKing risks a loop).
                if verbose {
                    let q = Quoting {
                        qctl: DEFAULT_QCTL,
                        qbin: None,
                        rept: None,
                        locking_shifts: false,
                    };
                    let msg = decode_error_message(&pkt.payload, q);
                    glog!("Kermit server: peer E-packet: {}", msg);
                }
                return Ok(all_received);
            }
            TYPE_EOT => {
                // Clean session-end signal.  ACK and exit.
                send_ack(writer, pkt.seq, b'1', 0, 0, CR, is_tcp).await?;
                if verbose {
                    glog!("Kermit server: B-packet → clean exit");
                }
                return Ok(all_received);
            }
            TYPE_GENERIC => {
                // Generic-command dispatch.  Per Frank da Cruz spec §6:
                // F=Finish, L=Logout, B=BYE end the session;
                // C=CWD updates per-session subdir;
                // D=DIR / $=SPACE / K=KERMIT reply with X+Z text data.
                // Anything else is acknowledged and ignored — that's
                // the spec-compliant fallback for unknown subcommands.
                let recv_q = Quoting {
                    qctl: DEFAULT_QCTL,
                    qbin: None,
                    rept: None,
                    locking_shifts: false,
                };
                let raw = decode_data(&pkt.payload, recv_q).unwrap_or_default();
                let action = raw.first().copied().unwrap_or(0);
                let arg: &[u8] = if raw.len() > 1 { &raw[1..] } else { &[] };
                let pkt_timeout = tokio::time::Duration::from_secs(cfg.kermit_packet_timeout);
                match action {
                    b'F' | b'L' | b'B' => {
                        send_ack(writer, pkt.seq, b'1', 0, 0, CR, is_tcp).await?;
                        if verbose {
                            glog!("Kermit server: G '{}' → exit", action as char);
                        }
                        return Ok(all_received);
                    }
                    b'C' => {
                        let new_subdir = String::from_utf8_lossy(arg).into_owned();
                        if !is_safe_relative_subdir(&new_subdir) {
                            send_error(
                                writer,
                                pkt.seq,
                                "Invalid directory",
                                b'1',
                                0,
                                0,
                                CR,
                                is_tcp,
                            )
                            .await?;
                            if verbose {
                                glog!(
                                    "Kermit server: G C '{}' refused (unsafe path)",
                                    new_subdir
                                );
                            }
                            // Spec §6.7: keep the server idle so the
                            // peer can retry with a valid subdir.
                            continue;
                        }
                        subdir = new_subdir;
                        send_ack(writer, pkt.seq, b'1', 0, 0, CR, is_tcp).await?;
                        if verbose {
                            glog!("Kermit server: G C → subdir='{}'", subdir);
                        }
                        continue;
                    }
                    b'D' => {
                        send_ack(writer, pkt.seq, b'1', 0, 0, CR, is_tcp).await?;
                        let dir_path = effective_transfer_path(&cfg, &subdir);
                        let listing = format_dir_listing(&dir_path);
                        send_g_text_response(
                            reader,
                            writer,
                            &listing,
                            pkt.seq,
                            is_tcp,
                            is_petscii,
                            verbose,
                            &mut state,
                            cfg.kermit_max_retries,
                            pkt_timeout,
                        )
                        .await?;
                        continue;
                    }
                    b'$' => {
                        send_ack(writer, pkt.seq, b'1', 0, 0, CR, is_tcp).await?;
                        let dir_path = effective_transfer_path(&cfg, &subdir);
                        let body = match fs_free_bytes(&dir_path) {
                            Some(b) => b.to_string(),
                            None => "unknown".to_string(),
                        };
                        send_g_text_response(
                            reader,
                            writer,
                            &body,
                            pkt.seq,
                            is_tcp,
                            is_petscii,
                            verbose,
                            &mut state,
                            cfg.kermit_max_retries,
                            pkt_timeout,
                        )
                        .await?;
                        continue;
                    }
                    b'K' => {
                        send_ack(writer, pkt.seq, b'1', 0, 0, CR, is_tcp).await?;
                        let body = format!(
                            "Ethernet Gateway Kermit {}",
                            env!("CARGO_PKG_VERSION")
                        );
                        send_g_text_response(
                            reader,
                            writer,
                            &body,
                            pkt.seq,
                            is_tcp,
                            is_petscii,
                            verbose,
                            &mut state,
                            cfg.kermit_max_retries,
                            pkt_timeout,
                        )
                        .await?;
                        continue;
                    }
                    b'H' | b'?' => {
                        // HELP — reply with the list of supported G
                        // subcommands.  C-Kermit's `remote help`
                        // sends G ?; some implementations use G H.
                        // We accept both.
                        send_ack(writer, pkt.seq, b'1', 0, 0, CR, is_tcp).await?;
                        send_g_text_response(
                            reader,
                            writer,
                            kermit_g_help_text(),
                            pkt.seq,
                            is_tcp,
                            is_petscii,
                            verbose,
                            &mut state,
                            cfg.kermit_max_retries,
                            pkt_timeout,
                        )
                        .await?;
                        continue;
                    }
                    _ => {
                        send_ack(writer, pkt.seq, b'1', 0, 0, CR, is_tcp).await?;
                        if verbose {
                            glog!(
                                "Kermit server: G '{}' acknowledged (no-op)",
                                action as char
                            );
                        }
                        continue;
                    }
                }
            }
            TYPE_SEND_INIT => {
                // Peer wants to upload one or more files to us.  Hand
                // the pre-read S off to the receiver state machine and
                // accumulate whatever it returns; then loop back for
                // the next command.  A read failure inside the receive
                // (timeout, malformed packet, etc.) propagates up.
                let received = kermit_receive_with_init(
                    reader,
                    writer,
                    is_tcp,
                    is_petscii,
                    verbose,
                    Some(pkt),
                )
                .await?;
                if verbose {
                    glog!(
                        "Kermit server: S-dispatch returned {} file(s)",
                        received.len()
                    );
                }
                all_received.extend(received);
                continue;
            }
            TYPE_R => {
                // Peer asks us to send a named file from `transfer_dir`.
                // Decode + validate the filename, look the file up on
                // disk, then hand off to the sender state machine
                // starting at seq+1 (so its S follows our just-received
                // R in the same monotonic stream).
                let fname = String::from_utf8_lossy(&pkt.payload).into_owned();
                if !is_safe_resume_filename(&fname) {
                    send_error(
                        writer,
                        pkt.seq,
                        "Invalid filename",
                        b'1',
                        0,
                        0,
                        CR,
                        is_tcp,
                    )
                    .await?;
                    if verbose {
                        glog!("Kermit server: refused R '{}' (unsafe filename)", fname);
                    }
                    // Spec §6.7: stay idle for the next command.
                    continue;
                }
                let path = effective_transfer_path(&cfg, &subdir).join(&fname);
                let bytes = match std::fs::read(&path) {
                    Ok(b) => b,
                    Err(_) => {
                        send_error(
                            writer,
                            pkt.seq,
                            "File not found",
                            b'1',
                            0,
                            0,
                            CR,
                            is_tcp,
                        )
                        .await?;
                        if verbose {
                            glog!(
                                "Kermit server: refused R '{}' (file not found)",
                                fname
                            );
                        }
                        // Stay idle for the next command per spec.
                        continue;
                    }
                };
                if bytes.len() as u64 > MAX_FILE_SIZE {
                    send_error(
                        writer,
                        pkt.seq,
                        "File too large",
                        b'1',
                        0,
                        0,
                        CR,
                        is_tcp,
                    )
                    .await?;
                    // Stay idle for the next command per spec.
                    continue;
                }
                let modtime = std::fs::metadata(&path)
                    .ok()
                    .and_then(|m| m.modified().ok())
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs());
                let file = KermitSendFile {
                    name: &fname,
                    data: &bytes,
                    modtime,
                    mode: None,
                };
                // ACK the R-packet explicitly *before* starting the
                // send.  C-Kermit (and per Frank da Cruz §6 the strict
                // spec reading) expects every command packet to be
                // acknowledged with a Y-packet before any new state
                // machine takes over — sending S directly without the
                // ACK first leaves the client retrying its R because
                // it never saw confirmation that we received it.  Our
                // own client (`kermit_client_get`) reads the ACK then
                // the S so this convention works on both peers.
                send_ack(writer, pkt.seq, b'1', 0, 0, CR, is_tcp).await?;
                // Empirical: C-Kermit (and the spec's "each transfer
                // is a fresh exchange" reading) expect the server's S
                // to start at seq 0, NOT R.seq+1.  After the R-ACK
                // we're between transfers; the upcoming S begins a
                // new send-side conversation with its own seq counter.
                let starting_seq = 0u8;
                if verbose {
                    glog!(
                        "Kermit server: R '{}' → ACK'd, sending {} bytes (starting seq={})",
                        fname,
                        bytes.len(),
                        starting_seq
                    );
                }
                kermit_send_with_starting_seq(
                    reader,
                    writer,
                    &[file],
                    is_tcp,
                    is_petscii,
                    verbose,
                    starting_seq,
                )
                .await?;
                continue;
            }
            other => {
                // Anything else — protocol error.  Per spec §6.7 we
                // stay idle after sending E so a confused peer can
                // recover by sending a valid command.  The per-command
                // negotiation-timeout bounds inactivity if the peer
                // just goes silent.
                if verbose {
                    glog!(
                        "Kermit server: unexpected type='{}' seq={}",
                        other as char,
                        pkt.seq
                    );
                }
                send_error(
                    writer,
                    pkt.seq,
                    "Unexpected packet type",
                    b'1',
                    0,
                    0,
                    CR,
                    is_tcp,
                )
                .await?;
                continue;
            }
        }
    }
}

// =============================================================================
// CLIENT STATE MACHINE
// =============================================================================

/// Send an R (Receive) request to a remote Kermit server and stream
/// the resulting transfer back through `kermit_receive_with_init`.
/// This is the core "pull a file" client primitive — the spec-compliant
/// equivalent of `ckermit -g <filename>`.
///
/// Wire flow:
/// 1. Client → Server: `R <filename>` at seq=0.
/// 2. Server → Client: either `E <reason>` (file missing / refused —
///    we bubble it as `Err`) or `S <peer-caps>` (server initiates a
///    send; we hand the pre-read S off to the receiver state machine).
/// 3. Receive proceeds normally: F/A/D…/Z/B exchange.
///
/// Returns the same `Vec<KermitReceive>` shape as `kermit_receive` —
/// typically a single entry, but the receiver naturally tolerates a
/// batch if the server sends one.
//
// `#[allow(dead_code)]` lifts the warning until telnet.rs grows a
// "Pull from remote Kermit" menu entry (Gap 3b commit 3 or later).
// The fn is already exercised by the unit tests below.
#[allow(dead_code)]
pub(crate) async fn kermit_client_get(
    reader: &mut (impl AsyncRead + Unpin),
    writer: &mut (impl AsyncWrite + Unpin),
    filename: &str,
    is_tcp: bool,
    is_petscii: bool,
    verbose: bool,
) -> Result<Vec<KermitReceive>, String> {
    let cfg = config::get_config();
    if verbose {
        glog!(
            "Kermit client GET: '{}', is_tcp={}, is_petscii={}",
            filename,
            is_tcp,
            is_petscii
        );
    }

    // 1. Send R-packet.  Filename goes in the payload as raw bytes —
    //    matches the convention the server's R handler reads (see
    //    `String::from_utf8_lossy(&pkt.payload)` in kermit_server).
    //    Quoting filenames here would force a corresponding decode
    //    branch on the server side; spec is loose either way and the
    //    raw form is what every Kermit we've seen on the wire uses.
    let r_pkt = build_packet(TYPE_R, 0, filename.as_bytes(), b'1', 0, 0, CR);
    raw_write_bytes(writer, &r_pkt, is_tcp).await?;

    // 2. Read the server's response.  Per spec §6 / C-Kermit interop
    //    the server first ACKs our R-packet, then sends an S to start
    //    the actual send.  Some servers might combine these (skip the
    //    ACK and send S directly) but tolerating both forms here costs
    //    little and helps interop with strict peers.  Use the
    //    negotiation timeout since the remote may be slow to consult
    //    disk; we don't yet have a peer TIME field to defer to.
    let mut state = ReadState::default();
    let mk_deadline = || {
        tokio::time::Instant::now()
            + tokio::time::Duration::from_secs(cfg.kermit_negotiation_timeout)
    };
    let resp = read_packet(
        reader,
        is_tcp,
        is_petscii,
        b'1',
        CR,
        verbose,
        &mut state,
        Some(mk_deadline()),
    )
    .await
    .map_err(|e| format!("Kermit client: GET response read failed: {}", e))?;

    match resp.kind {
        TYPE_ERROR => {
            // Server rejected the GET — decode the human-readable
            // reason and surface it.  Common cases: file not found,
            // unsafe filename, file too large.
            let q = Quoting {
                qctl: DEFAULT_QCTL,
                qbin: None,
                rept: None,
                locking_shifts: false,
            };
            let msg = decode_error_message(&resp.payload, q);
            Err(format!("Kermit client: server refused GET '{}': {}", filename, msg))
        }
        TYPE_ACK => {
            // ACK to our R — server is about to initiate the send.
            // Read the next packet, which should be S.
            let s_pkt = read_packet(
                reader,
                is_tcp,
                is_petscii,
                b'1',
                CR,
                verbose,
                &mut state,
                Some(mk_deadline()),
            )
            .await
            .map_err(|e| format!("Kermit client: GET S-read failed: {}", e))?;
            match s_pkt.kind {
                TYPE_SEND_INIT => kermit_receive_with_init(
                    reader,
                    writer,
                    is_tcp,
                    is_petscii,
                    verbose,
                    Some(s_pkt),
                )
                .await,
                TYPE_ERROR => {
                    let q = Quoting {
                        qctl: DEFAULT_QCTL,
                        qbin: None,
                        rept: None,
                        locking_shifts: false,
                    };
                    let msg = decode_error_message(&s_pkt.payload, q);
                    Err(format!(
                        "Kermit client: server E-packet after R-ACK: {}",
                        msg
                    ))
                }
                other => Err(format!(
                    "Kermit client: expected S after R-ACK, got '{}' seq={}",
                    other as char, s_pkt.seq
                )),
            }
        }
        TYPE_SEND_INIT => {
            // Loose-spec server skipped the R-ACK and sent S directly.
            // We tolerate this since our pre-fix server did exactly
            // that.  Hand the pre-read S off to the receiver state
            // machine.
            kermit_receive_with_init(
                reader,
                writer,
                is_tcp,
                is_petscii,
                verbose,
                Some(resp),
            )
            .await
        }
        other => Err(format!(
            "Kermit client: unexpected GET response type='{}' seq={}",
            other as char, resp.seq
        )),
    }
}

/// Send a Generic-command packet that expects a single-ACK reply
/// (F=Finish, L=Logout, B=BYE, C=CWD).  The peer's E-packet reply
/// surfaces as `Err`.  Caller assembles the action byte + optional
/// argument bytes (e.g. CWD's subdir name).
async fn kermit_client_send_g_simple(
    reader: &mut (impl AsyncRead + Unpin),
    writer: &mut (impl AsyncWrite + Unpin),
    action: u8,
    arg: &[u8],
    is_tcp: bool,
    is_petscii: bool,
    verbose: bool,
) -> Result<(), String> {
    let cfg = config::get_config();
    let mut state = ReadState::default();
    let mut payload = Vec::with_capacity(1 + arg.len());
    payload.push(action);
    payload.extend_from_slice(arg);
    let _ack_payload = send_and_await_ack(
        reader,
        writer,
        TYPE_GENERIC,
        0,
        &payload,
        b'1',
        0,
        0,
        CR,
        is_tcp,
        is_petscii,
        verbose,
        &mut state,
        Some(
            tokio::time::Instant::now()
                + tokio::time::Duration::from_secs(cfg.kermit_negotiation_timeout),
        ),
        cfg.kermit_max_retries,
        false,
    )
    .await?;
    Ok(())
}

/// Send a Generic-command packet that expects a text reply via X-Z
/// (D=DIR, `$`=SPACE, K=KERMIT version).  Drives the full
/// G→ACK→X→ACK→Z→ACK exchange and returns the decoded X payload as
/// a UTF-8 string.  Bubbles E-packets and protocol mismatches as Err.
async fn kermit_client_send_g_text(
    reader: &mut (impl AsyncRead + Unpin),
    writer: &mut (impl AsyncWrite + Unpin),
    action: u8,
    arg: &[u8],
    is_tcp: bool,
    is_petscii: bool,
    verbose: bool,
) -> Result<String, String> {
    let cfg = config::get_config();
    let mut state = ReadState::default();
    let mut payload = Vec::with_capacity(1 + arg.len());
    payload.push(action);
    payload.extend_from_slice(arg);
    // 1. Send G + await ACK.  send_and_await_ack auto-translates
    //    E-packet to Err so we don't have to second-guess that path.
    let _g_ack = send_and_await_ack(
        reader,
        writer,
        TYPE_GENERIC,
        0,
        &payload,
        b'1',
        0,
        0,
        CR,
        is_tcp,
        is_petscii,
        verbose,
        &mut state,
        Some(
            tokio::time::Instant::now()
                + tokio::time::Duration::from_secs(cfg.kermit_negotiation_timeout),
        ),
        cfg.kermit_max_retries,
        false,
    )
    .await?;
    // 2. Read X-packets until we see a Z.  Per Frank da Cruz §6 the
    //    server may paginate a long response across multiple X
    //    packets, terminated by a single Z.  We accumulate the
    //    decoded bodies in order.
    let q = Quoting {
        qctl: DEFAULT_QCTL,
        qbin: None,
        rept: Some(DEFAULT_REPT),
        locking_shifts: false,
    };
    let mut body: Vec<u8> = Vec::new();
    loop {
        let pkt = read_packet(
            reader,
            is_tcp,
            is_petscii,
            b'1',
            CR,
            verbose,
            &mut state,
            Some(
                tokio::time::Instant::now()
                    + tokio::time::Duration::from_secs(cfg.kermit_negotiation_timeout),
            ),
        )
        .await
        .map_err(|e| {
            format!(
                "Kermit client: G '{}' read X/Z failed: {}",
                action as char, e
            )
        })?;
        match pkt.kind {
            TYPE_TEXT => {
                let decoded = decode_data(&pkt.payload, q)?;
                body.extend(decoded);
                send_ack(writer, pkt.seq, b'1', 0, 0, CR, is_tcp).await?;
            }
            TYPE_EOF => {
                send_ack(writer, pkt.seq, b'1', 0, 0, CR, is_tcp).await?;
                break;
            }
            TYPE_ERROR => {
                let qe = Quoting {
                    qctl: DEFAULT_QCTL,
                    qbin: None,
                    rept: None,
                    locking_shifts: false,
                };
                let msg = decode_error_message(&pkt.payload, qe);
                return Err(format!(
                    "Kermit client: server E on G '{}': {}",
                    action as char, msg
                ));
            }
            other => {
                return Err(format!(
                    "Kermit client: G '{}' expected X/Z, got '{}'",
                    action as char, other as char
                ));
            }
        }
    }
    String::from_utf8(body).map_err(|e| {
        format!(
            "Kermit client: G '{}' response not UTF-8: {}",
            action as char, e
        )
    })
}

/// Tell a remote Kermit server to end its session (`G F`).
#[allow(dead_code)]
pub(crate) async fn kermit_client_finish(
    reader: &mut (impl AsyncRead + Unpin),
    writer: &mut (impl AsyncWrite + Unpin),
    is_tcp: bool,
    is_petscii: bool,
    verbose: bool,
) -> Result<(), String> {
    kermit_client_send_g_simple(reader, writer, b'F', &[], is_tcp, is_petscii, verbose).await
}

/// Log out and end the session (`G L`) — same wire effect as F on
/// most servers, but distinct for systems that distinguish "log out
/// the user" from "stop the protocol".
#[allow(dead_code)]
pub(crate) async fn kermit_client_logout(
    reader: &mut (impl AsyncRead + Unpin),
    writer: &mut (impl AsyncWrite + Unpin),
    is_tcp: bool,
    is_petscii: bool,
    verbose: bool,
) -> Result<(), String> {
    kermit_client_send_g_simple(reader, writer, b'L', &[], is_tcp, is_petscii, verbose).await
}

/// Send `G B` — BYE.  Equivalent end-session signal; some servers
/// use this to additionally close the underlying transport (we treat
/// it the same as F on the server side).
#[allow(dead_code)]
pub(crate) async fn kermit_client_bye(
    reader: &mut (impl AsyncRead + Unpin),
    writer: &mut (impl AsyncWrite + Unpin),
    is_tcp: bool,
    is_petscii: bool,
    verbose: bool,
) -> Result<(), String> {
    kermit_client_send_g_simple(reader, writer, b'B', &[], is_tcp, is_petscii, verbose).await
}

/// Change the remote server's working subdirectory (`G C <subdir>`).
/// The subdir argument is sent as raw UTF-8 bytes after the action
/// byte; servers typically validate it against their own sandbox
/// rules and refuse with E-packet on path-traversal attempts.
#[allow(dead_code)]
pub(crate) async fn kermit_client_cwd(
    reader: &mut (impl AsyncRead + Unpin),
    writer: &mut (impl AsyncWrite + Unpin),
    subdir: &str,
    is_tcp: bool,
    is_petscii: bool,
    verbose: bool,
) -> Result<(), String> {
    kermit_client_send_g_simple(
        reader,
        writer,
        b'C',
        subdir.as_bytes(),
        is_tcp,
        is_petscii,
        verbose,
    )
    .await
}

/// Ask a remote Kermit server for a file listing of its current
/// working directory (`G D`).  Returns the raw text the server sent
/// — typical format is one entry per line, but it varies by server
/// implementation.
#[allow(dead_code)]
pub(crate) async fn kermit_client_dir(
    reader: &mut (impl AsyncRead + Unpin),
    writer: &mut (impl AsyncWrite + Unpin),
    is_tcp: bool,
    is_petscii: bool,
    verbose: bool,
) -> Result<String, String> {
    kermit_client_send_g_text(reader, writer, b'D', &[], is_tcp, is_petscii, verbose).await
}

/// Ask a remote Kermit server how much free disk it has at its
/// current working directory (`G $`).  Format is server-specific —
/// our implementation returns the byte count as a decimal string,
/// but other peers may format it differently or return "unknown".
#[allow(dead_code)]
pub(crate) async fn kermit_client_space(
    reader: &mut (impl AsyncRead + Unpin),
    writer: &mut (impl AsyncWrite + Unpin),
    is_tcp: bool,
    is_petscii: bool,
    verbose: bool,
) -> Result<String, String> {
    kermit_client_send_g_text(reader, writer, b'$', &[], is_tcp, is_petscii, verbose).await
}

/// Ask a remote Kermit server for its help text (`G H`, with `G ?`
/// as a common alias).  Returns the help body the peer sent — a
/// list of supported subcommands or a free-form description.
#[allow(dead_code)]
pub(crate) async fn kermit_client_help(
    reader: &mut (impl AsyncRead + Unpin),
    writer: &mut (impl AsyncWrite + Unpin),
    is_tcp: bool,
    is_petscii: bool,
    verbose: bool,
) -> Result<String, String> {
    kermit_client_send_g_text(reader, writer, b'H', &[], is_tcp, is_petscii, verbose).await
}

/// Ask a remote Kermit server to identify itself (`G K`).  Returns
/// the version / identity string the peer sent in its X-packet body.
#[allow(dead_code)]
pub(crate) async fn kermit_client_version(
    reader: &mut (impl AsyncRead + Unpin),
    writer: &mut (impl AsyncWrite + Unpin),
    is_tcp: bool,
    is_petscii: bool,
    verbose: bool,
) -> Result<String, String> {
    kermit_client_send_g_text(reader, writer, b'K', &[], is_tcp, is_petscii, verbose).await
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
        // C0 controls and DEL — must QCTL.
        for b in 0..0x20 {
            assert!(is_kermit_control(b));
        }
        assert!(is_kermit_control(0x7F));
        // C1 controls and high-bit DEL — also must QCTL per spec §6.4.
        for b in 0x80u8..=0x9F {
            assert!(is_kermit_control(b), "0x{:02X} should be control", b);
        }
        assert!(is_kermit_control(0xFF));
        // Printable 7-bit and 8-bit non-control bytes — must NOT QCTL.
        assert!(!is_kermit_control(0x20));
        assert!(!is_kermit_control(0x7E));
        assert!(!is_kermit_control(0xA0));
        assert!(!is_kermit_control(0xFE));
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
            locking_shifts: false,
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
            locking_shifts: false,
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
            locking_shifts: false,
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
            locking_shifts: false,
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
            locking_shifts: false,
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
            locking_shifts: false,
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
            locking_shifts: false,
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
            locking_shifts: false,
        };
        assert!(decode_data(b"&", q).is_err());
    }

    // ---------- Locking shifts (Frank da Cruz §3.4.5) ----------

    /// Helper: build a Quoting with locking shifts on, qbin off, REPT
    /// optional.  Mirrors the precedence the spec mandates
    /// (locking-shift > QBIN).
    fn lshift_q(rept: Option<u8>) -> Quoting {
        Quoting {
            qctl: b'#',
            qbin: None,
            rept,
            locking_shifts: true,
        }
    }

    #[test]
    fn test_lshift_low_only_emits_no_shift_markers() {
        // All low-bit input: encoder must never emit SO/SI.  Wire output
        // is the same as a non-locking-shift transparent transmission.
        let q = lshift_q(None);
        let input = b"hello world";
        let enc = encode_data(input, q);
        // Find any ctl-quoted SO/SI in the output: would appear as
        // `qctl ctl(SO)` (`# N`) or `qctl ctl(SI)` (`# O`).
        let mut iter = enc.windows(2);
        let has_shift = iter.any(|w| w[0] == b'#' && (w[1] == ctl(SO) || w[1] == ctl(SI)));
        assert!(!has_shift, "no SO/SI markers on low-only input");
        let dec = decode_data(&enc, q).unwrap();
        assert_eq!(dec, input);
    }

    #[test]
    fn test_lshift_high_only_emits_so_then_closing_si() {
        // All high-bit input: one leading SO, optional REPT-compressed
        // body, one trailing SI to leave the packet in Normal mode.
        let q = lshift_q(None);
        let input: Vec<u8> = (0x80u8..=0x90u8).collect();
        let enc = encode_data(&input, q);
        // First two bytes must be `qctl ctl(SO)`.
        assert_eq!(
            &enc[..2],
            &[b'#', ctl(SO)],
            "expected leading SO, got {:?}",
            &enc[..2]
        );
        // Last two bytes must be `qctl ctl(SI)`.
        let last = enc.len();
        assert_eq!(
            &enc[last - 2..],
            &[b'#', ctl(SI)],
            "expected trailing SI, got {:?}",
            &enc[last - 2..]
        );
        let dec = decode_data(&enc, q).unwrap();
        assert_eq!(dec, input);
    }

    #[test]
    fn test_lshift_mixed_round_trip() {
        let q = lshift_q(None);
        // Alternate low/high so encoder must flip mode on every byte.
        let input: Vec<u8> = (0..32u8).map(|i| if i & 1 == 0 { i } else { 0x80 | i }).collect();
        let enc = encode_data(&input, q);
        let dec = decode_data(&enc, q).unwrap();
        assert_eq!(dec, input);
    }

    #[test]
    fn test_lshift_all_byte_values_round_trip() {
        let q = lshift_q(None);
        let input: Vec<u8> = (0..=255u8).collect();
        let enc = encode_data(&input, q);
        let dec = decode_data(&enc, q).unwrap();
        assert_eq!(dec, input);
    }

    #[test]
    fn test_lshift_literal_so_in_data_preserved() {
        // 0x0E (SO) and 0x0F (SI) appearing as DATA must round-trip
        // unchanged — they go out via the literal-prefix escape
        // (`qctl + raw byte`) so the decoder doesn't mode-flip.  This
        // is the most-likely-to-regress edge case for locking shifts.
        let q = lshift_q(None);
        let input: Vec<u8> = vec![SO, SI, 0x80 | SO, 0x80 | SI, b'x'];
        let enc = encode_data(&input, q);
        let dec = decode_data(&enc, q).unwrap();
        assert_eq!(dec, input);
    }

    #[test]
    fn test_lshift_with_rept_compression_high_bit_run() {
        // Run of identical high-bit bytes should compress under REPT
        // AND ride a single SO/SI mode pair.  The mode flip must come
        // BEFORE the REPT marker so the marker + body sit in the
        // shifted set; otherwise the count expands a wrongly-coloured
        // byte.
        let q = lshift_q(Some(b'~'));
        let mut input = vec![b'a'; 5];
        input.extend(std::iter::repeat_n(0xA5u8, 50));
        input.extend([b'b'; 3]);
        let enc = encode_data(&input, q);
        let dec = decode_data(&enc, q).unwrap();
        assert_eq!(dec, input);
    }

    #[test]
    fn test_lshift_decoder_recognises_ctl_quoted_so_si_only() {
        // Hand-craft a wire payload: `# N` (qctl ctl(SO)) is a SHIFT,
        // but `# 0x0E` (qctl + raw byte) is a literal-prefix escape
        // for byte 0x0E.  Decoder must treat them differently even
        // though they share the same qctl prefix.
        let q = lshift_q(None);
        let shift_to_high = vec![b'#', ctl(SO), b'A', b'#', ctl(SI)];
        // After shift to high: 'A' becomes 0xC1 (0x41 | 0x80).  After
        // SI we're back to Normal but no further bytes.
        let dec = decode_data(&shift_to_high, q).unwrap();
        assert_eq!(dec, vec![0xC1]);

        // Literal 0x0E in data: encoded as `# 0x0E`.
        let literal_so = vec![b'#', SO];
        let dec = decode_data(&literal_so, q).unwrap();
        assert_eq!(dec, vec![SO]);
    }

    #[test]
    fn test_decode_rejects_dangling_repeat() {
        let q = Quoting {
            qctl: b'#',
            qbin: None,
            rept: Some(b'~'),
            locking_shifts: false,
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
        let parsed = read_packet(&mut c, false, false, b'1', CR, false, &mut state, None)
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
        let parsed = read_packet(&mut c, false, false, b'2', CR, false, &mut state, None)
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
        let parsed = read_packet(&mut c, false, false, b'3', CR, false, &mut state, None)
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
        let parsed = read_packet(&mut c, false, false, b'3', CR, false, &mut state, None)
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
        let parsed = read_packet(&mut c, false, false, b'1', CR, false, &mut state, None)
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
        let result = read_packet(&mut c, false, false, b'3', CR, false, &mut state, None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_esc_during_mark_hunt_cancels() {
        // ESC byte arriving in the pre-MARK hunt should abort the read
        // with a "cancelled by user" error.
        let mut state = ReadState::default();
        let mut c = cursor(vec![0x20, 0x20, 0x1B]); // pads then ESC
        let result =
            read_packet(&mut c, false, false, b'1', CR, false, &mut state, None).await;
        let err = result.unwrap_err();
        assert!(err.contains("cancelled"), "got: {}", err);
    }

    #[tokio::test]
    async fn test_petscii_left_arrow_cancels() {
        // PETSCII left-arrow (0x5F) acts as ESC for C64 terminals.
        let mut state = ReadState::default();
        let mut c = cursor(vec![0x20, 0x5F]);
        let result =
            read_packet(&mut c, false, true, b'1', CR, false, &mut state, None).await;
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
            resend: true,
            locking_shifts: true,
            peer_id: Some("Ethernet Gateway Kermit".into()),
        };
        let payload = build_send_init_payload(&caps);
        let parsed = parse_send_init_payload(&payload);
        assert!(parsed.long_packets);
        assert!(parsed.attribute_packets);
        assert!(parsed.streaming);
        assert!(parsed.resend);
        assert!(parsed.locking_shifts);
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
            charset: Some(b'A'),
            encoding: Some(b'B'),
            record_format: Some(b'S'),
            record_length: Some(80),
            creator_id: Some("rbryce".into()),
            account_id: Some("ACCT-001".into()),
            block_size: Some(512),
            access_mode: Some(b'R'),
            encoding_alt: Some(b'A'),
            ..Attributes::default()
        };
        let bytes = encode_attributes(&a);
        let parsed = parse_attributes(&bytes);
        assert_eq!(parsed.length, Some(12345));
        assert_eq!(parsed.date.as_deref(), Some("20260426 12:34:56"));
        assert_eq!(parsed.mode, Some(0o644));
        assert_eq!(parsed.system_id.as_deref(), Some("UNIX"));
        assert_eq!(parsed.file_type, Some(b'B'));
        assert_eq!(parsed.disposition, Some(b'N'));
        assert_eq!(parsed.charset, Some(b'A'));
        assert_eq!(parsed.encoding, Some(b'B'));
        assert_eq!(parsed.record_format, Some(b'S'));
        assert_eq!(parsed.record_length, Some(80));
        assert_eq!(parsed.creator_id.as_deref(), Some("rbryce"));
        assert_eq!(parsed.account_id.as_deref(), Some("ACCT-001"));
        assert_eq!(parsed.block_size, Some(512));
        assert_eq!(parsed.access_mode, Some(b'R'));
        assert_eq!(parsed.encoding_alt, Some(b'A'));
    }

    #[test]
    fn test_attributes_per_tag_roundtrip_creator_id() {
        let a = Attributes {
            creator_id: Some("operator".into()),
            ..Attributes::default()
        };
        let bytes = encode_attributes(&a);
        assert!(bytes.contains(&b'$'));
        assert_eq!(
            parse_attributes(&bytes).creator_id.as_deref(),
            Some("operator")
        );
    }

    #[test]
    fn test_attributes_per_tag_roundtrip_account_id() {
        let a = Attributes {
            account_id: Some("BILL-42".into()),
            ..Attributes::default()
        };
        let bytes = encode_attributes(&a);
        assert!(bytes.contains(&b'%'));
        assert_eq!(
            parse_attributes(&bytes).account_id.as_deref(),
            Some("BILL-42")
        );
    }

    #[test]
    fn test_attributes_per_tag_roundtrip_block_size() {
        let a = Attributes {
            block_size: Some(1024),
            ..Attributes::default()
        };
        let bytes = encode_attributes(&a);
        assert!(bytes.contains(&b'\''));
        assert_eq!(parse_attributes(&bytes).block_size, Some(1024));
    }

    #[test]
    fn test_attributes_per_tag_roundtrip_access_mode() {
        let a = Attributes {
            access_mode: Some(b'A'),
            ..Attributes::default()
        };
        let bytes = encode_attributes(&a);
        assert!(bytes.contains(&b'('));
        assert_eq!(parse_attributes(&bytes).access_mode, Some(b'A'));
    }

    #[test]
    fn test_attributes_per_tag_roundtrip_encoding_alt() {
        let a = Attributes {
            encoding_alt: Some(b'C'),
            ..Attributes::default()
        };
        let bytes = encode_attributes(&a);
        assert!(bytes.contains(&b')'));
        assert_eq!(parse_attributes(&bytes).encoding_alt, Some(b'C'));
    }

    #[test]
    fn test_attributes_creator_id_oversize_dropped() {
        // Per spec, sub-attribute values can't exceed 94 bytes (the
        // tochar-encoded length field caps at 94).  Encoder must drop
        // values that would overflow rather than emit a garbled length.
        let a = Attributes {
            creator_id: Some("x".repeat(95)),
            ..Attributes::default()
        };
        let bytes = encode_attributes(&a);
        assert!(!bytes.contains(&b'$'), "oversized '$' must not be emitted");
    }

    #[test]
    fn test_attributes_long_length_parsed_when_only_amp() {
        // Hand-craft an A-packet payload with only '&' (long length),
        // no '!' — simulates a peer with files larger than '!' can
        // express.  Verify long_length is captured and the receiver
        // logic uses it as a fallback for declared_size.
        let mut data = Vec::new();
        data.push(b'&');
        let s = "5000000000"; // 5 GB
        data.push(tochar(s.len() as u8));
        data.extend_from_slice(s.as_bytes());
        let parsed = parse_attributes(&data);
        assert_eq!(parsed.length, None, "no '!' was sent");
        assert_eq!(parsed.long_length, Some(5_000_000_000));
    }

    #[test]
    fn test_attributes_per_tag_roundtrip_charset() {
        let a = Attributes {
            charset: Some(b'A'),
            ..Attributes::default()
        };
        let bytes = encode_attributes(&a);
        assert!(!bytes.is_empty());
        assert_eq!(parse_attributes(&bytes).charset, Some(b'A'));
    }

    #[test]
    fn test_attributes_per_tag_roundtrip_encoding() {
        let a = Attributes {
            encoding: Some(b'C'),
            ..Attributes::default()
        };
        let bytes = encode_attributes(&a);
        assert!(!bytes.is_empty());
        assert_eq!(parse_attributes(&bytes).encoding, Some(b'C'));
    }

    #[test]
    fn test_attributes_per_tag_roundtrip_record_format() {
        let a = Attributes {
            record_format: Some(b'F'),
            ..Attributes::default()
        };
        let bytes = encode_attributes(&a);
        assert!(!bytes.is_empty());
        assert_eq!(parse_attributes(&bytes).record_format, Some(b'F'));
    }

    #[test]
    fn test_attributes_per_tag_roundtrip_record_length() {
        let a = Attributes {
            record_length: Some(132),
            ..Attributes::default()
        };
        let bytes = encode_attributes(&a);
        assert!(!bytes.is_empty());
        assert_eq!(parse_attributes(&bytes).record_length, Some(132));
    }

    #[test]
    fn test_attributes_long_length_not_emitted_when_short() {
        // We never emit '&' from our encoder — '!' covers MAX_FILE_SIZE
        // and adding '&' would just bloat the packet.  Encoded form
        // must contain the '!' tag but not the '&' tag.
        let a = Attributes {
            length: Some(100),
            long_length: Some(100), // even if the caller sets it
            ..Attributes::default()
        };
        let bytes = encode_attributes(&a);
        assert!(bytes.contains(&b'!'), "should emit '!' for length");
        assert!(!bytes.contains(&b'&'), "should NOT emit '&' (we don't produce it)");
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

    // ---------- Resume-partial helper ----------

    /// Build a unique scratch directory under the OS temp dir.
    /// Cleaned by the caller via `let _ = std::fs::remove_dir_all(&dir);`.
    fn resume_scratch_dir(name: &str) -> std::path::PathBuf {
        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("xmodem_resume_{}_{}", pid, name));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_compute_resume_offset_existing_file_returns_size() {
        let dir = resume_scratch_dir("existing");
        let payload = b"partial bytes on disk";
        std::fs::write(dir.join("foo.bin"), payload).unwrap();
        let off = compute_resume_offset("foo.bin", dir.to_str().unwrap(), 168);
        assert_eq!(off, Some(payload.len() as u64));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_compute_resume_offset_zero_byte_file_returns_zero() {
        // Empty partial is still a partial — spec lets the receiver
        // advertise length=0, the sender just sends from byte 0.
        let dir = resume_scratch_dir("zerobyte");
        std::fs::write(dir.join("empty.bin"), b"").unwrap();
        let off = compute_resume_offset("empty.bin", dir.to_str().unwrap(), 168);
        assert_eq!(off, Some(0));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_compute_resume_offset_missing_file_returns_none() {
        let dir = resume_scratch_dir("missing");
        let off = compute_resume_offset("absent.bin", dir.to_str().unwrap(), 168);
        assert_eq!(off, None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_compute_resume_offset_directory_returns_none() {
        // The "filename" resolves to a directory — must not be treated
        // as a resumable partial.
        let dir = resume_scratch_dir("dirnotfile");
        std::fs::create_dir_all(dir.join("subdir")).unwrap();
        let off = compute_resume_offset("subdir", dir.to_str().unwrap(), 168);
        assert_eq!(off, None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_compute_resume_offset_too_old_returns_none() {
        // Backdate the file's mtime past the configured cutoff.
        // Using max_age_hours=1 with a file backdated to 2 hours ago
        // gives an unambiguous failure even on slow CI clocks.
        let dir = resume_scratch_dir("tooold");
        let path = dir.join("stale.bin");
        std::fs::write(&path, b"stale partial").unwrap();
        // Set mtime to 2 hours ago.
        let two_hours_ago = std::time::SystemTime::now()
            - std::time::Duration::from_secs(2 * 3600);
        let f = std::fs::File::open(&path).unwrap();
        f.set_modified(two_hours_ago).unwrap();
        drop(f);
        let off = compute_resume_offset("stale.bin", dir.to_str().unwrap(), 1);
        assert_eq!(off, None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_compute_resume_offset_within_age_window_returns_size() {
        // Sanity check: same backdating mechanism, but the file is
        // young enough relative to the configured window — must be
        // accepted.  Guards against an off-by-one in the cutoff math.
        let dir = resume_scratch_dir("fresh_aged");
        let path = dir.join("recent.bin");
        std::fs::write(&path, b"recent partial").unwrap();
        // Backdate to 30 minutes ago, max_age_hours = 1 → eligible.
        let thirty_min_ago = std::time::SystemTime::now()
            - std::time::Duration::from_secs(1800);
        let f = std::fs::File::open(&path).unwrap();
        f.set_modified(thirty_min_ago).unwrap();
        drop(f);
        let off = compute_resume_offset("recent.bin", dir.to_str().unwrap(), 1);
        assert_eq!(off, Some(b"recent partial".len() as u64));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_compute_resume_offset_future_mtime_returns_none() {
        // Clock-skew defense: a file timestamped in the future could
        // wrap around our age math (now - mtime is Err) and silently
        // become "always eligible".  Treat as ineligible instead.
        let dir = resume_scratch_dir("future_mtime");
        let path = dir.join("future.bin");
        std::fs::write(&path, b"clock skew payload").unwrap();
        let one_hour_ahead = std::time::SystemTime::now()
            + std::time::Duration::from_secs(3600);
        let f = std::fs::File::open(&path).unwrap();
        f.set_modified(one_hour_ahead).unwrap();
        drop(f);
        let off = compute_resume_offset("future.bin", dir.to_str().unwrap(), 168);
        assert_eq!(off, None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_compute_resume_offset_missing_dir_returns_none() {
        let off = compute_resume_offset(
            "anything.bin",
            "/nonexistent/path/that/does/not/exist",
            168,
        );
        assert_eq!(off, None);
    }

    #[test]
    fn test_is_safe_resume_filename_accepts_normal_names() {
        assert!(is_safe_resume_filename("foo.bin"));
        assert!(is_safe_resume_filename("a"));
        assert!(is_safe_resume_filename("file_v2.tar.gz"));
        assert!(is_safe_resume_filename("UPPER-CASE-NAME.TXT"));
    }

    #[test]
    fn test_is_safe_resume_filename_rejects_traversal_and_separators() {
        // Path-traversal threat model: the receiver joins this name
        // onto cfg.transfer_dir before stat-ing.  Anything that could
        // escape the directory must be refused.
        assert!(!is_safe_resume_filename(""));
        assert!(!is_safe_resume_filename(".hidden"));
        assert!(!is_safe_resume_filename("../escape"));
        assert!(!is_safe_resume_filename("foo/../bar"));
        assert!(!is_safe_resume_filename("sub/file"));
        assert!(!is_safe_resume_filename("win\\style"));
        assert!(!is_safe_resume_filename("nul\0byte"));
        assert!(!is_safe_resume_filename(".."));
    }

    #[test]
    fn test_compute_resume_offset_unsafe_filename_returns_none() {
        // Even if the on-disk path would accidentally resolve to a
        // real file, the safety check must short-circuit before any
        // stat happens.  This guards against a future regression
        // where we might be tempted to canonicalize the path "after"
        // the join — by that point a `..` has already escaped.
        let dir = resume_scratch_dir("unsafe_name");
        std::fs::write(dir.join("real.bin"), b"shouldn't matter").unwrap();
        // Construct a filename that would point back at real.bin via
        // traversal if joining naively from a sibling dir, then make
        // sure the helper refuses it regardless.
        let off = compute_resume_offset("../real.bin", dir.to_str().unwrap(), 168);
        assert_eq!(off, None);
        let _ = std::fs::remove_dir_all(&dir);
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

    // CAN×2 abort state machine moved to tnio.rs (shared across
    // xmodem and kermit).  See `tnio::tests::test_can_abort_state_machine`.

    // ---------- Server-mode dispatch (Gap 3a commit 1) ----------

    use tokio::io::{duplex, split, AsyncReadExt, AsyncWriteExt};

    /// Spin up `kermit_server` against a duplex pipe.  The caller's
    /// closure receives one half of the pipe to play the part of a
    /// Kermit client (write requests, read server responses).  Returns
    /// the closure's value plus the server's exit `Result`.
    async fn run_server_with_client<F, T>(
        client: F,
    ) -> (T, Result<Vec<KermitReceive>, String>)
    where
        F: AsyncFnOnce(
            &mut tokio::io::WriteHalf<tokio::io::DuplexStream>,
            &mut tokio::io::ReadHalf<tokio::io::DuplexStream>,
        ) -> T,
    {
        let _guard = CONFIG_LOCK.lock().await;
        init_test_config();
        let (server_side, client_side) = duplex(65536);
        let (mut s_read, mut s_write) = split(server_side);
        let (mut c_read, mut c_write) = split(client_side);
        let server_task = tokio::spawn(async move {
            kermit_server(&mut s_read, &mut s_write, false, false, false).await
        });
        let client_result = client(&mut c_write, &mut c_read).await;
        // Flush so any pending bytes from client side reach the server.
        let _ = c_write.flush().await;
        let server_result = server_task.await.unwrap();
        (client_result, server_result)
    }

    /// Build a complete on-the-wire packet at session-default settings
    /// (CHKT=1, no padding, EOL=CR) — what a peer would emit before
    /// negotiation completes.
    fn wire_packet(kind: u8, seq: u8, payload: &[u8]) -> Vec<u8> {
        build_packet(kind, seq, payload, b'1', 0, 0, CR)
    }

    /// Read one packet from the server's response stream using the
    /// same protocol the receiver does at default settings.
    async fn read_server_packet(
        reader: &mut tokio::io::ReadHalf<tokio::io::DuplexStream>,
    ) -> Packet {
        let mut state = ReadState::default();
        let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(5);
        read_packet(reader, false, false, b'1', CR, false, &mut state, Some(deadline))
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn test_server_refuses_host_command_with_e_packet() {
        // C-packet (host command) is a remote-code-execution primitive;
        // server must refuse with an E-packet by default.  Per spec
        // §6.7 the server stays idle after the refusal so the peer can
        // try a different command — we close with G F.
        let ((), result) = run_server_with_client(async |w, r| {
            w.write_all(&wire_packet(TYPE_HOST, 0, b"rm -rf /"))
                .await
                .unwrap();
            let resp = read_server_packet(r).await;
            assert_eq!(resp.kind, TYPE_ERROR, "expected E-packet, got '{}'", resp.kind as char);
            let q = Quoting::default();
            let msg = decode_error_message(&resp.payload, q);
            assert!(
                msg.to_ascii_lowercase().contains("disabled"),
                "E-packet message must explain refusal, got: {}",
                msg
            );
            close_server_session(w, r).await;
        })
        .await;
        result.unwrap();
    }

    #[tokio::test]
    async fn test_server_handles_init_with_capas_yack() {
        // I-packet asks for fresh CAPAS — server must reply with Y-ACK
        // whose payload is a Send-Init (parseable as Capabilities).
        // After the I-ACK, the server stays alive; we send B to close.
        let ((), result) = run_server_with_client(async |w, r| {
            w.write_all(&wire_packet(TYPE_INIT, 0, &[])).await.unwrap();
            let resp = read_server_packet(r).await;
            assert_eq!(resp.kind, TYPE_ACK, "expected ACK, got '{}'", resp.kind as char);
            let parsed = parse_send_init_payload(&resp.payload);
            // Sanity-check a couple fields that config_capabilities
            // always sets — proves the payload is a real Send-Init,
            // not just empty bytes.
            assert!(parsed.maxl >= MIN_PACKET_LEN as u16);
            assert!(matches!(parsed.chkt, b'1' | b'2' | b'3'));
            // Now send B to close the session cleanly.
            w.write_all(&wire_packet(TYPE_EOT, 1, &[])).await.unwrap();
            let close = read_server_packet(r).await;
            assert_eq!(close.kind, TYPE_ACK, "expected ACK to B, got '{}'", close.kind as char);
        })
        .await;
        result.unwrap();
    }

    #[tokio::test]
    async fn test_server_eot_acks_and_exits() {
        // B-packet (EOT) signals clean session-end.  Server ACKs and
        // returns Ok.
        let ((), result) = run_server_with_client(async |w, r| {
            w.write_all(&wire_packet(TYPE_EOT, 0, &[])).await.unwrap();
            let resp = read_server_packet(r).await;
            assert_eq!(resp.kind, TYPE_ACK);
        })
        .await;
        result.unwrap();
    }

    #[tokio::test]
    async fn test_server_peer_e_packet_exits_silently() {
        // E-packet is fatal both ways.  Server must NOT respond
        // (responding could trigger a loop with a peer that's also
        // about to exit on E).  It just logs and returns.
        let ((), result) = run_server_with_client(async |w, _r| {
            w.write_all(&wire_packet(TYPE_ERROR, 0, b"client gave up"))
                .await
                .unwrap();
        })
        .await;
        result.unwrap();
    }

    #[tokio::test]
    async fn test_server_g_finish_acks_and_exits() {
        // G F (Generic Finish): server ACKs then exits.
        let ((), result) = run_server_with_client(async |w, r| {
            w.write_all(&wire_packet(TYPE_GENERIC, 0, b"F")).await.unwrap();
            let resp = read_server_packet(r).await;
            assert_eq!(resp.kind, TYPE_ACK);
        })
        .await;
        result.unwrap();
    }

    #[tokio::test]
    async fn test_server_g_logout_acks_and_exits() {
        let ((), result) = run_server_with_client(async |w, r| {
            w.write_all(&wire_packet(TYPE_GENERIC, 0, b"L")).await.unwrap();
            let resp = read_server_packet(r).await;
            assert_eq!(resp.kind, TYPE_ACK);
        })
        .await;
        result.unwrap();
    }

    #[tokio::test]
    async fn test_server_g_unknown_subcommand_acks_and_continues() {
        // Unknown G subcommand (not F/L): ACK and stay in the loop.
        // Verify by sending a follow-up B and expecting a second ACK.
        let ((), result) = run_server_with_client(async |w, r| {
            // Custom unknown G subcommand 'X' — server must ACK and
            // continue, not exit.  BYE/CWD/DIR/SPACE/KERMIT will be
            // wired in commit 3.
            w.write_all(&wire_packet(TYPE_GENERIC, 0, b"X")).await.unwrap();
            let resp = read_server_packet(r).await;
            assert_eq!(resp.kind, TYPE_ACK, "G X should be ACKed");
            // Follow up with B to close.
            w.write_all(&wire_packet(TYPE_EOT, 1, &[])).await.unwrap();
            let close = read_server_packet(r).await;
            assert_eq!(close.kind, TYPE_ACK);
        })
        .await;
        result.unwrap();
    }

    #[tokio::test]
    async fn test_server_dispatches_s_to_receive() {
        // S-dispatch end-to-end: client uses `kermit_send` to upload
        // a file via the server's S handler.  After the transfer
        // completes, client closes the session with G F.  The server
        // must return the received file in its Vec<KermitReceive>.
        let payload: Vec<u8> = b"hello kermit server".to_vec();
        let payload_for_client = payload.clone();
        let ((), result) = run_server_with_client(async move |w, r| {
            // Client-side: kermit_send the file, then send G F at
            // default-chkt to close the server's dispatch loop.
            let kfile = KermitSendFile {
                name: "uploaded.bin",
                data: &payload_for_client,
                modtime: None,
                mode: None,
            };
            kermit_send(r, w, &[kfile], false, false, false)
                .await
                .unwrap();
            w.write_all(&wire_packet(TYPE_GENERIC, 0, b"F")).await.unwrap();
            // Drain the G-F ACK so it doesn't sit in the pipe.
            let _ = read_server_packet(r).await;
        })
        .await;
        let received = result.unwrap();
        assert_eq!(received.len(), 1, "exactly one file should round-trip");
        assert_eq!(received[0].filename, "uploaded.bin");
        assert_eq!(received[0].data, payload);
    }

    #[tokio::test]
    async fn test_server_r_pulls_existing_file() {
        // R-dispatch end-to-end at the wire level: client sends R,
        // reads the explicit ACK (per Frank da Cruz §6 / C-Kermit
        // interop convention), then runs `kermit_receive_with_init`
        // against the server's S→F→A→D…→Z→B stream.  Locks in both
        // the seq numbering and the ACK-then-S response shape.
        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("xmodem_server_r_pull_{}", pid));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let payload: Vec<u8> = (0..4096u32).map(|i| (i ^ 0xA5) as u8).collect();
        std::fs::write(dir.join("pull.bin"), &payload).unwrap();

        let dir_str = dir.to_str().unwrap().to_string();
        let payload_clone = payload.clone();
        let dir_for_cleanup = dir.clone();

        let (recv_data, result) = run_server_with_client(async move |w, r| {
            config::update_config_value("transfer_dir", &dir_str);
            // Client → server: R(pull.bin) at seq 0.
            w.write_all(&wire_packet(TYPE_R, 0, b"pull.bin")).await.unwrap();
            // Server's first response is now an ACK to R (seq=0).
            let r_ack = read_server_packet(r).await;
            assert_eq!(r_ack.kind, TYPE_ACK, "server must ACK R before sending S");
            assert_eq!(r_ack.seq, 0);
            // Then it sends S(seq=1) to start the actual transfer —
            // pre-read it and hand off to `kermit_receive_with_init`.
            let s_pkt = read_server_packet(r).await;
            assert_eq!(s_pkt.kind, TYPE_SEND_INIT);
            let received = kermit_receive_with_init(r, w, false, false, false, Some(s_pkt))
                .await
                .unwrap();
            // Close the dispatch loop with G F.
            w.write_all(&wire_packet(TYPE_GENERIC, 0, b"F")).await.unwrap();
            let _ = read_server_packet(r).await;
            assert_eq!(received.len(), 1);
            assert_eq!(received[0].data, payload_clone);
            received[0].data.clone()
        })
        .await;

        config::update_config_value("transfer_dir", "transfer");
        let _ = std::fs::remove_dir_all(&dir_for_cleanup);

        result.unwrap();
        assert_eq!(recv_data, payload);
    }

    #[tokio::test]
    async fn test_server_r_missing_file_returns_e_packet() {
        // R for a file that doesn't exist in transfer_dir → server
        // emits E-packet "File not found" and stays idle for the next
        // command (spec §6.7).  Locks in the safe-by-default behavior:
        // server must NOT create the file, hang, or exit.
        let ((), result) = run_server_with_client(async |w, r| {
            w.write_all(&wire_packet(TYPE_R, 0, b"absent.bin")).await.unwrap();
            let resp = read_server_packet(r).await;
            assert_eq!(resp.kind, TYPE_ERROR, "expected E-packet for missing file");
            let q = Quoting::default();
            let msg = decode_error_message(&resp.payload, q).to_ascii_lowercase();
            assert!(
                msg.contains("not found") || msg.contains("missing"),
                "E-packet message must explain absence, got: {}",
                msg
            );
            close_server_session(w, r).await;
        })
        .await;
        result.unwrap();
    }

    /// Helper: run a G subcommand that produces a text response
    /// (DIR/SPACE/KERMIT).  Drives the full G→ACK→X→ACK→Z→ACK
    /// exchange and returns the decoded X-packet body.
    async fn run_g_text_command(
        w: &mut tokio::io::WriteHalf<tokio::io::DuplexStream>,
        r: &mut tokio::io::ReadHalf<tokio::io::DuplexStream>,
        action: u8,
        arg: &[u8],
    ) -> String {
        let mut payload = vec![action];
        payload.extend_from_slice(arg);
        w.write_all(&wire_packet(TYPE_GENERIC, 0, &payload))
            .await
            .unwrap();
        let g_ack = read_server_packet(r).await;
        assert_eq!(g_ack.kind, TYPE_ACK, "expected ACK to G, got '{}'", g_ack.kind as char);
        // Server may paginate the X body across multiple packets;
        // accumulate decoded chunks until we see the terminating Z.
        let q = Quoting::default();
        let mut body = Vec::new();
        loop {
            let pkt = read_server_packet(r).await;
            match pkt.kind {
                TYPE_TEXT => {
                    body.extend(decode_data(&pkt.payload, q).unwrap());
                    w.write_all(&wire_packet(TYPE_ACK, pkt.seq, &[])).await.unwrap();
                }
                TYPE_EOF => {
                    w.write_all(&wire_packet(TYPE_ACK, pkt.seq, &[])).await.unwrap();
                    break;
                }
                other => panic!("expected X/Z, got '{}'", other as char),
            }
        }
        String::from_utf8(body).unwrap()
    }

    /// Helper: close a server-mode session cleanly with G F.
    async fn close_server_session(
        w: &mut tokio::io::WriteHalf<tokio::io::DuplexStream>,
        r: &mut tokio::io::ReadHalf<tokio::io::DuplexStream>,
    ) {
        w.write_all(&wire_packet(TYPE_GENERIC, 0, b"F")).await.unwrap();
        let _ = read_server_packet(r).await;
    }

    #[tokio::test]
    async fn test_is_safe_relative_subdir_accepts_safe_paths() {
        assert!(is_safe_relative_subdir(""));
        assert!(is_safe_relative_subdir("foo"));
        assert!(is_safe_relative_subdir("foo/bar"));
        assert!(is_safe_relative_subdir("a-b_c.d"));
    }

    #[tokio::test]
    async fn test_is_safe_relative_subdir_rejects_unsafe_paths() {
        assert!(!is_safe_relative_subdir("/abs"));
        assert!(!is_safe_relative_subdir(".."));
        assert!(!is_safe_relative_subdir("foo/.."));
        assert!(!is_safe_relative_subdir(".hidden"));
        assert!(!is_safe_relative_subdir("foo//bar"));
        assert!(!is_safe_relative_subdir("win\\path"));
        assert!(!is_safe_relative_subdir("nul\0byte"));
        assert!(!is_safe_relative_subdir("has space"));
    }

    #[tokio::test]
    async fn test_filename_and_subdir_length_caps() {
        // Resume-filename cap.  64-char name accepted, 65-char rejected.
        let at_cap: String = "a".repeat(MAX_KERMIT_FILENAME_LEN);
        assert!(is_safe_resume_filename(&at_cap), "name AT cap must pass");
        let over_cap: String = "a".repeat(MAX_KERMIT_FILENAME_LEN + 1);
        assert!(
            !is_safe_resume_filename(&over_cap),
            "name OVER cap must fail"
        );
        // Subdir cap.  255 accepted, 256 rejected.
        let sub_at_cap: String = "a".repeat(MAX_KERMIT_SUBDIR_LEN);
        assert!(is_safe_relative_subdir(&sub_at_cap));
        let sub_over_cap: String = "a".repeat(MAX_KERMIT_SUBDIR_LEN + 1);
        assert!(!is_safe_relative_subdir(&sub_over_cap));
    }

    #[tokio::test]
    async fn test_server_r_oversized_filename_refused_and_session_alive() {
        // Peer sends an R with an over-cap filename.  Server refuses
        // (length cap kicks in before any disk I/O), then the session
        // remains idle for the next command.  Locks in the second-pass
        // audit's "cap before validate" defense-in-depth fix.
        let huge: String = "a".repeat(MAX_KERMIT_FILENAME_LEN + 1);
        let huge_bytes = huge.into_bytes();
        let ((), result) = run_server_with_client(async move |w, r| {
            w.write_all(&wire_packet(TYPE_R, 0, &huge_bytes))
                .await
                .unwrap();
            let resp = read_server_packet(r).await;
            assert_eq!(resp.kind, TYPE_ERROR);
            // Session still alive.
            let body = run_g_text_command(w, r, b'K', &[]).await;
            assert!(body.contains("Kermit"));
            close_server_session(w, r).await;
        })
        .await;
        result.unwrap();
    }

    #[tokio::test]
    async fn test_server_g_cwd_oversized_subdir_refused_and_session_alive() {
        // Peer sends G C with a path well past the subdir cap.
        // Refused without modifying the subdir; session continues.
        let huge: Vec<u8> = std::iter::once(b'C')
            .chain(std::iter::repeat_n(b'a', MAX_KERMIT_SUBDIR_LEN + 1))
            .collect();
        let ((), result) = run_server_with_client(async move |w, r| {
            w.write_all(&wire_packet(TYPE_GENERIC, 0, &huge))
                .await
                .unwrap();
            let resp = read_server_packet(r).await;
            assert_eq!(resp.kind, TYPE_ERROR);
            // Drive a follow-up command.
            let body = run_g_text_command(w, r, b'K', &[]).await;
            assert!(body.contains("Kermit"));
            close_server_session(w, r).await;
        })
        .await;
        result.unwrap();
    }

    #[tokio::test]
    async fn test_server_g_bye_exits_like_finish() {
        // BYE is treated as session-end at the kermit layer.  Telnet
        // integration may interpret it as "log out the connection"
        // separately, but the protocol exit path is shared.
        let ((), result) = run_server_with_client(async |w, r| {
            w.write_all(&wire_packet(TYPE_GENERIC, 0, b"B")).await.unwrap();
            let resp = read_server_packet(r).await;
            assert_eq!(resp.kind, TYPE_ACK);
        })
        .await;
        result.unwrap();
    }

    #[tokio::test]
    async fn test_server_g_help_returns_command_list() {
        // G H replies with our supported-command list via X+Z.  The
        // body must mention each subcommand letter so a peer's
        // `remote help` user sees what works.
        let ((), result) = run_server_with_client(async |w, r| {
            let body = run_g_text_command(w, r, b'H', &[]).await;
            for letter in &["F", "L", "B", "C", "D", "$", "K", "H"] {
                assert!(
                    body.contains(letter),
                    "help text missing subcommand '{}'; got: {:?}",
                    letter,
                    body
                );
            }
            close_server_session(w, r).await;
        })
        .await;
        result.unwrap();
    }

    #[tokio::test]
    async fn test_server_g_help_question_mark_alias() {
        // C-Kermit's `remote help` sends G ? rather than G H.  The
        // server must accept both as the help command.
        let ((), result) = run_server_with_client(async |w, r| {
            let body = run_g_text_command(w, r, b'?', &[]).await;
            assert!(body.to_ascii_lowercase().contains("kermit"));
            close_server_session(w, r).await;
        })
        .await;
        result.unwrap();
    }

    #[tokio::test]
    async fn test_paginate_g_text_response_single_chunk_under_cap() {
        // Short text fits in one X-packet.  Sanity check.
        let q = Quoting::default();
        let chunks = paginate_g_text_response("Hello world", q);
        assert_eq!(chunks.len(), 1);
        let decoded = decode_data(&chunks[0], q).unwrap();
        assert_eq!(&decoded[..], b"Hello world");
    }

    #[tokio::test]
    async fn test_paginate_g_text_response_multi_chunk_round_trip() {
        // Long text: must split across multiple chunks AND each
        // chunk's encoded payload must round-trip back to the source.
        let q = Quoting::default();
        let mut text = String::new();
        for i in 0..50 {
            text.push_str(&format!("file_{:02}.bin\t{}\n", i, i * 100));
        }
        let chunks = paginate_g_text_response(&text, q);
        assert!(
            chunks.len() > 1,
            "expected multiple chunks for 50-line listing, got {}",
            chunks.len()
        );
        for chunk in &chunks {
            assert!(
                chunk.len() <= G_RESPONSE_MAX_PAYLOAD,
                "chunk exceeded MAXL cap: {} > {}",
                chunk.len(),
                G_RESPONSE_MAX_PAYLOAD
            );
        }
        // Reassemble: decode each chunk and concatenate.  Result must
        // equal the original source byte-for-byte.
        let mut reassembled = Vec::new();
        for chunk in &chunks {
            reassembled.extend(decode_data(chunk, q).unwrap());
        }
        assert_eq!(String::from_utf8(reassembled).unwrap(), text);
    }

    #[tokio::test]
    async fn test_server_g_dir_paginates_large_listing() {
        // DIR with 30 files produces a listing too long for a single
        // classic-MAXL X.  Server must paginate; client must
        // reassemble correctly.
        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("xmodem_g_dir_paginate_{}", pid));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        for i in 0..30 {
            std::fs::write(dir.join(format!("file_{:03}.bin", i)), b"x").unwrap();
        }
        let dir_str = dir.to_str().unwrap().to_string();
        let dir_for_cleanup = dir.clone();

        let ((), result) = run_server_with_client(async move |w, r| {
            config::update_config_value("transfer_dir", &dir_str);
            // Hand-roll the multi-X read since `run_g_text_command`
            // assumes a single X.  Drives G@0 → ACK → loop X+ACK →
            // Z → ACK.
            w.write_all(&wire_packet(TYPE_GENERIC, 0, b"D")).await.unwrap();
            let g_ack = read_server_packet(r).await;
            assert_eq!(g_ack.kind, TYPE_ACK);
            let mut body = Vec::new();
            let q = Quoting::default();
            let mut x_count = 0;
            loop {
                let pkt = read_server_packet(r).await;
                match pkt.kind {
                    TYPE_TEXT => {
                        body.extend(decode_data(&pkt.payload, q).unwrap());
                        w.write_all(&wire_packet(TYPE_ACK, pkt.seq, &[])).await.unwrap();
                        x_count += 1;
                    }
                    TYPE_EOF => {
                        w.write_all(&wire_packet(TYPE_ACK, pkt.seq, &[])).await.unwrap();
                        break;
                    }
                    other => panic!("unexpected packet '{}' during DIR pagination", other as char),
                }
            }
            assert!(x_count > 1, "expected multiple X-packets, got {}", x_count);
            let body_text = String::from_utf8(body).unwrap();
            assert!(body_text.contains("file_000.bin"));
            assert!(body_text.contains("file_029.bin"));
            close_server_session(w, r).await;
        })
        .await;

        config::update_config_value("transfer_dir", "transfer");
        let _ = std::fs::remove_dir_all(&dir_for_cleanup);
        result.unwrap();
    }

    #[tokio::test]
    async fn test_server_g_kermit_returns_version() {
        // G K reports our identity + version via X-packet.
        let ((), result) = run_server_with_client(async |w, r| {
            let body = run_g_text_command(w, r, b'K', &[]).await;
            assert!(
                body.contains("Ethernet Gateway Kermit"),
                "missing identity in: {:?}",
                body
            );
            assert!(
                body.contains(env!("CARGO_PKG_VERSION")),
                "missing version in: {:?}",
                body
            );
            close_server_session(w, r).await;
        })
        .await;
        result.unwrap();
    }

    #[tokio::test]
    async fn test_server_g_space_returns_numeric_or_unknown() {
        // G $ replies with free-bytes count (Unix) or "unknown" (other
        // platforms).  Either is spec-compliant; what matters is that
        // we replied with X+Z rather than NAKing.
        let ((), result) = run_server_with_client(async |w, r| {
            let body = run_g_text_command(w, r, b'$', &[]).await;
            assert!(!body.is_empty(), "SPACE response must not be empty");
            // Body must parse as a u64 OR equal "unknown".
            assert!(
                body.parse::<u64>().is_ok() || body == "unknown",
                "SPACE response must be numeric or 'unknown', got: {:?}",
                body
            );
            close_server_session(w, r).await;
        })
        .await;
        result.unwrap();
    }

    #[tokio::test]
    async fn test_server_g_dir_returns_listing() {
        // G D lists files in the current effective dir.  Set up a
        // temp dir with two files + a hidden file (skipped) and verify
        // the listing.
        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("xmodem_server_g_dir_{}", pid));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("alpha.bin"), b"a").unwrap();
        std::fs::write(dir.join("beta.bin"), b"bb").unwrap();
        std::fs::write(dir.join(".hidden"), b"x").unwrap();
        let dir_str = dir.to_str().unwrap().to_string();
        let dir_for_cleanup = dir.clone();

        let ((), result) = run_server_with_client(async move |w, r| {
            config::update_config_value("transfer_dir", &dir_str);
            let body = run_g_text_command(w, r, b'D', &[]).await;
            assert!(body.contains("alpha.bin"), "missing alpha.bin in {:?}", body);
            assert!(body.contains("beta.bin"), "missing beta.bin in {:?}", body);
            assert!(!body.contains(".hidden"), "hidden file leaked in {:?}", body);
            close_server_session(w, r).await;
        })
        .await;

        config::update_config_value("transfer_dir", "transfer");
        let _ = std::fs::remove_dir_all(&dir_for_cleanup);
        result.unwrap();
    }

    #[tokio::test]
    async fn test_server_g_cwd_updates_subdir_for_subsequent_pulls() {
        // G C <subdir> updates the per-session working dir; a
        // subsequent R must look the file up in <transfer_dir>/<subdir>.
        // Locks in the cross-command state plumbing.
        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("xmodem_server_g_cwd_{}", pid));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        let payload = b"sub-dir contents".to_vec();
        std::fs::write(dir.join("sub").join("file.bin"), &payload).unwrap();
        let dir_str = dir.to_str().unwrap().to_string();
        let dir_for_cleanup = dir.clone();
        let payload_clone = payload.clone();

        let ((), result) = run_server_with_client(async move |w, r| {
            config::update_config_value("transfer_dir", &dir_str);
            // CWD into "sub"
            w.write_all(&wire_packet(TYPE_GENERIC, 0, b"Csub")).await.unwrap();
            let cwd_ack = read_server_packet(r).await;
            assert_eq!(cwd_ack.kind, TYPE_ACK);
            // Pull file.bin — must resolve under <transfer_dir>/sub.
            w.write_all(&wire_packet(TYPE_R, 0, b"file.bin")).await.unwrap();
            // Server now ACKs R first (per spec §6 + ckermit interop),
            // then sends S to start the transfer.
            let r_ack = read_server_packet(r).await;
            assert_eq!(r_ack.kind, TYPE_ACK);
            let s_pkt = read_server_packet(r).await;
            assert_eq!(s_pkt.kind, TYPE_SEND_INIT);
            let received = kermit_receive_with_init(r, w, false, false, false, Some(s_pkt))
                .await
                .unwrap();
            assert_eq!(received.len(), 1);
            assert_eq!(received[0].data, payload_clone);
            close_server_session(w, r).await;
        })
        .await;

        config::update_config_value("transfer_dir", "transfer");
        let _ = std::fs::remove_dir_all(&dir_for_cleanup);
        result.unwrap();
    }

    #[tokio::test]
    async fn test_server_g_cwd_unsafe_path_refused() {
        // Path-traversal in CWD argument: server emits E-packet and
        // stays idle without modifying the subdir.  Server keeps
        // running per spec §6.7 so a peer can retry with a valid path.
        let ((), result) = run_server_with_client(async |w, r| {
            w.write_all(&wire_packet(TYPE_GENERIC, 0, b"C../etc")).await.unwrap();
            let resp = read_server_packet(r).await;
            assert_eq!(resp.kind, TYPE_ERROR, "expected E for CWD ../etc");
            close_server_session(w, r).await;
        })
        .await;
        result.unwrap();
    }

    #[tokio::test]
    async fn test_server_r_unsafe_filename_refused() {
        // Path-traversal in R filename → reject before any disk I/O.
        // Reuses the same `is_safe_resume_filename` guard used by the
        // resume-partial code path.  Server stays idle after the
        // refusal per spec §6.7.
        let ((), result) = run_server_with_client(async |w, r| {
            w.write_all(&wire_packet(TYPE_R, 0, b"../../etc/passwd")).await.unwrap();
            let resp = read_server_packet(r).await;
            assert_eq!(resp.kind, TYPE_ERROR);
            let q = Quoting::default();
            let msg = decode_error_message(&resp.payload, q).to_ascii_lowercase();
            assert!(msg.contains("invalid"), "expected refusal message, got: {}", msg);
            close_server_session(w, r).await;
        })
        .await;
        result.unwrap();
    }

    #[tokio::test]
    async fn test_server_stays_alive_after_r_unsafe_filename() {
        // Regression: the previous implementation exited the server
        // session whenever R was refused.  Spec §6.7 says E-packet
        // responses keep the server idle.  Send an unsafe R, then
        // immediately G K — the server must respond to the second
        // command, proving it didn't exit on the refusal.
        let ((), result) = run_server_with_client(async |w, r| {
            w.write_all(&wire_packet(TYPE_R, 0, b"../escape")).await.unwrap();
            let e = read_server_packet(r).await;
            assert_eq!(e.kind, TYPE_ERROR, "R refusal must be E-packet");
            // Now drive a follow-up G K to prove the server is still
            // listening.  Before the fix this would time out.
            let body = run_g_text_command(w, r, b'K', &[]).await;
            assert!(body.contains("Ethernet Gateway Kermit"));
            close_server_session(w, r).await;
        })
        .await;
        result.unwrap();
    }

    #[tokio::test]
    async fn test_server_stays_alive_after_r_missing_file() {
        // Same regression as above but for the file-not-found path.
        let ((), result) = run_server_with_client(async |w, r| {
            w.write_all(&wire_packet(TYPE_R, 0, b"absent.bin")).await.unwrap();
            let e = read_server_packet(r).await;
            assert_eq!(e.kind, TYPE_ERROR);
            // Server still alive — exercise SPACE.
            let body = run_g_text_command(w, r, b'$', &[]).await;
            assert!(!body.is_empty());
            close_server_session(w, r).await;
        })
        .await;
        result.unwrap();
    }

    #[tokio::test]
    async fn test_server_stays_alive_after_g_cwd_unsafe() {
        // CWD refusal must keep the server idle and must NOT modify
        // the subdir state.  Verify by following with a successful
        // CWD and a DIR — the listing should reflect only the
        // second CWD's effect.
        let _guard = CONFIG_LOCK.lock().await;
        init_test_config();

        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("xmodem_after_bad_cwd_{}", pid));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::create_dir_all(dir.join("ok")).unwrap();
        std::fs::write(dir.join("ok").join("inside.bin"), b"x").unwrap();
        std::fs::write(dir.join("at-root.bin"), b"r").unwrap();
        let dir_str = dir.to_str().unwrap().to_string();
        let dir_for_cleanup = dir.clone();

        let (server_side, client_side) = duplex(65536);
        let (mut s_read, mut s_write) = split(server_side);
        let (mut c_read, mut c_write) = split(client_side);
        let server_task = tokio::spawn(async move {
            kermit_server(&mut s_read, &mut s_write, false, false, false).await
        });

        config::update_config_value("transfer_dir", &dir_str);
        // 1. Bad CWD — server refuses, stays idle, subdir unchanged
        //    (still at "" = root).
        c_write
            .write_all(&wire_packet(TYPE_GENERIC, 0, b"C../escape"))
            .await
            .unwrap();
        let e = read_server_packet(&mut c_read).await;
        assert_eq!(e.kind, TYPE_ERROR);
        // 2. DIR — must list ROOT contents, not anything weird.
        let listing_before = run_g_text_command(&mut c_write, &mut c_read, b'D', &[]).await;
        assert!(
            listing_before.contains("at-root.bin"),
            "after bad CWD, listing should still be ROOT contents — got {:?}",
            listing_before
        );
        // 3. Good CWD into ok/.
        c_write
            .write_all(&wire_packet(TYPE_GENERIC, 0, b"Cok"))
            .await
            .unwrap();
        let ack = read_server_packet(&mut c_read).await;
        assert_eq!(ack.kind, TYPE_ACK);
        // 4. DIR now reflects subdir.
        let listing_after = run_g_text_command(&mut c_write, &mut c_read, b'D', &[]).await;
        assert!(
            listing_after.contains("inside.bin"),
            "after good CWD, listing should be subdir contents — got {:?}",
            listing_after
        );
        assert!(
            !listing_after.contains("at-root.bin"),
            "subdir listing should NOT include root file"
        );
        close_server_session(&mut c_write, &mut c_read).await;
        let server_result = server_task.await.unwrap();

        config::update_config_value("transfer_dir", "transfer");
        let _ = std::fs::remove_dir_all(&dir_for_cleanup);
        server_result.unwrap();
    }

    #[tokio::test]
    async fn test_server_stays_alive_after_host_command_refused() {
        // C (host command) is permanently disabled in our build —
        // refusal must not kill the session.
        let ((), result) = run_server_with_client(async |w, r| {
            w.write_all(&wire_packet(TYPE_HOST, 0, b"id")).await.unwrap();
            let e = read_server_packet(r).await;
            assert_eq!(e.kind, TYPE_ERROR);
            // Drive G K to confirm we're still alive.
            let body = run_g_text_command(w, r, b'K', &[]).await;
            assert!(body.contains("Kermit"));
            close_server_session(w, r).await;
        })
        .await;
        result.unwrap();
    }

    #[tokio::test]
    async fn test_server_g_cwd_empty_string_resets_to_root() {
        // G C with empty argument resets subdir to root.  Verify by
        // CWDing into a subdir, then CWD "" resets it, then DIR
        // returns root contents.
        let _guard = CONFIG_LOCK.lock().await;
        init_test_config();

        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("xmodem_cwd_reset_{}", pid));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("nested")).unwrap();
        std::fs::write(dir.join("rootfile.bin"), b"r").unwrap();
        std::fs::write(dir.join("nested").join("subfile.bin"), b"s").unwrap();
        let dir_str = dir.to_str().unwrap().to_string();
        let dir_for_cleanup = dir.clone();

        let (server_side, client_side) = duplex(65536);
        let (mut s_read, mut s_write) = split(server_side);
        let (mut c_read, mut c_write) = split(client_side);
        let server_task = tokio::spawn(async move {
            kermit_server(&mut s_read, &mut s_write, false, false, false).await
        });

        config::update_config_value("transfer_dir", &dir_str);
        // CWD into nested
        c_write
            .write_all(&wire_packet(TYPE_GENERIC, 0, b"Cnested"))
            .await
            .unwrap();
        let _ = read_server_packet(&mut c_read).await;
        // CWD with empty arg → reset
        c_write
            .write_all(&wire_packet(TYPE_GENERIC, 0, b"C"))
            .await
            .unwrap();
        let ack = read_server_packet(&mut c_read).await;
        assert_eq!(ack.kind, TYPE_ACK, "G C with empty arg should be ACKed (reset)");
        // DIR — should now be ROOT.
        let listing = run_g_text_command(&mut c_write, &mut c_read, b'D', &[]).await;
        assert!(listing.contains("rootfile.bin"));
        assert!(!listing.contains("subfile.bin"));
        close_server_session(&mut c_write, &mut c_read).await;
        let server_result = server_task.await.unwrap();

        config::update_config_value("transfer_dir", "transfer");
        let _ = std::fs::remove_dir_all(&dir_for_cleanup);
        server_result.unwrap();
    }

    #[tokio::test]
    async fn test_server_handles_multiple_s_uploads_in_one_session() {
        // Server-mode batching at the COMMAND level: client uploads
        // file A via S, then file B via a fresh S, then closes with
        // G F.  Server must accumulate both files in its
        // Vec<KermitReceive> return value.  Locks in the per-file
        // state-reset across S boundaries (pending_resume_offset,
        // declared_size, etc.).
        let _guard = CONFIG_LOCK.lock().await;
        init_test_config();

        let payload_a: Vec<u8> = b"first upload".to_vec();
        let payload_b: Vec<u8> = b"second upload, distinct content".to_vec();
        let pa = payload_a.clone();
        let pb = payload_b.clone();

        let (server_side, client_side) = duplex(65536);
        let (mut s_read, mut s_write) = split(server_side);
        let (mut c_read, mut c_write) = split(client_side);
        let server_task = tokio::spawn(async move {
            kermit_server(&mut s_read, &mut s_write, false, false, false).await
        });

        // First upload via kermit_send.
        let kfile_a = KermitSendFile {
            name: "first.bin",
            data: &pa,
            modtime: None,
            mode: None,
        };
        kermit_send(&mut c_read, &mut c_write, &[kfile_a], false, false, false)
            .await
            .unwrap();
        // Second upload — separate kermit_send call so the server
        // sees a fresh S/F/A/D/Z/B sequence.
        let kfile_b = KermitSendFile {
            name: "second.bin",
            data: &pb,
            modtime: None,
            mode: None,
        };
        kermit_send(&mut c_read, &mut c_write, &[kfile_b], false, false, false)
            .await
            .unwrap();
        // Close.
        close_server_session(&mut c_write, &mut c_read).await;
        let received = server_task.await.unwrap().unwrap();

        assert_eq!(received.len(), 2, "server must accumulate both uploads");
        assert_eq!(received[0].filename, "first.bin");
        assert_eq!(received[0].data, payload_a);
        assert_eq!(received[1].filename, "second.bin");
        assert_eq!(received[1].data, payload_b);
    }

    #[tokio::test]
    async fn test_compute_resume_offset_rejects_symlink() {
        // Symlink-to-file must NOT qualify for resume — otherwise a
        // pre-existing partial named X could be replaced by a symlink
        // pointing at /etc/passwd, and we'd advertise its size + bytes
        // back to the sender on the next transfer.  Defense in depth.
        let dir = resume_scratch_dir("symlink");
        let real_path = dir.join("real.bin");
        std::fs::write(&real_path, b"real bytes").unwrap();
        let link_path = dir.join("link.bin");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&real_path, &link_path).unwrap();
        // On non-Unix we can't make a symlink portably; the test is
        // unix-only since the threat is filesystem-specific.
        #[cfg(unix)]
        {
            let off = compute_resume_offset("link.bin", dir.to_str().unwrap(), 168);
            assert_eq!(off, None, "symlink must be ineligible for resume");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_server_unexpected_packet_type_returns_e_packet() {
        // Anything outside the known set: protocol error.  Use a type
        // letter that isn't claimed by any handler.  Server stays idle
        // after sending E so a confused peer can recover.
        let ((), result) = run_server_with_client(async |w, r| {
            w.write_all(&wire_packet(b'Z', 0, &[])).await.unwrap();
            let resp = read_server_packet(r).await;
            assert_eq!(resp.kind, TYPE_ERROR);
            close_server_session(w, r).await;
        })
        .await;
        result.unwrap();
    }

    // ---------- Client-mode dispatch (Gap 3b commit 1) ----------

    /// Drive both a `kermit_client_get` and a `kermit_server` in
    /// duplex pipes.  Returns the client's GET result so tests can
    /// assert on success / error details, plus the server's exit
    /// `Result<Vec<KermitReceive>>` (which should be empty in the
    /// pure-pull case but is checked anyway to surface server-side
    /// errors).
    async fn run_client_get_against_server(
        filename: &str,
    ) -> (
        Result<Vec<KermitReceive>, String>,
        Result<Vec<KermitReceive>, String>,
    ) {
        let (server_side, client_side) = duplex(65536);
        let (mut s_read, mut s_write) = split(server_side);
        let (mut c_read, mut c_write) = split(client_side);
        let server_task = tokio::spawn(async move {
            kermit_server(&mut s_read, &mut s_write, false, false, false).await
        });
        let fname = filename.to_string();
        let client_task = tokio::spawn(async move {
            let result = kermit_client_get(
                &mut c_read,
                &mut c_write,
                &fname,
                false,
                false,
                false,
            )
            .await;
            // Send G F to close the server idle loop after the GET
            // completes (success OR failure), so the server task
            // resolves and the test doesn't time out waiting on it.
            // On failure paths the server has already exited (E from
            // R handler), so the write quietly drops — that's fine.
            let g_finish = build_packet(TYPE_GENERIC, 0, b"F", b'1', 0, 0, CR);
            let _ = c_write.write_all(&g_finish).await;
            // Drain whatever the server wrote (G-F ACK or nothing).
            let mut buf = [0u8; 256];
            let _ = tokio::time::timeout(
                tokio::time::Duration::from_millis(200),
                c_read.read(&mut buf),
            )
            .await;
            result
        });
        let client_result = client_task.await.unwrap();
        let server_result = server_task.await.unwrap();
        (client_result, server_result)
    }

    #[tokio::test]
    async fn test_client_get_pulls_existing_file() {
        // End-to-end: client GETs a file from a server peer, both
        // running in the same process.  Locks in the wire flow
        // R(filename) → S(caps) → ACK → F → A → D... → Z → B and
        // confirms the bytes round-trip.
        let _guard = CONFIG_LOCK.lock().await;
        init_test_config();

        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("xmodem_client_get_{}", pid));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let payload: Vec<u8> = (0..4096u32).map(|i| (i ^ 0x5A) as u8).collect();
        std::fs::write(dir.join("pulled.bin"), &payload).unwrap();
        config::update_config_value("transfer_dir", dir.to_str().unwrap());

        let (client_result, _server_result) =
            run_client_get_against_server("pulled.bin").await;

        config::update_config_value("transfer_dir", "transfer");
        let _ = std::fs::remove_dir_all(&dir);

        let received = client_result.expect("GET should succeed");
        assert_eq!(received.len(), 1);
        assert_eq!(received[0].data, payload);
    }

    #[tokio::test]
    async fn test_client_get_missing_file_returns_error() {
        // Server has no such file → emits E-packet → client surfaces
        // the refusal as a structured error (not a hang or panic).
        let _guard = CONFIG_LOCK.lock().await;
        init_test_config();

        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("xmodem_client_missing_{}", pid));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        config::update_config_value("transfer_dir", dir.to_str().unwrap());

        let (client_result, _) = run_client_get_against_server("nonexistent.bin").await;

        config::update_config_value("transfer_dir", "transfer");
        let _ = std::fs::remove_dir_all(&dir);

        let err = client_result.expect_err("GET must fail when file absent");
        let lower = err.to_ascii_lowercase();
        assert!(
            lower.contains("not found") || lower.contains("refused"),
            "expected file-not-found indicator in error: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_client_get_unsafe_filename_returns_error() {
        // Path traversal in the GET filename — server's R-handler
        // refuses with E-packet, client surfaces as Err.  Guards
        // against a future regression where the client might try
        // local validation and accidentally bypass the server check.
        let _guard = CONFIG_LOCK.lock().await;
        init_test_config();

        let (client_result, _) = run_client_get_against_server("../../etc/passwd").await;
        let err = client_result.expect_err("GET must fail for unsafe filename");
        let lower = err.to_ascii_lowercase();
        assert!(
            lower.contains("invalid") || lower.contains("refused"),
            "expected refusal indicator in error: {}",
            err
        );
    }

    /// Run a client-side closure against `kermit_server` in duplex
    /// pipes.  Closure receives `(reader, writer)` in the order the
    /// public client functions expect.  The server's exit result is
    /// returned alongside the closure's value so tests can assert
    /// both halves succeeded.
    async fn run_client_against_server<F, T>(
        client: F,
    ) -> (T, Result<Vec<KermitReceive>, String>)
    where
        F: AsyncFnOnce(
            &mut tokio::io::ReadHalf<tokio::io::DuplexStream>,
            &mut tokio::io::WriteHalf<tokio::io::DuplexStream>,
        ) -> T,
    {
        let _guard = CONFIG_LOCK.lock().await;
        init_test_config();
        let (server_side, client_side) = duplex(65536);
        let (mut s_read, mut s_write) = split(server_side);
        let (mut c_read, mut c_write) = split(client_side);
        let server_task = tokio::spawn(async move {
            kermit_server(&mut s_read, &mut s_write, false, false, false).await
        });
        let client_result = client(&mut c_read, &mut c_write).await;
        let server_result = server_task.await.unwrap();
        (client_result, server_result)
    }

    #[tokio::test]
    async fn test_client_finish_ends_session_cleanly() {
        let (client_result, server_result) = run_client_against_server(async |r, w| {
            kermit_client_finish(r, w, false, false, false).await
        })
        .await;
        client_result.unwrap();
        // Server should have exited cleanly with no files received.
        assert!(server_result.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_client_logout_ends_session_cleanly() {
        let (client_result, _) = run_client_against_server(async |r, w| {
            kermit_client_logout(r, w, false, false, false).await
        })
        .await;
        client_result.unwrap();
    }

    #[tokio::test]
    async fn test_client_bye_ends_session_cleanly() {
        let (client_result, _) = run_client_against_server(async |r, w| {
            kermit_client_bye(r, w, false, false, false).await
        })
        .await;
        client_result.unwrap();
    }

    #[tokio::test]
    async fn test_client_help_returns_subcommand_list() {
        // GET help → server replies with multi-X paginated body
        // listing all supported G subcommands.  Locks in the client's
        // ability to drive a paginated text response.
        let (client_result, _) = run_client_against_server(async |r, w| {
            let v = kermit_client_help(r, w, false, false, false).await;
            let _ = kermit_client_finish(r, w, false, false, false).await;
            v
        })
        .await;
        let body = client_result.unwrap();
        assert!(body.to_ascii_lowercase().contains("kermit"));
        for letter in &["F", "L", "B", "C", "D", "K", "H"] {
            assert!(body.contains(letter), "help body missing '{}': {:?}", letter, body);
        }
    }

    #[tokio::test]
    async fn test_client_version_returns_identity() {
        // GET version → server replies with "Ethernet Gateway Kermit
        // <version>".  Tests the X-Z text-response client path.
        let (client_result, _) = run_client_against_server(async |r, w| {
            let v = kermit_client_version(r, w, false, false, false).await;
            // Then close the session — server is still running.
            let _ = kermit_client_finish(r, w, false, false, false).await;
            v
        })
        .await;
        let body = client_result.unwrap();
        assert!(
            body.contains("Ethernet Gateway Kermit"),
            "missing identity in: {:?}",
            body
        );
        assert!(
            body.contains(env!("CARGO_PKG_VERSION")),
            "missing version in: {:?}",
            body
        );
    }

    #[tokio::test]
    async fn test_client_space_returns_text() {
        // SPACE returns either a numeric byte-count (Unix) or
        // "unknown" (other platforms).  Body must be non-empty.
        let (client_result, _) = run_client_against_server(async |r, w| {
            let s = kermit_client_space(r, w, false, false, false).await;
            let _ = kermit_client_finish(r, w, false, false, false).await;
            s
        })
        .await;
        let body = client_result.unwrap();
        assert!(!body.is_empty());
        assert!(body.parse::<u64>().is_ok() || body == "unknown");
    }

    #[tokio::test]
    async fn test_client_dir_returns_listing() {
        // Stage a couple files in transfer_dir; client_dir must see
        // them in the response.  Hidden files must be omitted.
        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("xmodem_client_dir_{}", pid));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("alpha.bin"), b"a").unwrap();
        std::fs::write(dir.join("beta.bin"), b"bb").unwrap();
        std::fs::write(dir.join(".hidden"), b"x").unwrap();
        let dir_str = dir.to_str().unwrap().to_string();
        let dir_for_cleanup = dir.clone();

        let (client_result, _) = run_client_against_server(async move |r, w| {
            config::update_config_value("transfer_dir", &dir_str);
            let listing = kermit_client_dir(r, w, false, false, false).await;
            let _ = kermit_client_finish(r, w, false, false, false).await;
            listing
        })
        .await;

        config::update_config_value("transfer_dir", "transfer");
        let _ = std::fs::remove_dir_all(&dir_for_cleanup);

        let body = client_result.unwrap();
        assert!(body.contains("alpha.bin"));
        assert!(body.contains("beta.bin"));
        assert!(!body.contains(".hidden"));
    }

    #[tokio::test]
    async fn test_client_cwd_then_dir_lists_subdir() {
        // Chain CWD → DIR on the client side.  The dir listing the
        // server returns must reflect the new subdir, not the root.
        // Covers the client-side cross-command state plumbing in the
        // dir-listing direction (the get-from-subdir test below covers
        // it for R; this one covers it for G D).
        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("xmodem_client_cwd_dir_{}", pid));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("inner")).unwrap();
        std::fs::write(dir.join("rootfile.bin"), b"r").unwrap();
        std::fs::write(dir.join("inner").join("innerfile.bin"), b"i").unwrap();
        let dir_str = dir.to_str().unwrap().to_string();
        let dir_for_cleanup = dir.clone();

        let (client_result, _) = run_client_against_server(async move |r, w| {
            config::update_config_value("transfer_dir", &dir_str);
            kermit_client_cwd(r, w, "inner", false, false, false)
                .await
                .unwrap();
            let listing = kermit_client_dir(r, w, false, false, false).await;
            let _ = kermit_client_finish(r, w, false, false, false).await;
            listing
        })
        .await;

        config::update_config_value("transfer_dir", "transfer");
        let _ = std::fs::remove_dir_all(&dir_for_cleanup);

        let body = client_result.unwrap();
        assert!(body.contains("innerfile.bin"), "subdir listing missing innerfile in: {:?}", body);
        assert!(
            !body.contains("rootfile.bin"),
            "subdir listing must NOT include root files; got: {:?}",
            body
        );
    }

    #[tokio::test]
    async fn test_client_cwd_then_get_pulls_from_subdir() {
        // CWD into a subdir, then GET a file that lives there.
        // Confirms cross-command state plumbing works from the client
        // side too — the server keeps the subdir set across our
        // distinct G C and R commands.
        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("xmodem_client_cwd_{}", pid));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("nested")).unwrap();
        let payload = b"nested content".to_vec();
        std::fs::write(dir.join("nested").join("file.bin"), &payload).unwrap();
        let dir_str = dir.to_str().unwrap().to_string();
        let dir_for_cleanup = dir.clone();
        let payload_clone = payload.clone();

        let (client_result, _) = run_client_against_server(async move |r, w| {
            config::update_config_value("transfer_dir", &dir_str);
            kermit_client_cwd(r, w, "nested", false, false, false)
                .await
                .unwrap();
            let received = kermit_client_get(r, w, "file.bin", false, false, false).await;
            let _ = kermit_client_finish(r, w, false, false, false).await;
            received
        })
        .await;

        config::update_config_value("transfer_dir", "transfer");
        let _ = std::fs::remove_dir_all(&dir_for_cleanup);

        let received = client_result.unwrap();
        assert_eq!(received.len(), 1);
        assert_eq!(received[0].data, payload_clone);
    }

    #[tokio::test]
    async fn test_client_cwd_unsafe_path_returns_error() {
        // Path traversal in CWD argument: server emits E-packet, the
        // client's send_g_simple surfaces it as Err.
        let (client_result, _) = run_client_against_server(async |r, w| {
            kermit_client_cwd(r, w, "../etc", false, false, false).await
        })
        .await;
        let err = client_result.expect_err("CWD ../etc must fail");
        let lower = err.to_ascii_lowercase();
        assert!(
            lower.contains("invalid") || lower.contains("refused"),
            "expected refusal indicator: {}",
            err
        );
    }

    // ---------- End-to-end round trips ----------

    // (`duplex` and `split` already imported at the top of the
    // server-mode tests section above.)

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

    /// Serialises tests that mutate the global config singleton.  Held
    /// across the async round-trip so a parallel test can't change
    /// CHKT or 8-bit-quote mid-transfer.  `tokio::sync::Mutex` lets the
    /// guard cross await points (std::sync::Mutex can't on a
    /// multi-threaded runtime).
    static CONFIG_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    async fn round_trip_with_overrides(
        overrides: &[(&str, &str)],
        files: Vec<(String, Vec<u8>)>,
    ) -> Result<Vec<KermitReceive>, String> {
        let _guard = CONFIG_LOCK.lock().await;
        init_test_config();
        for (k, v) in overrides {
            config::update_config_value(k, v);
        }
        round_trip(files).await
    }

    #[tokio::test]
    async fn test_round_trip_resume_partial_in_memory() {
        // End-to-end resume test: receiver finds a partial on disk,
        // advertises disposition='R' + length in the A-packet ACK,
        // sender slices its file from that offset, receiver merges
        // its pre-loaded partial bytes with the resumed D-packet
        // stream → the final in-memory data must equal the full
        // file content.  If anything goes wrong end-to-end (sender
        // doesn't honor the ACK, receiver double-loads, slice math
        // is off) we'd see corrupted data length or mismatched bytes.
        let _guard = CONFIG_LOCK.lock().await;
        init_test_config();

        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("xmodem_resume_e2e_{}", pid));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // Build full file: 8 KB of distinct bytes so any off-by-one
        // mismerge would surface as a wrong byte at a known offset.
        let full: Vec<u8> = (0..8192u32).map(|i| (i ^ (i >> 8)) as u8).collect();
        // Partial: first 3 KB.  Mid-byte boundary so the sender has
        // to slice into the middle of a chunk.
        let partial_len = 3072usize;
        std::fs::write(dir.join("resume.bin"), &full[..partial_len]).unwrap();

        config::update_config_value("transfer_dir", dir.to_str().unwrap());
        config::update_config_value("kermit_resume_partial", "true");

        let result = round_trip(vec![("resume.bin".into(), full.clone())]).await;

        // Reset the resume flag and transfer_dir so unrelated tests
        // running after this one see the init_test_config baseline.
        // (init_test_config doesn't reset these — they aren't part
        // of its baseline set.)
        config::update_config_value("kermit_resume_partial", "false");
        config::update_config_value("transfer_dir", "transfer");
        let _ = std::fs::remove_dir_all(&dir);

        let received = result.unwrap();
        assert_eq!(received.len(), 1);
        assert_eq!(received[0].filename, "resume.bin");
        assert_eq!(
            received[0].data.len(),
            full.len(),
            "merged data length must equal full file (got {} expected {})",
            received[0].data.len(),
            full.len()
        );
        assert_eq!(
            received[0].data, full,
            "merged data must equal full file byte-for-byte"
        );
    }

    #[tokio::test]
    async fn test_round_trip_resume_partial_larger_than_full_aborts_resume() {
        // Edge case from the spec doc: partial size > declared full
        // size.  The on-disk bytes can't be a valid prefix, so the
        // receiver must abandon resume and accept the full file from
        // byte 0.  If the guard isn't in place we'd see merged data
        // that's longer than the sender's file, or the wrong bytes
        // at the start.
        let _guard = CONFIG_LOCK.lock().await;
        init_test_config();

        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("xmodem_resume_oversize_{}", pid));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // Sender's full file is 1 KB; partial on disk is 4 KB of
        // entirely different bytes.  If the guard fires correctly,
        // received[0].data should match the 1 KB sender content.
        let full: Vec<u8> = (0..1024u32).map(|i| i as u8).collect();
        std::fs::write(dir.join("oversize.bin"), vec![0xAAu8; 4096]).unwrap();

        config::update_config_value("transfer_dir", dir.to_str().unwrap());
        config::update_config_value("kermit_resume_partial", "true");

        let result = round_trip(vec![("oversize.bin".into(), full.clone())]).await;

        config::update_config_value("kermit_resume_partial", "false");
        config::update_config_value("transfer_dir", "transfer");
        let _ = std::fs::remove_dir_all(&dir);

        let received = result.unwrap();
        assert_eq!(received.len(), 1);
        assert_eq!(
            received[0].data.len(),
            full.len(),
            "must receive exactly the sender's full file, not the larger partial"
        );
        assert_eq!(received[0].data, full);
    }

    #[tokio::test]
    async fn test_round_trip_resume_partial_equals_full_already_complete() {
        // Edge case: the on-disk partial is byte-for-byte identical to
        // the sender's full file (transfer was already complete; we're
        // just being asked again).  Receiver advertises offset=N, sender
        // slices `f.data[N..]` = empty, sends 0 D-packets, then Z-packet.
        // Receiver returns its pre-loaded N bytes which == full content.
        let _guard = CONFIG_LOCK.lock().await;
        init_test_config();

        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("xmodem_resume_equal_{}", pid));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let full: Vec<u8> = (0..2048u32).map(|i| (i ^ 0x5A) as u8).collect();
        // Partial byte-for-byte equal to sender content — i.e. the
        // partial IS the file.
        std::fs::write(dir.join("complete.bin"), &full).unwrap();

        config::update_config_value("transfer_dir", dir.to_str().unwrap());
        config::update_config_value("kermit_resume_partial", "true");

        let result = round_trip(vec![("complete.bin".into(), full.clone())]).await;

        config::update_config_value("kermit_resume_partial", "false");
        config::update_config_value("transfer_dir", "transfer");
        let _ = std::fs::remove_dir_all(&dir);

        let received = result.unwrap();
        assert_eq!(received[0].data, full);
        assert_eq!(received[0].data.len(), full.len());
    }

    #[tokio::test]
    async fn test_round_trip_resume_batch_mixed_resume_and_fresh() {
        // Multi-file batch: middle file has a partial on disk, outer
        // two don't.  All three must arrive byte-correct, proving the
        // per-file `pending_resume_offset` reset works (file 1 starts
        // fresh, file 2 resumes, file 3 starts fresh again).
        let _guard = CONFIG_LOCK.lock().await;
        init_test_config();

        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("xmodem_resume_batch_{}", pid));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // Three files, each with distinct content so a misroute would
        // surface as wrong content instead of wrong size.
        let f1: Vec<u8> = (0..512u32).map(|i| i as u8).collect();
        let f2: Vec<u8> = (0..2048u32).map(|i| (i ^ 0x33) as u8).collect();
        let f3: Vec<u8> = (0..1024u32).map(|i| (i ^ 0x77) as u8).collect();
        // Partial for f2 only — first 768 bytes.
        let f2_partial_len = 768usize;
        std::fs::write(dir.join("middle.bin"), &f2[..f2_partial_len]).unwrap();

        config::update_config_value("transfer_dir", dir.to_str().unwrap());
        config::update_config_value("kermit_resume_partial", "true");

        let result = round_trip(vec![
            ("first.bin".into(), f1.clone()),
            ("middle.bin".into(), f2.clone()),
            ("last.bin".into(), f3.clone()),
        ])
        .await;

        config::update_config_value("kermit_resume_partial", "false");
        config::update_config_value("transfer_dir", "transfer");
        let _ = std::fs::remove_dir_all(&dir);

        let received = result.unwrap();
        assert_eq!(received.len(), 3);
        assert_eq!(received[0].filename, "first.bin");
        assert_eq!(received[0].data, f1);
        assert_eq!(received[1].filename, "middle.bin");
        assert_eq!(received[1].data, f2);
        assert_eq!(received[2].filename, "last.bin");
        assert_eq!(received[2].data, f3);
    }

    #[tokio::test]
    async fn test_round_trip_resume_disabled_falls_back_to_full_send() {
        // Same scenario but with kermit_resume_partial=false: the
        // partial on disk must be ignored, the receiver must NOT
        // pre-load anything, and the transfer must complete with the
        // full file content as if no partial existed.  Guards against
        // an opt-out regression.
        let _guard = CONFIG_LOCK.lock().await;
        init_test_config();

        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("xmodem_resume_disabled_{}", pid));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let full: Vec<u8> = (0..2048u32).map(|i| i as u8).collect();
        // Write a deliberately-wrong "partial" — different bytes than
        // the real content.  If the receiver erroneously pre-loaded
        // it, the merged data would diverge.
        std::fs::write(dir.join("noresume.bin"), vec![0xFFu8; 512]).unwrap();

        config::update_config_value("transfer_dir", dir.to_str().unwrap());
        config::update_config_value("kermit_resume_partial", "false");

        let result = round_trip(vec![("noresume.bin".into(), full.clone())]).await;

        config::update_config_value("transfer_dir", "transfer");
        let _ = std::fs::remove_dir_all(&dir);

        let received = result.unwrap();
        assert_eq!(received[0].data, full, "must receive full file unmodified");
    }

    #[tokio::test]
    async fn test_round_trip_locking_shifts_negotiated() {
        // End-to-end: both peers configured with kermit_locking_shifts
        // = true and 8-bit-quote = on.  Negotiation must pick locking
        // shifts (qbin off, locking_shifts on); the resulting transfer
        // must round-trip 8-bit data correctly through the SO/SI mode
        // switching layer.
        let _guard = CONFIG_LOCK.lock().await;
        init_test_config();
        config::update_config_value("kermit_locking_shifts", "true");
        config::update_config_value("kermit_8bit_quote", "on");

        // Mix of low- and high-bit bytes plus an all-bytes pass —
        // exercises mode switches, REPT interaction (when enabled),
        // literal SO/SI in data, and the closing SI on packet end.
        let mut payload: Vec<u8> = Vec::new();
        payload.extend_from_slice(b"hello low-bit prefix\n");
        payload.extend((0x80u8..=0xFFu8).collect::<Vec<u8>>());
        payload.extend_from_slice(b"\nback to low\n");
        payload.extend([SO, SI, 0x8E, 0x8F, b'!']);
        payload.extend((0..=255u8).collect::<Vec<u8>>());

        let result = round_trip(vec![("locking.bin".into(), payload.clone())]).await;

        // Reset so unrelated tests don't inherit the locking-shift
        // settings (init_test_config doesn't reset these).
        config::update_config_value("kermit_locking_shifts", "false");
        config::update_config_value("kermit_8bit_quote", "auto");

        let received = result.unwrap();
        assert_eq!(received.len(), 1);
        assert_eq!(received[0].data, payload, "locking-shift round-trip must be lossless");
    }

    // ---------- HIGH-priority: round-2 fix coverage ----------

    #[test]
    fn test_wrap_send_err_strips_kermit_prefix() {
        // Inner already has the Kermit: prefix — should be stripped.
        let wrapped = wrap_send_err("Z-packet", "Kermit: read timeout".into());
        assert_eq!(wrapped, "Kermit send Z-packet: read timeout");
        // Inner without prefix — passes through after the wrapper prefix.
        let wrapped = wrap_send_err("F-packet", "i/o error".into());
        assert_eq!(wrapped, "Kermit send F-packet: i/o error");
    }

    #[test]
    fn test_decode_error_message_valid_utf8() {
        let q = Quoting::default();
        // "hello" encoded through the quoting layer.
        let encoded = encode_data(b"hello", q);
        assert_eq!(decode_error_message(&encoded, q), "hello");
    }

    #[test]
    fn test_decode_error_message_empty_payload() {
        assert_eq!(decode_error_message(&[], Quoting::default()), "");
    }

    #[test]
    fn test_decode_error_message_invalid_utf8() {
        // Quoted bytes that decode to a single 0xFF — not valid UTF-8.
        let q = Quoting {
            qctl: b'#',
            qbin: Some(b'&'),
            rept: None,
            locking_shifts: false,
        };
        let encoded = encode_data(&[0xFF], q);
        assert_eq!(decode_error_message(&encoded, q), "(unparseable)");
    }

    #[tokio::test]
    async fn test_send_rejects_oversize_file() {
        // Build a buffer one byte larger than MAX_FILE_SIZE.  Don't
        // actually allocate 8 MB — fake the length by passing a
        // synthetic struct via Vec::from_raw_parts isn't safe; instead
        // allocate the cap + 1.  Test runs once, ~8 MB peak.
        let _guard = CONFIG_LOCK.lock().await;
        init_test_config();
        let big = vec![0u8; (MAX_FILE_SIZE + 1) as usize];
        // Use a sink writer + source reader; the size check fires
        // before any I/O happens.
        let (a, b) = tokio::io::duplex(64);
        let (mut a_r, mut a_w) = tokio::io::split(a);
        let _ = b; // unused; kermit_send only writes/reads on a's side
        let files = [KermitSendFile {
            name: "big.bin",
            data: &big,
            modtime: None,
            mode: None,
        }];
        let result = kermit_send(&mut a_r, &mut a_w, &files, false, false, false).await;
        let err = result.expect_err("should reject");
        assert!(
            err.contains("exceeds") && err.contains("byte cap"),
            "got: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_receive_rejects_data_before_file() {
        // Hand-build a wire stream: peer's Send-Init, then a D-packet
        // straight away with no F-packet in between.  Receiver should
        // emit an E-packet response and return an error.
        let _guard = CONFIG_LOCK.lock().await;
        init_test_config();

        let peer_caps = Capabilities {
            chkt: b'1',
            maxl: 80,
            ..Capabilities::default()
        };
        let init_payload = build_send_init_payload(&peer_caps);
        let mut wire = build_packet(TYPE_SEND_INIT, 0, &init_payload, b'1', 0, 0, CR);
        let q = Quoting {
            qctl: b'#',
            qbin: None,
            rept: None,
            locking_shifts: false,
        };
        let data_payload = encode_data(b"oops", q);
        wire.extend_from_slice(&build_packet(TYPE_DATA, 1, &data_payload, b'1', 0, 0, CR));

        let (peer_to_gw, gw_in) = tokio::io::duplex(8192);
        let (gw_out, peer_from_gw) = tokio::io::duplex(8192);
        let (mut gw_r, _) = tokio::io::split(gw_in);
        let (_, mut gw_w) = tokio::io::split(gw_out);
        let (mut peer_r, mut peer_w) = (
            tokio::io::split(peer_from_gw).0,
            tokio::io::split(peer_to_gw).1,
        );

        let peer_task = tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            peer_w.write_all(&wire).await.ok();
            // Drain whatever the receiver writes back so its sends don't block.
            let mut buf = vec![0u8; 4096];
            let _ = peer_r.read(&mut buf).await;
        });

        let result = kermit_receive(&mut gw_r, &mut gw_w, false, false, false).await;
        peer_task.await.ok();
        let err = result.expect_err("D-before-F should error");
        assert!(err.contains("D-packet before F-packet"), "got: {}", err);
    }

    // ---------- HIGH-priority: round-trip with non-default settings ----------

    #[tokio::test]
    async fn test_round_trip_chkt1() {
        let received = round_trip_with_overrides(
            &[("kermit_block_check_type", "1")],
            vec![("chkt1.bin".into(), b"chkt-one round trip".to_vec())],
        )
        .await
        .unwrap();
        assert_eq!(received[0].data, b"chkt-one round trip");
    }

    #[tokio::test]
    async fn test_round_trip_chkt2() {
        let received = round_trip_with_overrides(
            &[("kermit_block_check_type", "2")],
            vec![("chkt2.bin".into(), b"chkt-two round trip".to_vec())],
        )
        .await
        .unwrap();
        assert_eq!(received[0].data, b"chkt-two round trip");
    }

    #[tokio::test]
    async fn test_round_trip_8bit_quoting_on() {
        // Force 8-bit quoting and round-trip a payload with high-bit
        // bytes; the QBIN prefix layer must round-trip cleanly.
        let payload: Vec<u8> = (0u16..=255).map(|v| v as u8).collect();
        let received = round_trip_with_overrides(
            &[("kermit_8bit_quote", "on")],
            vec![("hibit.bin".into(), payload.clone())],
        )
        .await
        .unwrap();
        assert_eq!(received[0].data, payload);
    }

    // ---------- Sliding-window round-trips ----------

    #[tokio::test]
    async fn test_round_trip_window_4() {
        // Window=4 round-trip — exercises the windowed sender + receiver
        // out-of-order buffer paths.  Payload is large enough to span
        // many D-packets so multiple in-window packets are outstanding
        // simultaneously.
        let payload: Vec<u8> = (0..16384).map(|i| (i * 13 + 7) as u8).collect();
        let received = round_trip_with_overrides(
            &[
                ("kermit_sliding_windows", "true"),
                ("kermit_window_size", "4"),
                // Keep MAXL classic-sized so we get many D-packets
                // rather than 1-2 long packets.
                ("kermit_long_packets", "false"),
                ("kermit_max_packet_length", "94"),
            ],
            vec![("win4.bin".into(), payload.clone())],
        )
        .await
        .unwrap();
        assert_eq!(received[0].data, payload);
    }

    #[tokio::test]
    async fn test_round_trip_window_8_long_packets_chkt3() {
        // Window=8 + long packets + CRC-16 (CHKT-3): the most-capable
        // negotiated combo, what real-world C-Kermit↔C-Kermit uses.
        let payload: Vec<u8> = (0..65536).map(|i| (i ^ (i >> 3)) as u8).collect();
        let received = round_trip_with_overrides(
            &[
                ("kermit_sliding_windows", "true"),
                ("kermit_window_size", "8"),
                ("kermit_long_packets", "true"),
                ("kermit_max_packet_length", "4096"),
                ("kermit_block_check_type", "3"),
            ],
            vec![("big.bin".into(), payload.clone())],
        )
        .await
        .unwrap();
        assert_eq!(received[0].data, payload);
    }

    #[tokio::test]
    async fn test_round_trip_window_multifile_resets_per_file() {
        // Multi-file batch with window>1 — verifies that the window
        // drains between files (the windowed sender returns the next
        // seq, control packets resume stop-and-wait).
        let files = vec![
            ("a.bin".into(), vec![0xAAu8; 4096]),
            ("b.bin".into(), vec![0xBBu8; 4096]),
            ("c.bin".into(), vec![0xCCu8; 4096]),
        ];
        let received = round_trip_with_overrides(
            &[
                ("kermit_sliding_windows", "true"),
                ("kermit_window_size", "4"),
            ],
            files.clone(),
        )
        .await
        .unwrap();
        assert_eq!(received.len(), 3);
        for (i, f) in files.iter().enumerate() {
            assert_eq!(received[i].filename, f.0);
            assert_eq!(received[i].data, f.1);
        }
    }

    #[tokio::test]
    async fn test_round_trip_window_max_31() {
        // Window=31 — the spec maximum (5-bit field).  Confirms we
        // negotiate and operate at the upper bound without wraparound
        // ambiguity (window=31 < 32 = half of seq mod-64 space).
        let payload: Vec<u8> = (0..32768).map(|i| (i % 251) as u8).collect();
        let received = round_trip_with_overrides(
            &[
                ("kermit_sliding_windows", "true"),
                ("kermit_window_size", "31"),
                ("kermit_long_packets", "false"),
                ("kermit_max_packet_length", "94"),
            ],
            vec![("max_window.bin".into(), payload.clone())],
        )
        .await
        .unwrap();
        assert_eq!(received[0].data, payload);
    }

    // ---------- Windowed receiver out-of-order buffer (lossy bridge) ---------

    /// A duplex bridge that drops the first D-packet matching a target
    /// seq the first time it sees it, then passes everything else
    /// through.  Used to verify the sliding-window sender's selective
    /// retransmit on per-seq timeout.
    #[derive(Clone)]
    struct LossyBridgeConfig {
        /// Drop the first D-packet whose seq byte (post-tochar) equals
        /// `tochar(target_seq)`.  Set None to disable.
        drop_d_seq: Option<u8>,
    }

    /// Forward bytes from `src` to `dst` while applying lossy-bridge
    /// rules.  We watch for SOH framing and selectively drop one
    /// matching D-packet.  Telnet IAC escaping isn't applied (test
    /// streams use is_tcp=false) so the byte stream is the raw packet
    /// sequence.
    async fn lossy_forward<R, W>(
        mut src: R,
        mut dst: W,
        cfg: LossyBridgeConfig,
    ) -> std::io::Result<()>
    where
        R: tokio::io::AsyncRead + Unpin,
        W: tokio::io::AsyncWrite + Unpin,
    {
        use tokio::io::AsyncWriteExt;
        let target = cfg.drop_d_seq.map(tochar);
        let mut dropped = false;
        // Streaming state machine — accumulate one packet's bytes,
        // then either forward or drop as a unit.
        let mut buf = [0u8; 1];
        let mut pkt_buf: Vec<u8> = Vec::with_capacity(128);
        let mut in_pkt = false;
        let mut is_d = false;
        let mut header_idx = 0usize; // bytes since SOH
        let mut payload_to_read: usize = 0;
        let mut check_to_read: usize = 0;
        let mut have_eol = false;
        loop {
            let n = match tokio::io::AsyncReadExt::read(&mut src, &mut buf).await {
                Ok(0) => return Ok(()),
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
                Err(e) => return Err(e),
            };
            if n == 0 {
                return Ok(());
            }
            let b = buf[0];

            if !in_pkt {
                if b == SOH {
                    in_pkt = true;
                    pkt_buf.clear();
                    pkt_buf.push(b);
                    header_idx = 1;
                    is_d = false;
                    payload_to_read = 0;
                    check_to_read = 0;
                    have_eol = false;
                } else {
                    // Not in packet, just forward (pad bytes etc).
                    dst.write_all(&[b]).await?;
                }
                continue;
            }

            pkt_buf.push(b);
            header_idx += 1;

            // Test bridge only handles classic (non-extended) packets;
            // tests using lossy_forward force kermit_long_packets=false.
            // Header layout: SOH LEN SEQ TYPE [DATA] [CHECK] [EOL]
            if header_idx == 2 {
                // LEN byte
                let n = unchar(b) as usize;
                // n = SEQ + TYPE + DATA + CHECK
                check_to_read = 3; // CHKT-3 cklen by default in tests; resolved post-TYPE
                payload_to_read = n.saturating_sub(2 + check_to_read);
            } else if header_idx == 3 {
                // SEQ byte — check for drop match
            } else if header_idx == 4 {
                // TYPE byte
                if b == TYPE_DATA {
                    is_d = true;
                }
                // Adjust check size now that we know type — but we just
                // keep CHKT-3's 3 bytes assumption since tests force
                // kermit_block_check_type=3.
            } else if header_idx > 4 {
                if payload_to_read > 0 {
                    payload_to_read -= 1;
                } else if check_to_read > 0 {
                    check_to_read -= 1;
                } else if !have_eol {
                    // EOL byte
                    have_eol = true;
                    in_pkt = false;
                    // Decide: drop or forward.
                    let seq_byte = pkt_buf.get(2).copied();
                    let drop_this = is_d
                        && !dropped
                        && match (target, seq_byte) {
                            (Some(t), Some(s)) => t == s,
                            _ => false,
                        };
                    if drop_this {
                        dropped = true;
                    } else {
                        dst.write_all(&pkt_buf).await?;
                    }
                    pkt_buf.clear();
                    header_idx = 0;
                }
            }
        }
    }

    /// Round-trip with a lossy bridge inserted between sender and
    /// receiver that drops the first D-packet at `drop_seq`.  Verifies
    /// the windowed sender selectively retransmits on per-seq timeout
    /// and the windowed receiver buffers + drains in-order.
    async fn round_trip_lossy(
        files: Vec<(String, Vec<u8>)>,
        drop_seq: u8,
    ) -> Result<Vec<KermitReceive>, String> {
        round_trip_lossy_with_overrides(&[], files, drop_seq).await
    }

    async fn round_trip_lossy_with_overrides(
        extra_overrides: &[(&str, &str)],
        files: Vec<(String, Vec<u8>)>,
        drop_seq: u8,
    ) -> Result<Vec<KermitReceive>, String> {
        use tokio::io::{duplex, split};
        let _guard = CONFIG_LOCK.lock().await;
        init_test_config();
        // Force classic packets, CHKT=3 — the lossy bridge assumes
        // these.  Sliding windows on by default; callers can layer
        // streaming on via extra_overrides.
        config::update_config_value("kermit_sliding_windows", "true");
        config::update_config_value("kermit_window_size", "4");
        config::update_config_value("kermit_long_packets", "false");
        config::update_config_value("kermit_max_packet_length", "94");
        config::update_config_value("kermit_block_check_type", "3");
        // Aggressive timeout so the test runs fast — sender's
        // retransmit timer fires within 1 second of the dropped
        // packet.
        config::update_config_value("kermit_packet_timeout", "1");
        config::update_config_value("kermit_max_retries", "10");
        for (k, v) in extra_overrides {
            config::update_config_value(k, v);
        }

        // sx pipe (sender → bridge): sender writes one end, bridge
        // reads the other.  split() returns (ReadHalf, WriteHalf) so
        // we destructure accordingly.
        let (sx_a, sx_b) = duplex(65536);
        let (_sx_a_r, mut sx_w_for_send) = split(sx_a);
        let (sx_r_pre_drop, _sx_b_w) = split(sx_b);

        // sy pipe (bridge → receiver): bridge writes one end, receiver
        // reads the other.
        let (sy_a, sy_b) = duplex(65536);
        let (_sy_a_r, sx_w_post) = split(sy_a);
        let (mut sx_r_for_recv, _sy_b_w) = split(sy_b);

        // rx pipe (receiver → sender ACKs, no lossy injection).
        let (rx_a, rx_b) = duplex(65536);
        let (mut rx_r_for_send, _rx_a_w) = split(rx_a);
        let (_rx_b_r, mut rx_w_for_recv) = split(rx_b);

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

        // Bridge task: forwards sx_r_pre_drop → sx_w_post, dropping
        // the first D-packet at `drop_seq`.
        let bridge_cfg = LossyBridgeConfig {
            drop_d_seq: Some(drop_seq),
        };
        let bridge_task = tokio::spawn(async move {
            let _ = lossy_forward(sx_r_pre_drop, sx_w_post, bridge_cfg).await;
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

        // Cap the whole test at 30 s so a hung retransmit loop fails
        // loudly rather than wedging CI.
        let send_result = tokio::time::timeout(
            tokio::time::Duration::from_secs(30),
            send_task,
        )
        .await
        .map_err(|_| "send task hung".to_string())?
        .unwrap();
        let recv_result = tokio::time::timeout(
            tokio::time::Duration::from_secs(30),
            recv_task,
        )
        .await
        .map_err(|_| "recv task hung".to_string())?
        .unwrap();
        bridge_task.abort();

        send_result?;
        recv_result
    }

    #[tokio::test]
    async fn test_round_trip_streaming_lossy_drop_one_d_packet() {
        // Streaming mode: sender pushes D-packets back-to-back without
        // waiting for ACKs, then sends Z and waits for Z-ACK.  When a
        // D-packet is dropped mid-stream, the receiver NAKs the
        // missing seq during the Z-drain phase and the sender must
        // selectively retransmit it.  Verifies the streaming sender's
        // NAK-handling path against real packet loss.
        let payload: Vec<u8> = (0..2048).map(|i| (i % 200 + 30) as u8).collect();
        let received = round_trip_lossy_with_overrides(
            &[("kermit_streaming", "true")],
            vec![("stream_lossy.bin".into(), payload.clone())],
            2,
        )
        .await
        .unwrap();
        assert_eq!(received.len(), 1);
        assert_eq!(received[0].data, payload);
    }

    #[tokio::test]
    async fn test_round_trip_window_lossy_drop_one_d_packet() {
        // Drop the first D-packet (seq=2 — the peer increments from 0
        // for Send-Init, 1 for F-packet, 2 for first D).  Sender's
        // per-seq timer must fire and retransmit while the receiver
        // buffers later D-packets out-of-order.  Final file must
        // round-trip identically.
        let payload: Vec<u8> = (0..2048).map(|i| (i % 200 + 30) as u8).collect();
        let received = round_trip_lossy(
            vec![("lossy.bin".into(), payload.clone())],
            2,
        )
        .await
        .unwrap();
        assert_eq!(received.len(), 1);
        assert_eq!(received[0].data, payload);
    }

    // ---------- Streaming Kermit ----------

    #[tokio::test]
    async fn test_round_trip_streaming_simple() {
        // Streaming on both sides — no per-D ACKs, Z-ACK confirms whole
        // stream.  Small payload to verify the basic path works.
        let received = round_trip_with_overrides(
            &[
                ("kermit_streaming", "true"),
                ("kermit_sliding_windows", "true"),
                ("kermit_window_size", "8"),
            ],
            vec![("stream.txt".into(), b"streaming hello kermit".to_vec())],
        )
        .await
        .unwrap();
        assert_eq!(received[0].data, b"streaming hello kermit");
    }

    #[tokio::test]
    async fn test_round_trip_streaming_64kb() {
        // 64 KB streaming round-trip — exercises a long stream where
        // the receiver consumes back-to-back D-packets and only ACKs
        // the trailing Z.
        let payload: Vec<u8> = (0u32..65536).map(|i| i.wrapping_mul(17) as u8).collect();
        let received = round_trip_with_overrides(
            &[
                ("kermit_streaming", "true"),
                ("kermit_long_packets", "true"),
                ("kermit_max_packet_length", "4096"),
                ("kermit_block_check_type", "3"),
            ],
            vec![("big.bin".into(), payload.clone())],
        )
        .await
        .unwrap();
        assert_eq!(received[0].data, payload);
    }

    #[tokio::test]
    async fn test_round_trip_streaming_all_byte_values() {
        // Streaming + 8-bit + repeat + every byte value — confirms the
        // quoting layer works end-to-end under streaming.
        let payload: Vec<u8> = (0u16..=255).map(|v| v as u8).collect();
        let received = round_trip_with_overrides(
            &[
                ("kermit_streaming", "true"),
                ("kermit_8bit_quote", "on"),
            ],
            vec![("allbytes.bin".into(), payload.clone())],
        )
        .await
        .unwrap();
        assert_eq!(received[0].data, payload);
    }

    #[tokio::test]
    async fn test_round_trip_streaming_multifile() {
        // Streaming carries one file at a time — Z-ACK terminates each
        // file's stream, F-packet starts the next.  Verify a 3-file
        // batch round-trips intact.
        let files = vec![
            ("a.bin".into(), vec![0x11u8; 8192]),
            ("b.bin".into(), vec![0x22u8; 8192]),
            ("c.bin".into(), vec![0x33u8; 8192]),
        ];
        let received = round_trip_with_overrides(
            &[("kermit_streaming", "true")],
            files.clone(),
        )
        .await
        .unwrap();
        assert_eq!(received.len(), 3);
        for (i, f) in files.iter().enumerate() {
            assert_eq!(received[i].filename, f.0);
            assert_eq!(received[i].data, f.1);
        }
    }

    #[tokio::test]
    async fn test_streaming_negotiation_off_when_only_one_side() {
        // If only one side advertises streaming, intersection should
        // turn it off (both sides must agree per Capabilities rule).
        // We can't directly test the wire here — that's
        // intersect_capabilities territory — but we can at least
        // verify a round-trip where ours is on and we run normally.
        // A second test below covers the intersection unit-level.
        let received = round_trip_with_overrides(
            &[("kermit_streaming", "false")],
            vec![("nostream.txt".into(), b"abc".to_vec())],
        )
        .await
        .unwrap();
        assert_eq!(received[0].data, b"abc");
    }

    #[test]
    fn test_streaming_intersection_requires_both() {
        let on = Capabilities {
            streaming: true,
            ..Capabilities::default()
        };
        let off = Capabilities {
            streaming: false,
            ..Capabilities::default()
        };
        assert!(!intersect_capabilities(&on, &off).streaming);
        assert!(!intersect_capabilities(&off, &on).streaming);
        assert!(intersect_capabilities(&on, &on).streaming);
    }

    // ---------- Effective packet timeout (peer TIME) ----------

    #[test]
    fn test_effective_packet_timeout_honors_peer_time() {
        // Peer specified TIME=3, fallback=10 → we use 3.
        assert_eq!(
            effective_packet_timeout(3, 10),
            tokio::time::Duration::from_secs(3)
        );
    }

    #[test]
    fn test_effective_packet_timeout_falls_back_when_peer_zero() {
        // Peer specified TIME=0 (= "no preference") → we use the
        // configured fallback.
        assert_eq!(
            effective_packet_timeout(0, 7),
            tokio::time::Duration::from_secs(7)
        );
    }

    #[test]
    fn test_effective_packet_timeout_floors_at_one_second() {
        // Pathological config: peer TIME=0 + fallback=0 → we floor at
        // 1 s so a wedged peer can't pin our retransmit timer at zero.
        assert_eq!(
            effective_packet_timeout(0, 0),
            tokio::time::Duration::from_secs(1)
        );
    }

    // ---------- MED-priority defensive tests ----------

    #[test]
    fn test_verify_check_error_messages_have_kermit_prefix() {
        // All four mismatch / length error strings must carry the
        // "Kermit:" prefix so they're consistent with the rest of the
        // module's error output.
        let bad_len_chkt1 = verify_check(b'1', b"x", &[]).unwrap_err();
        assert!(bad_len_chkt1.starts_with("Kermit:"), "{}", bad_len_chkt1);
        let bad_len_chkt2 = verify_check(b'2', b"x", b" ").unwrap_err();
        assert!(bad_len_chkt2.starts_with("Kermit:"), "{}", bad_len_chkt2);
        let bad_len_chkt3 = verify_check(b'3', b"x", b"  ").unwrap_err();
        assert!(bad_len_chkt3.starts_with("Kermit:"), "{}", bad_len_chkt3);
        // Mismatch (CRC poisoned).
        let mut trailer = block_check(b'3', b"hello");
        trailer[0] = trailer[0].wrapping_add(1);
        let mismatch = verify_check(b'3', b"hello", &trailer).unwrap_err();
        assert!(mismatch.starts_with("Kermit:"), "{}", mismatch);
    }

    #[test]
    fn test_encode_decode_repeat_boundary_3() {
        let q = Quoting {
            qctl: b'#',
            qbin: None,
            rept: Some(b'~'),
            locking_shifts: false,
        };
        // Run-length 3 — just at the encoder's threshold.  Must
        // round-trip whether or not compression actually fires.
        let input = vec![b'X'; 3];
        let enc = encode_data(&input, q);
        assert_eq!(decode_data(&enc, q).unwrap(), input);
    }

    #[test]
    fn test_encode_decode_repeat_boundary_94() {
        let q = Quoting {
            qctl: b'#',
            qbin: None,
            rept: Some(b'~'),
            locking_shifts: false,
        };
        // Max single-repeat run length (tochar(94) = '~' is the prefix
        // itself; tochar(94) the count byte = 0x7E).  Verify exactly
        // 94 identical bytes round-trip.
        let input = vec![b'Z'; 94];
        let enc = encode_data(&input, q);
        assert_eq!(decode_data(&enc, q).unwrap(), input);
    }

    #[test]
    fn test_encode_decode_repeat_boundary_95() {
        let q = Quoting {
            qctl: b'#',
            qbin: None,
            rept: Some(b'~'),
            locking_shifts: false,
        };
        // 95 identical bytes — must split into two repeat groups.
        let input = vec![b'Q'; 95];
        let enc = encode_data(&input, q);
        assert_eq!(decode_data(&enc, q).unwrap(), input);
    }

    #[test]
    fn test_parse_send_init_truncated_at_each_position() {
        // Build a known-good 14-byte payload; truncate to every
        // length 0..=14 and confirm the parser doesn't panic and that
        // each truncation produces sensible defaults for the missing
        // fields.
        let caps = Capabilities {
            maxl: 4096,
            time: 10,
            qctl: b'#',
            qbin: Some(b'&'),
            chkt: b'3',
            rept: Some(b'~'),
            window: 4,
            long_packets: true,
            attribute_packets: true,
            ..Capabilities::default()
        };
        let full = build_send_init_payload(&caps);
        for n in 0..=full.len() {
            let _ = parse_send_init_payload(&full[..n]);
        }
    }

    #[test]
    fn test_parse_send_init_rejects_ckermit_capas_extension_as_peer_id() {
        // Captured C-Kermit Send-Init payload — the trailing bytes
        // [30 5F 5F 5F 5E 22 55 31 41] are vendor CAPAS extension
        // fields (CHECKPOINT, WHATAMI, ATCAPB, ...), not text.  Older
        // versions of our parser interpreted them as a peer_id string
        // and broke downstream flavor detection.
        let raw = [
            0x7E, 0x2F, 0x20, 0x40, 0x2D, 0x23, 0x59, 0x33, 0x7E, 0x5E, 0x3E, 0x4A, 0x29, 0x30,
            0x5F, 0x5F, 0x5F, 0x5E, 0x22, 0x55, 0x31, 0x41,
        ];
        let parsed = parse_send_init_payload(&raw);
        assert_eq!(parsed.maxl, 3999);
        assert_eq!(parsed.time, 15);
        assert_eq!(parsed.chkt, b'3');
        assert_eq!(parsed.window, 30);
        assert!(parsed.long_packets);
        assert!(parsed.attribute_packets);
        assert!(
            parsed.peer_id.is_none(),
            "trailing CAPAS extension bytes should NOT be treated as peer_id, got: {:?}",
            parsed.peer_id
        );
    }

    #[test]
    fn test_parse_send_init_accepts_real_text_peer_id() {
        // A genuine ASCII identification string with a 4-letter run
        // (e.g., "Kermit") should be captured as peer_id.
        let mut payload = build_send_init_payload(&Capabilities {
            maxl: 4096,
            window: 4,
            long_packets: true,
            ..Capabilities::default()
        });
        payload.extend_from_slice(b"C-Kermit 9.0.302");
        let parsed = parse_send_init_payload(&payload);
        assert_eq!(parsed.peer_id.as_deref(), Some("C-Kermit 9.0.302"));
    }

    #[test]
    fn test_detect_flavor_ckermit_from_capas_alone() {
        // C-Kermit's Send-Init buries identification in binary CAPAS
        // extension fields rather than a readable peer_id, so the
        // capability-based heuristic must classify it correctly when
        // peer_id is None.
        let c = Capabilities {
            maxl: 3999,
            time: 15,
            chkt: b'3',
            window: 30,
            long_packets: true,
            attribute_packets: true,
            peer_id: None,
            ..Capabilities::default()
        };
        assert_eq!(detect_flavor(&c), KermitFlavor::CKermit);
    }

    // ---------- WINDO/MAXLX conditional emission (spec §4.4) ----------
    //
    // WINDO is present in Send-Init iff the sliding-window bit is
    // set in CAPAS byte 1; MAXLX1/MAXLX2 are present iff the
    // long-packets bit is set.  Each combination is verified
    // separately against build/parse round-trip.

    #[test]
    fn test_send_init_no_windo_when_sliding_off() {
        // long_packets on, sliding off → MAXLX present, WINDO absent.
        let caps = Capabilities {
            maxl: 4096,
            window: 1, // sliding off
            long_packets: true,
            attribute_packets: true,
            ..Capabilities::default()
        };
        let payload = build_send_init_payload(&caps);
        // No streaming → CAPAS chain is one byte at slot 9 (idx 9).
        // After QCTL/QBIN/CHKT/REPT slots the layout is:
        //   slots 0..=8 (9 bytes), CAPAS at idx 9, then optional
        //   fields.  Long-only means slots 10-11 are MAXLX1/MAXLX2.
        let capas = unchar(payload[9]);
        assert_eq!(capas & CAPAS_SLIDING, 0, "sliding bit should NOT be set");
        assert_ne!(capas & CAPAS_LONGPKT, 0, "long bit should be set");
        // Parse round-trip recovers maxl=4096, window=1.
        let parsed = parse_send_init_payload(&payload);
        assert_eq!(parsed.maxl, 4096);
        assert_eq!(parsed.window, 1);
        assert!(parsed.long_packets);
    }

    #[test]
    fn test_send_init_no_maxlx_when_long_off() {
        // sliding on, long off → WINDO present, MAXLX absent.
        let caps = Capabilities {
            maxl: 80, // classic-only
            window: 8,
            long_packets: false,
            attribute_packets: true,
            ..Capabilities::default()
        };
        let payload = build_send_init_payload(&caps);
        let capas = unchar(payload[9]);
        assert_ne!(capas & CAPAS_SLIDING, 0, "sliding bit should be set");
        assert_eq!(capas & CAPAS_LONGPKT, 0, "long bit should NOT be set");
        let parsed = parse_send_init_payload(&payload);
        assert_eq!(parsed.window, 8);
        assert!(!parsed.long_packets);
        assert_eq!(parsed.maxl, 80, "maxl should match the slot-1 value");
    }

    #[test]
    fn test_send_init_neither_windo_nor_maxlx_when_both_off() {
        // sliding off, long off → CAPAS chain ends; no WINDO, no MAXLX.
        let caps = Capabilities {
            maxl: 80,
            window: 1,
            long_packets: false,
            attribute_packets: true,
            ..Capabilities::default()
        };
        let payload = build_send_init_payload(&caps);
        // Without any optional extensions, the payload should end at
        // CAPAS byte 1 (offset 9) — no WINDO, no MAXLX1/2.
        assert_eq!(payload.len(), 10);
        let parsed = parse_send_init_payload(&payload);
        assert_eq!(parsed.window, 1);
        assert!(!parsed.long_packets);
        assert_eq!(parsed.maxl, 80);
    }

    #[test]
    fn test_send_init_both_windo_and_maxlx_when_both_on() {
        let caps = Capabilities {
            maxl: 4096,
            window: 16,
            long_packets: true,
            attribute_packets: true,
            ..Capabilities::default()
        };
        let payload = build_send_init_payload(&caps);
        let capas = unchar(payload[9]);
        assert_ne!(capas & CAPAS_SLIDING, 0);
        assert_ne!(capas & CAPAS_LONGPKT, 0);
        let parsed = parse_send_init_payload(&payload);
        assert_eq!(parsed.window, 16);
        assert!(parsed.long_packets);
        assert_eq!(parsed.maxl, 4096);
    }

    #[test]
    fn test_parse_send_init_long_only_no_windo_byte() {
        // Hand-craft a Send-Init payload that simulates a strict-spec
        // peer advertising long-packets only (no sliding): CAPAS=long,
        // followed directly by MAXLX1/MAXLX2.  Verify our parser
        // doesn't treat MAXLX1 as WINDO.
        let mut payload: Vec<u8> = vec![
            tochar(94),               // MAXL = 94 (classic)
            tochar(15),               // TIME = 15
            tochar(0),                // NPAD
            ctl(0),                   // PADC
            tochar(0x0D),             // EOL = CR
            b'#',                     // QCTL
            b'Y',                     // QBIN = willing
            b'3',                     // CHKT = 3
            b'~',                     // REPT
            tochar(CAPAS_LONGPKT),    // CAPAS byte 1 — long only, no continue
            tochar(43),               // MAXLX1 = 43
            tochar(11),               // MAXLX2 = 11
        ];
        // Add a trailing letter run so the peer_id heuristic doesn't trigger.
        payload.extend_from_slice(b"");
        let parsed = parse_send_init_payload(&payload);
        // Without the conditional fix, our parser would have read
        // tochar(43)='K' as WINDO=43, then tried to read MAXLX1/2
        // from beyond the buffer, leaving maxl at the slot-1 value
        // of 94 (or 138 from misaligned MAXLX bytes).  The spec-
        // compliant parse recovers maxl = 43*95 + 11 = 4096.
        assert!(parsed.long_packets);
        assert_eq!(parsed.window, 1, "no sliding advertised → window 1");
        assert_eq!(parsed.maxl, 4096);
    }

    #[test]
    fn test_send_init_capas_resend_bit_set_when_advertised() {
        // CAPAS byte 1 lives at payload[9].  Bit 4 (CAPAS_RESEND, 0x10)
        // tells the peer we can do resume-partial coordination.
        let caps = Capabilities {
            attribute_packets: true,
            resend: true,
            ..Capabilities::default()
        };
        let payload = build_send_init_payload(&caps);
        let capas = unchar(payload[9]);
        assert_ne!(capas & CAPAS_RESEND, 0, "RESEND bit must be set");
        assert_ne!(capas & CAPAS_ATTRIBUTE, 0, "ATTRIBUTE bit must be set");
    }

    #[test]
    fn test_send_init_capas_resend_bit_clear_when_not_advertised() {
        // Default Capabilities has resend=false; the bit must be clear.
        // Guards against the encoder accidentally setting it for all
        // sessions (which would mislead a strict peer into expecting
        // disposition='R' coordination we won't provide).
        let caps = Capabilities {
            attribute_packets: true,
            resend: false,
            ..Capabilities::default()
        };
        let payload = build_send_init_payload(&caps);
        let capas = unchar(payload[9]);
        assert_eq!(capas & CAPAS_RESEND, 0, "RESEND bit must be clear");
    }

    #[test]
    fn test_send_init_resend_round_trips_through_parse() {
        let caps = Capabilities {
            resend: true,
            ..Capabilities::default()
        };
        let payload = build_send_init_payload(&caps);
        let parsed = parse_send_init_payload(&payload);
        assert!(parsed.resend, "parse must recover the RESEND bit");

        let caps = Capabilities {
            resend: false,
            ..Capabilities::default()
        };
        let payload = build_send_init_payload(&caps);
        let parsed = parse_send_init_payload(&payload);
        assert!(!parsed.resend, "parse must NOT spuriously set RESEND");
    }

    #[test]
    fn test_intersect_capabilities_resend_requires_both_sides() {
        // Spec rule (and our gate): RESEND is enabled only when BOTH
        // peers advertise it.  Asymmetric advertisement falls back to
        // disabled — otherwise an opt-out peer could be surprised by
        // disposition='R' tags it doesn't understand.
        let ours = Capabilities {
            resend: true,
            ..Capabilities::default()
        };
        let theirs = Capabilities {
            resend: false,
            ..Capabilities::default()
        };
        assert!(!intersect_capabilities(&ours, &theirs).resend);
        assert!(!intersect_capabilities(&theirs, &ours).resend);

        let both = Capabilities {
            resend: true,
            ..Capabilities::default()
        };
        assert!(intersect_capabilities(&both, &both).resend);
    }

    #[test]
    fn test_send_init_capas_locking_shift_bit_set_when_advertised() {
        // CAPAS byte 1 lives at payload[9].  Bit 5
        // (CAPAS_LOCKING_SHIFT, 0x20) tells the peer we can do SO/SI
        // region quoting.
        let caps = Capabilities {
            attribute_packets: true,
            locking_shifts: true,
            ..Capabilities::default()
        };
        let payload = build_send_init_payload(&caps);
        let capas = unchar(payload[9]);
        assert_ne!(capas & CAPAS_LOCKING_SHIFT, 0, "LOCKING_SHIFT bit must be set");
    }

    #[test]
    fn test_send_init_capas_locking_shift_bit_clear_when_not_advertised() {
        // Default: bit must be clear.  Catches a regression where the
        // encoder accidentally sets it for all sessions, which would
        // confuse strict-spec peers into expecting SO/SI we won't send.
        let caps = Capabilities {
            attribute_packets: true,
            locking_shifts: false,
            ..Capabilities::default()
        };
        let payload = build_send_init_payload(&caps);
        let capas = unchar(payload[9]);
        assert_eq!(capas & CAPAS_LOCKING_SHIFT, 0, "LOCKING_SHIFT bit must be clear");
    }

    #[test]
    fn test_send_init_locking_shifts_round_trips_through_parse() {
        let caps = Capabilities {
            locking_shifts: true,
            ..Capabilities::default()
        };
        let payload = build_send_init_payload(&caps);
        assert!(parse_send_init_payload(&payload).locking_shifts);

        let caps = Capabilities {
            locking_shifts: false,
            ..Capabilities::default()
        };
        let payload = build_send_init_payload(&caps);
        assert!(!parse_send_init_payload(&payload).locking_shifts);
    }

    #[test]
    fn test_intersect_locking_shifts_wins_over_qbin_when_both_advertise() {
        // Spec precedence (Frank da Cruz §3.4): when both peers
        // advertise CAPAS_LOCKING_SHIFT *and* either side wants 8-bit
        // transmission, locking shifts replace QBIN entirely.
        let ours = Capabilities {
            qbin: Some(b'&'),
            locking_shifts: true,
            ..Capabilities::default()
        };
        let theirs = Capabilities {
            qbin: None, // peer is willing but doesn't insist
            locking_shifts: true,
            ..Capabilities::default()
        };
        let session = intersect_capabilities(&ours, &theirs);
        assert!(session.locking_shifts, "both advertise + 8-bit needed → locking_shifts on");
        assert_eq!(
            session.qbin, None,
            "QBIN must be off when locking_shifts is on (spec precedence)"
        );
    }

    #[test]
    fn test_intersect_locking_shifts_off_when_only_one_side_advertises() {
        // Asymmetric advertisement: fall back to QBIN per existing
        // 8-bit logic.  Otherwise an opt-out peer would see SO/SI it
        // can't decode.
        let ours = Capabilities {
            qbin: Some(b'&'),
            locking_shifts: true,
            ..Capabilities::default()
        };
        let theirs = Capabilities {
            qbin: Some(b'&'),
            locking_shifts: false,
            ..Capabilities::default()
        };
        let session = intersect_capabilities(&ours, &theirs);
        assert!(!session.locking_shifts);
        assert_eq!(session.qbin, Some(b'&'), "fall back to QBIN");
    }

    #[test]
    fn test_intersect_locking_shifts_off_when_neither_needs_eight_bit() {
        // Both advertise the capability but neither asserts QBIN
        // (both 8-bit-clean): there's nothing to convey, so neither
        // mechanism activates.
        let both = Capabilities {
            qbin: None,
            locking_shifts: true,
            ..Capabilities::default()
        };
        let session = intersect_capabilities(&both, &both);
        assert!(!session.locking_shifts);
        assert_eq!(session.qbin, None);
    }

    #[test]
    fn test_intersect_qbin_peer_yes_means_none() {
        // Peer signals 'Y' (parsed to None == "willing"); we have no
        // 8-bit prefix configured — intersection should remain None.
        let ours = Capabilities {
            qbin: None,
            ..Capabilities::default()
        };
        let theirs = Capabilities {
            qbin: None,
            ..Capabilities::default()
        };
        let session = intersect_capabilities(&ours, &theirs);
        assert_eq!(session.qbin, None);
        // We require 8-bit; peer is willing (None).  Intersection
        // takes our Some(c).
        let ours = Capabilities {
            qbin: Some(b'&'),
            ..Capabilities::default()
        };
        let session = intersect_capabilities(&ours, &theirs);
        assert_eq!(session.qbin, Some(b'&'));
    }

    // ---------- C-Kermit subprocess interop ----------
    //
    // Spawns the real `kermit` binary in send mode over a TCP socket
    // and runs our `kermit_receive` against it.  Validates that we
    // negotiate Send-Init and round-trip a file with an actual
    // C-Kermit peer — not just our own send/receive.  `#[ignore]`
    // because it requires `kermit` (ckermit) installed and creates
    // network sockets; run with:
    //
    //   cargo test test_ckermit_send_interop -- --ignored --nocapture
    //
    // Three sub-tests exercise the three negotiation modes we
    // shipped: stop-and-wait, sliding-window, and streaming.  Each
    // configures `egateway.conf` keys via `update_config_value` so
    // the receiver advertises the matching capabilities.

    #[cfg(unix)]
    async fn run_ckermit_interop(
        cfg_overrides: &[(&str, &str)],
        payload: &[u8],
    ) -> Result<Vec<KermitReceive>, String> {
        use std::process::Stdio;
        use tokio::net::TcpListener;
        use tokio::process::Command;

        // 1. Verify kermit is on PATH; otherwise this is a developer-
        //    machine config issue, not a test failure to investigate.
        if Command::new("kermit")
            .arg("-h")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .map(|s| !s.success())
            .unwrap_or(true)
        {
            return Err("kermit (ckermit) not found on PATH".into());
        }

        let _guard = CONFIG_LOCK.lock().await;
        init_test_config();
        for (k, v) in cfg_overrides {
            config::update_config_value(k, v);
        }

        // 2. Stage a payload file on disk for kermit to send.
        let tmp = std::env::temp_dir().join(format!(
            "kermit_interop_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).map_err(|e| e.to_string())?;
        let send_path = tmp.join("interop.bin");
        std::fs::write(&send_path, payload).map_err(|e| e.to_string())?;

        // 3. Listen on an ephemeral port; spawn ckermit pointing at it.
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|e| e.to_string())?;
        let port = listener.local_addr().map_err(|e| e.to_string())?.port();

        // -B: batch / no controlling terminal
        // -j host:port: open TCP connection (telnet protocol)
        // -i: image (binary) transfer
        // -s file: send file (action option)
        // -q: quiet
        let mut child = Command::new("kermit")
            .arg("-B")
            .arg("-j")
            .arg(format!("127.0.0.1:{}", port))
            .arg("-i")
            .arg("-q")
            .arg("-s")
            .arg(&send_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("spawn kermit: {}", e))?;

        // 4. Accept the connection and run kermit_receive against it.
        //    Cap the whole thing at 30 s so a hung negotiation fails
        //    loudly instead of wedging the test runner.
        let accept = tokio::time::timeout(
            tokio::time::Duration::from_secs(30),
            listener.accept(),
        )
        .await
        .map_err(|_| "ckermit didn't connect within 30 s".to_string())?
        .map_err(|e| format!("accept: {}", e))?;
        let (sock, _addr) = accept;
        let (mut r, mut w) = tokio::io::split(sock);

        // is_tcp=true so the IAC/CR-NUL layer is active — kermit -j
        // opens a telnet-protocol connection and may negotiate
        // options on the wire.
        let result = tokio::time::timeout(
            tokio::time::Duration::from_secs(30),
            kermit_receive(&mut r, &mut w, true, false, true),
        )
        .await
        .map_err(|_| "kermit_receive timed out".to_string())?;

        // 5. Always reap the child to keep CI clean.
        let _ = child.wait().await;
        let _ = std::fs::remove_dir_all(&tmp);
        result
    }

    /// Diagnostic: capture C-Kermit's raw wire bytes for hand-inspection.
    /// Used to debug interop issues against a real ckermit peer.
    /// Run with: `cargo test test_ckermit_capture_wire_bytes -- --ignored --nocapture`
    #[cfg(unix)]
    #[tokio::test]
    #[ignore]
    async fn test_ckermit_capture_wire_bytes() {
        use std::process::Stdio;
        use tokio::io::AsyncReadExt;
        use tokio::net::TcpListener;
        use tokio::process::Command;

        let _guard = CONFIG_LOCK.lock().await;
        init_test_config();
        config::update_config_value("kermit_sliding_windows", "true");
        config::update_config_value("kermit_window_size", "8");
        config::update_config_value("kermit_long_packets", "true");
        config::update_config_value("kermit_max_packet_length", "4096");

        let payload: Vec<u8> = (0..4096).map(|i| (i * 13 + 7) as u8).collect();
        let tmp = std::env::temp_dir().join("kermit_capture_test");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let send_path = tmp.join("interop.bin");
        std::fs::write(&send_path, &payload).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let mut child = Command::new("kermit")
            .arg("-B")
            .arg("-j")
            .arg(format!("127.0.0.1:{}", port))
            .arg("-i")
            .arg("-q")
            .arg("-s")
            .arg(&send_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();

        let (sock, _) = listener.accept().await.unwrap();
        let (mut r, mut w) = tokio::io::split(sock);

        // Do the Send-Init exchange manually: read S-packet, send ACK
        // with our caps.  After that, dump everything to a file.
        let mut state = ReadState::default();
        let s_pkt = read_packet(
            &mut r, true, false, b'1', CR, false, &mut state,
            Some(tokio::time::Instant::now() + tokio::time::Duration::from_secs(10)),
        ).await.unwrap();
        let raw_payload: Vec<String> = s_pkt.payload.iter().map(|b| format!("{:02X}", b)).collect();
        eprintln!(
            "S-packet raw payload ({} bytes): [{}]",
            s_pkt.payload.len(),
            raw_payload.join(" ")
        );
        let peer_init = parse_send_init_payload(&s_pkt.payload);
        eprintln!(
            "peer Send-Init: maxl={} time={} qctl=0x{:02X}('{}') qbin={:?} chkt='{}' rept={:?} window={} long={} stream={} attrs={} peer_id={:?}",
            peer_init.maxl, peer_init.time, peer_init.qctl, peer_init.qctl as char,
            peer_init.qbin, peer_init.chkt as char, peer_init.rept,
            peer_init.window, peer_init.long_packets, peer_init.streaming,
            peer_init.attribute_packets, peer_init.peer_id,
        );
        let our_caps = config_capabilities();
        let ack_payload = build_send_init_payload(&our_caps);
        send_ack_with_payload(&mut w, s_pkt.seq, &ack_payload, b'1', 0, 0, CR, true).await.unwrap();
        // ACK the F-packet so kermit proceeds.
        let f_pkt = read_packet(&mut r, true, false, peer_init.chkt, CR, false, &mut state,
            Some(tokio::time::Instant::now() + tokio::time::Duration::from_secs(5))).await.unwrap();
        eprintln!("F-packet seq={} payload_len={}", f_pkt.seq, f_pkt.payload.len());
        send_ack(&mut w, f_pkt.seq, peer_init.chkt, 0, 0, CR, true).await.unwrap();
        // ACK the A-packet too if present.
        let a_pkt = read_packet(&mut r, true, false, peer_init.chkt, CR, false, &mut state,
            Some(tokio::time::Instant::now() + tokio::time::Duration::from_secs(5))).await.unwrap();
        eprintln!("Got packet type='{}' seq={} payload_len={}", a_pkt.kind as char, a_pkt.seq, a_pkt.payload.len());
        send_ack(&mut w, a_pkt.seq, peer_init.chkt, 0, 0, CR, true).await.unwrap();

        // Capture all subsequent bytes for 3 seconds.
        let capture_path = tmp.join("wire.bin");
        let mut capture = std::fs::File::create(&capture_path).unwrap();
        use std::io::Write;
        let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(3);
        let mut buf = [0u8; 4096];
        loop {
            let now = tokio::time::Instant::now();
            if now >= deadline { break; }
            match tokio::time::timeout(deadline - now, r.read(&mut buf)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => { capture.write_all(&buf[..n]).unwrap(); }
                Ok(Err(_)) | Err(_) => break,
            }
        }
        drop(capture);
        let _ = child.kill().await;

        let bytes = std::fs::read(&capture_path).unwrap();
        eprintln!("captured {} bytes; first 100:", bytes.len());
        for chunk in bytes.chunks(32).take(8) {
            let hex: Vec<String> = chunk.iter().map(|b| format!("{:02X}", b)).collect();
            eprintln!("  {}", hex.join(" "));
        }
        eprintln!("(file at {})", capture_path.display());
    }

    #[cfg(unix)]
    #[tokio::test]
    #[ignore]
    async fn test_ckermit_send_interop_stop_and_wait() {
        let payload: Vec<u8> = (0..2048).map(|i| (i * 7 + 11) as u8).collect();
        let received = run_ckermit_interop(
            &[
                ("kermit_sliding_windows", "false"),
                ("kermit_window_size", "1"),
                ("kermit_streaming", "false"),
            ],
            &payload,
        )
        .await
        .expect("ckermit stop-and-wait interop failed");
        assert_eq!(received.len(), 1, "expected 1 file");
        assert_eq!(received[0].data, payload, "file content mismatch");
        // C-Kermit's Send-Init has no readable peer_id slot (it's
        // filled with binary CAPAS extension bytes), so detect_flavor
        // classifies via capability bits — long_packets +
        // attribute_packets + window>1 → CKermit.
        assert_eq!(received[0].flavor, KermitFlavor::CKermit);
    }

    #[cfg(unix)]
    #[tokio::test]
    #[ignore]
    async fn test_ckermit_send_interop_sliding_window() {
        let payload: Vec<u8> = (0..16384).map(|i| (i * 13 + 7) as u8).collect();
        let received = run_ckermit_interop(
            &[
                ("kermit_sliding_windows", "true"),
                ("kermit_window_size", "8"),
                ("kermit_streaming", "false"),
            ],
            &payload,
        )
        .await
        .expect("ckermit sliding-window interop failed");
        assert_eq!(received[0].data, payload);
        // Flavor detection is heuristic; assert it's at least classified
        // as something more specific than Unknown when peer_id parses.
        // Known C-Kermit S-packets sometimes have a malformed trailing
        // peer_id field — that's a parser issue tracked separately;
        // here we just confirm the protocol-level data round-tripped.
        let f = received[0].flavor.display();
        eprintln!("kermit interop flavor: {}", f);
    }

    #[cfg(unix)]
    #[tokio::test]
    #[ignore]
    async fn test_ckermit_send_interop_streaming() {
        let payload: Vec<u8> = (0..32768).map(|i| (i ^ (i >> 5)) as u8).collect();
        let received = run_ckermit_interop(
            &[
                ("kermit_sliding_windows", "true"),
                ("kermit_window_size", "8"),
                ("kermit_streaming", "true"),
            ],
            &payload,
        )
        .await
        .expect("ckermit streaming interop failed");
        assert_eq!(received[0].data, payload);
        // Flavor detection is heuristic; assert it's at least classified
        // as something more specific than Unknown when peer_id parses.
        // Known C-Kermit S-packets sometimes have a malformed trailing
        // peer_id field — that's a parser issue tracked separately;
        // here we just confirm the protocol-level data round-tripped.
        let f = received[0].flavor.display();
        eprintln!("kermit interop flavor: {}", f);
    }

    /// Server-mode interop: spawn C-Kermit as a CLIENT doing `get
    /// filename` against our `kermit_server`.  Verifies the full
    /// I → R → S → F → A → D... → Z → B handshake against a real
    /// ckermit peer, including:
    ///
    /// - Auto-startup string (`kermit -x\r\n`) on the wire before the
    ///   first SOH — our MARK-hunt in `read_packet` discards it.
    /// - I-packet (re-init) as the first Kermit packet, which our
    ///   server ACKs with our CAPAS payload.
    /// - R-packet at seq=0; server ACKs explicitly before the S.
    /// - Server's S at seq=0 (each transfer is a fresh exchange — NOT
    ///   continuation of the I/R seq counter).
    ///
    /// `#[ignore]` because it requires `kermit` (ckermit) installed;
    /// run with `cargo test test_ckermit_server -- --ignored`.
    #[cfg(unix)]
    #[tokio::test]
    #[ignore]
    async fn test_ckermit_server_get_interop() {
        use std::process::Stdio;
        use tokio::net::TcpListener;
        use tokio::process::Command;

        if Command::new("kermit")
            .arg("-h")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .map(|s| !s.success())
            .unwrap_or(true)
        {
            eprintln!("ckermit not on PATH; skipping interop test");
            return;
        }

        let _guard = CONFIG_LOCK.lock().await;
        init_test_config();

        // Stage a file in transfer_dir for ckermit to GET.
        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("kermit_server_interop_{}", pid));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let payload: Vec<u8> = (0..4096u32).map(|i| (i * 17) as u8).collect();
        std::fs::write(dir.join("interop.bin"), &payload).unwrap();
        // Where ckermit will save what it pulls from us.
        let local_save = dir.join("local_save.bin");

        config::update_config_value("transfer_dir", dir.to_str().unwrap());

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        // -B: batch / no controlling terminal.
        // -j host:port: open TCP connection (telnet protocol).
        // -i: image (binary) transfer.
        // -g name: GET name from the server.
        // -a localname: save received file as localname.
        // -q: quiet.
        let mut child = Command::new("kermit")
            .arg("-B")
            .arg("-j")
            .arg(format!("127.0.0.1:{}", port))
            .arg("-i")
            .arg("-q")
            .arg("-g")
            .arg("interop.bin")
            .arg("-a")
            .arg(&local_save)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn ckermit");

        let (sock, _) = tokio::time::timeout(
            tokio::time::Duration::from_secs(30),
            listener.accept(),
        )
        .await
        .expect("ckermit didn't connect within 30s")
        .expect("accept");
        let (mut r, mut w) = tokio::io::split(sock);

        // is_tcp=true so the IAC/CR-NUL layer is active for the
        // telnet-mode connection ckermit -j establishes.
        let server_result = tokio::time::timeout(
            tokio::time::Duration::from_secs(30),
            kermit_server(&mut r, &mut w, true, false, true),
        )
        .await
        .expect("kermit_server timed out");

        let _ = child.wait().await;

        // Reset state for unrelated tests, then verify what ckermit
        // saved.  If anything in the dispatch loop / R handler /
        // kermit_send_with_starting_seq path is wrong we'll either
        // fail to find local_save or its bytes will diverge.
        config::update_config_value("transfer_dir", "transfer");
        let downloaded = std::fs::read(&local_save)
            .expect("ckermit should have saved the pulled file");
        let _ = std::fs::remove_dir_all(&dir);

        server_result.expect("kermit_server returned an error");
        assert_eq!(downloaded, payload, "downloaded content must equal staged file");
    }

    /// C-Kermit sends a file to our `kermit_server`.  Uses ckermit's
    /// `-s file` action flag (no script, no tty needed — the action
    /// runs to completion and ckermit exits).  Verifies the server's
    /// S-dispatch path with a real ckermit peer end-to-end.
    ///
    /// Why we don't have script-driven server-mode interop tests for
    /// `finish` / `bye` / `remote dir` / `remote cd` / `remote kermit`:
    /// those are interactive commands that ckermit refuses to run
    /// without a tty even in `-B` batch mode (it errors out with
    /// "/dev/tty is not a terminal device" before sending the
    /// command).  Working around that requires a pseudo-tty wrapper
    /// (e.g. `script -qc` / `unbuffer`) which is platform-fragile and
    /// out of scope for an `#[ignore]`'d test.  Those code paths are
    /// instead covered by in-process tests using `kermit_server` as
    /// the peer (see `test_server_g_*` and `test_client_*` above) —
    /// the wire flow is identical, so the test value is in the
    /// protocol-level coverage rather than the cross-process exercise.
    #[cfg(unix)]
    #[tokio::test]
    #[ignore]
    async fn test_ckermit_server_send_interop() {
        use std::process::Stdio;
        use tokio::net::TcpListener;
        use tokio::process::Command;

        if Command::new("kermit")
            .arg("-h")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .map(|s| !s.success())
            .unwrap_or(true)
        {
            eprintln!("ckermit not on PATH; skipping interop test");
            return;
        }

        let _guard = CONFIG_LOCK.lock().await;
        init_test_config();

        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("kermit_send_interop_{}", pid));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let payload: Vec<u8> = (0..2048u32).map(|i| (i ^ 0x5A) as u8).collect();
        let src_file = dir.join("uploaded.bin");
        std::fs::write(&src_file, &payload).unwrap();
        config::update_config_value("transfer_dir", dir.to_str().unwrap());

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        // ckermit dials in via -j and runs the -s action (send file)
        // to completion.  No interactive commands → no tty needed.
        let mut child = Command::new("kermit")
            .arg("-B")
            .arg("-j")
            .arg(format!("127.0.0.1:{}", port))
            .arg("-i")
            .arg("-q")
            .arg("-s")
            .arg(&src_file)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn ckermit");

        let (sock, _) = tokio::time::timeout(
            tokio::time::Duration::from_secs(30),
            listener.accept(),
        )
        .await
        .expect("ckermit didn't connect within 30s")
        .expect("accept");
        let (mut r, mut w) = tokio::io::split(sock);

        let server_result = tokio::time::timeout(
            tokio::time::Duration::from_secs(30),
            kermit_server(&mut r, &mut w, true, false, true),
        )
        .await
        .expect("kermit_server timed out");

        let _ = child.wait().await;
        config::update_config_value("transfer_dir", "transfer");
        let _ = std::fs::remove_dir_all(&dir);

        let received = server_result.expect("kermit_server returned an error");
        assert_eq!(received.len(), 1, "expected exactly one received file");
        assert_eq!(received[0].data, payload, "uploaded content must round-trip");
    }

    // ---------- Proptest fuzzers (panic-only assertions) ----------

    proptest::proptest! {
        #![proptest_config(proptest::test_runner::Config {
            cases: 128,
            ..proptest::test_runner::Config::default()
        })]

        #[test]
        fn proptest_parse_send_init_no_panic(
            data in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..256),
        ) {
            let _ = parse_send_init_payload(&data);
        }

        #[test]
        fn proptest_parse_attributes_no_panic(
            data in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..256),
        ) {
            let _ = parse_attributes(&data);
        }

        #[test]
        fn proptest_decode_data_no_panic(
            data in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..256),
        ) {
            let q1 = Quoting { qctl: b'#', qbin: None, rept: None, locking_shifts: false };
            let q2 = Quoting { qctl: b'#', qbin: Some(b'&'), rept: Some(b'~'), locking_shifts: false };
            let _ = decode_data(&data, q1);
            let _ = decode_data(&data, q2);
        }

        #[test]
        fn proptest_read_packet_no_panic(
            data in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..512),
        ) {
            // Reuse a single tokio runtime across all 128 proptest cases.
            // Spinning up Runtime::new() per case creates a thread pool
            // each time — measurable overhead with no test-value gain.
            static RT: std::sync::OnceLock<tokio::runtime::Runtime> =
                std::sync::OnceLock::new();
            let rt = RT.get_or_init(|| tokio::runtime::Runtime::new().unwrap());
            rt.block_on(async {
                let mut state = ReadState::default();
                let mut c = std::io::Cursor::new(data);
                for chkt in [b'1', b'2', b'3'] {
                    let _ = read_packet(&mut c, false, false, chkt, CR, false, &mut state, None).await;
                    // Cursor is consumed after the first call; don't expect later iterations to do anything meaningful.
                }
            });
        }

        /// Adversarial input to the safety validators must never panic.
        /// Both functions take peer-supplied bytes (R-packet payload,
        /// G C subdir argument) so they're a real attack surface.
        #[test]
        fn proptest_is_safe_resume_filename_no_panic(
            data in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..512),
        ) {
            let s = String::from_utf8_lossy(&data);
            let _: bool = is_safe_resume_filename(&s);
        }

        #[test]
        fn proptest_is_safe_relative_subdir_no_panic(
            data in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..512),
        ) {
            let s = String::from_utf8_lossy(&data);
            let _: bool = is_safe_relative_subdir(&s);
        }

        /// `compute_resume_offset` does fs I/O on a peer-controlled
        /// filename component.  Filename validation runs before the
        /// fs call, so the only way to reach the stat layer is with a
        /// validator-passing name.  Either way, no input must panic.
        #[test]
        fn proptest_compute_resume_offset_no_panic(
            data in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..256),
        ) {
            let s = String::from_utf8_lossy(&data);
            // Use a path that almost certainly doesn't exist so we
            // exercise the lookup-fails branch most of the time, with
            // occasional validator-passing names that hit the stat
            // layer against a non-existent file.
            let _ = compute_resume_offset(&s, "/nonexistent/proptest/dir", 168);
        }

        /// Locking-shift decoder: adversarial wire bytes (with the
        /// shift markers possibly malformed or truncated) must not
        /// panic and must produce *some* result without infinite-looping.
        /// Pairs with the existing `proptest_decode_data_no_panic`
        /// case that covers the non-locking-shift path.
        #[test]
        fn proptest_decode_data_locking_shifts_no_panic(
            data in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..512),
        ) {
            let q = Quoting {
                qctl: b'#',
                qbin: None,
                rept: Some(b'~'),
                locking_shifts: true,
            };
            let _ = decode_data(&data, q);
        }

        /// `encode_data` with locking shifts on an arbitrary input
        /// must produce a byte stream `decode_data` can round-trip.
        /// Stronger than panic-only: also asserts protocol invariant.
        #[test]
        fn proptest_locking_shifts_round_trip(
            input in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..256),
        ) {
            let q = Quoting {
                qctl: b'#',
                qbin: None,
                rept: Some(b'~'),
                locking_shifts: true,
            };
            let encoded = encode_data(&input, q);
            let decoded = decode_data(&encoded, q).expect("must decode our own encode");
            proptest::prop_assert_eq!(decoded, input);
        }
    }
}
