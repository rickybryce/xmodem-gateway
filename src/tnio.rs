//! Shared raw-I/O layer for the file-transfer protocol modules.
//!
//! Centralizes the byte-stream details that are identical across
//! XMODEM/YMODEM, ZMODEM, and Kermit:
//!
//! - **Telnet IAC unescaping.**  On TCP connections the peer doubles
//!   any 0xFF data byte as `IAC IAC`; we collapse it back.  Telnet
//!   command sequences (WILL/WONT/DO/DONT and SB ... SE blocks) are
//!   silently consumed so option-negotiation traffic doesn't show up
//!   as data.
//!
//! - **NVT CR-NUL stripping (RFC 854).**  A bare CR on the wire
//!   appears as `CR NUL`; we drop the trailing NUL so byte counts at
//!   the protocol layer stay aligned with what the sender intended.
//!
//! - **Forsberg's CAN×2 abort rule.**  Two consecutive 0x18 bytes mean
//!   "user pressed Ctrl-X to bail."  XMODEM and Kermit both honor it
//!   (ZMODEM has its own ZCAN frame, so it doesn't use this helper).
//!
//! Each protocol module imports what it needs from here rather than
//! redefining the same ~140 lines.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

// ─── Telnet protocol constants ───────────────────────────────

/// Telnet IAC ("Interpret As Command", 0xFF) — start of every option
/// negotiation or sub-negotiation, doubled when transmitting a literal
/// 0xFF data byte.
pub(crate) const IAC: u8 = 0xFF;
/// Subnegotiation begin — followed by option-specific bytes until SE.
pub(crate) const SB: u8 = 250;
/// Subnegotiation end.
pub(crate) const SE: u8 = 240;
/// Option-negotiation verbs.
pub(crate) const WILL: u8 = 251;
pub(crate) const WONT: u8 = 252;
pub(crate) const DO_CMD: u8 = 253;
pub(crate) const DONT: u8 = 254;

/// CAN (0x18) — bytewise abort signal.  XMODEM and Kermit both adopt
/// Forsberg's "two consecutive CANs = abort" rule; a single CAN is
/// considered line noise.
pub(crate) const CAN: u8 = 0x18;

// ─── Per-stream read state ───────────────────────────────────

/// State threaded through the byte readers so they can implement
/// CR-NUL collapse and CAN×2 detection without losing context across
/// calls.
///
/// - `pushback` holds a byte the CR-NUL lookahead consumed but turned
///   out not to be a NUL; the next read returns it before pulling
///   fresh bytes.
/// - `pending_can` records that the most-recent abort-relevant byte
///   was a CAN.  The next CAN aborts; any non-CAN clears the flag.
///   ZMODEM doesn't use this field (its own CANCAN logic handles
///   abort) but carrying it costs nothing.
#[derive(Default)]
pub(crate) struct ReadState {
    pub(crate) pushback: Option<u8>,
    pub(crate) pending_can: bool,
}

/// Forsberg's CAN×2 abort rule, factored so every read site applies
/// the same state transitions:
///
/// - On CAN: if a previous CAN was already pending, return `true`
///   (caller aborts).  Otherwise set `pending_can` and return `false`
///   so the caller treats the byte as "ignore for now, keep reading."
/// - On any other byte: clear `pending_can` and return `false`.
///
/// Crucially, `pending_can` persists across read calls: a CAN seen
/// during one block followed by a normal byte must NOT abort the
/// session — only **consecutive** CANs do.
pub(crate) fn is_can_abort(byte: u8, state: &mut ReadState) -> bool {
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

// ─── Byte readers ────────────────────────────────────────────

/// Read one logical byte, applying NVT CR-NUL stripping and pushback.
/// After returning a CR (0x0D) we look one byte ahead; if it's NUL we
/// swallow it, otherwise we stash it in `state` for the next call.
pub(crate) async fn nvt_read_byte(
    reader: &mut (impl AsyncRead + Unpin),
    is_tcp: bool,
    state: &mut ReadState,
) -> Result<u8, String> {
    if let Some(b) = state.pushback.take() {
        return Ok(b);
    }
    let byte = raw_read_byte(reader, is_tcp).await?;
    if is_tcp && byte == 0x0D {
        let next = raw_read_byte(reader, is_tcp).await?;
        if next != 0x00 {
            state.pushback = Some(next);
        }
    }
    Ok(byte)
}

/// Read one byte from the wire, transparently consuming any telnet
/// IAC sequences encountered.  `IAC IAC` collapses to a literal 0xFF
/// data byte; other commands are passed to `consume_telnet_command`
/// to drain their payload, then the loop continues looking for a real
/// data byte.
pub(crate) async fn raw_read_byte(
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

/// Drain a telnet command sequence after an IAC and command byte have
/// already been read.  WILL/WONT/DO/DONT each take one option byte;
/// SB ... SE blocks are read until the closing IAC SE pair (with a
/// 5-second timeout so a buggy peer can't wedge us).
pub(crate) async fn consume_telnet_command(
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
                Err(_) => return Err("Telnet subnegotiation timed out".into()),
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

// ─── Byte writer ─────────────────────────────────────────────

/// Write a buffer of bytes to the wire, applying telnet IAC escaping
/// (`0xFF` → `IAC IAC`) and NVT CR-NUL stuffing (`0x0D` → `0x0D 0x00`)
/// when `is_tcp` is true.  Both transforms are required by RFC 854 for
/// transparent transmission of 8-bit data over telnet — skipping
/// either causes mid-block desync at the first 0xFF or 0x0D byte.
pub(crate) async fn raw_write_bytes(
    writer: &mut (impl AsyncWrite + Unpin),
    data: &[u8],
    is_tcp: bool,
) -> Result<(), String> {
    if is_tcp {
        let mut buf = Vec::with_capacity(data.len() + 8);
        for &b in data {
            if b == IAC {
                buf.push(IAC);
                buf.push(IAC);
            } else if b == 0x0D {
                buf.push(0x0D);
                buf.push(0x00);
            } else {
                buf.push(b);
            }
        }
        writer.write_all(&buf).await.map_err(|e| e.to_string())?;
    } else {
        writer.write_all(data).await.map_err(|e| e.to_string())?;
    }
    writer.flush().await.map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_can_abort_state_machine() {
        let mut s = ReadState::default();
        // First CAN sets pending; doesn't abort.
        assert!(!is_can_abort(CAN, &mut s));
        assert!(s.pending_can);
        // Second consecutive CAN aborts.
        assert!(is_can_abort(CAN, &mut s));
        assert!(!s.pending_can);
        // Non-CAN clears pending.
        assert!(!is_can_abort(CAN, &mut s));
        assert!(s.pending_can);
        assert!(!is_can_abort(b'X', &mut s));
        assert!(!s.pending_can);
    }

    #[tokio::test]
    async fn test_raw_write_bytes_iac_escapes() {
        let mut buf: Vec<u8> = Vec::new();
        raw_write_bytes(&mut buf, &[0x41, IAC, 0x42], true).await.unwrap();
        assert_eq!(buf, &[0x41, IAC, IAC, 0x42]);
    }

    #[tokio::test]
    async fn test_raw_write_bytes_cr_null_stuffs() {
        let mut buf: Vec<u8> = Vec::new();
        raw_write_bytes(&mut buf, &[0x41, 0x0D, 0x42], true).await.unwrap();
        assert_eq!(buf, &[0x41, 0x0D, 0x00, 0x42]);
    }

    #[tokio::test]
    async fn test_raw_write_bytes_passthrough_when_not_tcp() {
        let mut buf: Vec<u8> = Vec::new();
        raw_write_bytes(&mut buf, &[0x41, IAC, 0x0D, 0x42], false).await.unwrap();
        assert_eq!(buf, &[0x41, IAC, 0x0D, 0x42]);
    }

    #[tokio::test]
    async fn test_nvt_read_byte_strips_cr_null() {
        let data = vec![0x41, 0x0D, 0x00, 0x42];
        let mut cur = std::io::Cursor::new(data);
        let mut s = ReadState::default();
        assert_eq!(nvt_read_byte(&mut cur, true, &mut s).await.unwrap(), 0x41);
        assert_eq!(nvt_read_byte(&mut cur, true, &mut s).await.unwrap(), 0x0D);
        assert_eq!(nvt_read_byte(&mut cur, true, &mut s).await.unwrap(), 0x42);
    }

    #[tokio::test]
    async fn test_nvt_read_byte_pushes_back_non_null_after_cr() {
        let data = vec![0x0D, 0x42];
        let mut cur = std::io::Cursor::new(data);
        let mut s = ReadState::default();
        assert_eq!(nvt_read_byte(&mut cur, true, &mut s).await.unwrap(), 0x0D);
        assert_eq!(nvt_read_byte(&mut cur, true, &mut s).await.unwrap(), 0x42);
    }

    #[tokio::test]
    async fn test_raw_read_byte_unescapes_iac_iac() {
        let data = vec![IAC, IAC, 0x42];
        let mut cur = std::io::Cursor::new(data);
        assert_eq!(raw_read_byte(&mut cur, true).await.unwrap(), IAC);
        assert_eq!(raw_read_byte(&mut cur, true).await.unwrap(), 0x42);
    }
}
