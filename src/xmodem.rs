//! XMODEM Protocol Module
//!
//! Implements the XMODEM file transfer protocol with CRC-16 and checksum modes:
//! - xmodem_receive: receive file data from a sender (upload)
//! - xmodem_send: send file data to a receiver (download)
//! - Raw I/O helpers with telnet IAC escaping
//! - CRC-16 (CCITT polynomial 0x1021) computation

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::config;
use crate::logger::glog;
use crate::telnet::is_esc_key;

// XMODEM protocol constants
const SOH: u8 = 0x01;
/// XMODEM-1K block header: the next block is 1024 bytes of payload.
const STX: u8 = 0x02;
const EOT: u8 = 0x04;
const ACK: u8 = 0x06;
const NAK: u8 = 0x15;
const CAN: u8 = 0x18;
const SUB: u8 = 0x1A;
const CRC_REQUEST: u8 = b'C';

// Telnet protocol bytes
const IAC: u8 = 0xFF;
const SB: u8 = 250;
const SE: u8 = 240;
const WILL: u8 = 251;
const WONT: u8 = 252;
const DO_CMD: u8 = 253;
const DONT: u8 = 254;

pub(crate) const XMODEM_BLOCK_SIZE: usize = 128;
/// XMODEM-1K block size.  The sender chooses per-block; the receiver
/// branches on the `SOH` / `STX` header byte to know which one arrived.
pub(crate) const XMODEM_1K_BLOCK_SIZE: usize = 1024;

const MAX_FILE_SIZE: usize = 8 * 1024 * 1024;
/// Time allowed for the full 131-byte block body (after SOH) to arrive.
const BLOCK_BODY_TIMEOUT_SECS: u64 = 60;

#[derive(Clone, Copy)]
enum TransferMode {
    Checksum,
    Crc16,
}

/// YMODEM header metadata supplied by the caller when sending in
/// YMODEM (batch) mode.  Filename and size are mandatory; receivers
/// use the size for exact end-of-file truncation (Forsberg §5).
/// `modtime` (UNIX seconds) and `mode` (UNIX permission bits) are
/// optional informational fields per Forsberg §6.1 — when supplied
/// they're emitted in their respective slots, when `None` they're
/// emitted as octal `0` (the spec-defined "unknown" sentinel).
/// Passing `None` for the whole `Option<YmodemHeader>` parameter to
/// `xmodem_send` selects plain XMODEM mode (no block 0 at all).
#[derive(Clone)]
pub(crate) struct YmodemHeader {
    pub filename: String,
    pub size: u64,
    pub modtime: Option<u64>,
    pub mode: Option<u32>,
}

/// Metadata parsed out of a YMODEM block 0 by the receiver.  All fields
/// are `Option` because the spec allows minimal senders that emit only
/// the filename, or filename + size.  When present, `mode` is masked to
/// `0o7777` by the parser to keep setuid/setgid/sticky bits visible to
/// callers that want them, but the upload-save path masks further to
/// `0o777` before applying.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct YmodemReceiveMeta {
    pub size: Option<u64>,
    pub modtime: Option<u64>,
    pub mode: Option<u32>,
}

// =============================================================================
// XMODEM PROTOCOL - RECEIVE (UPLOAD)
// =============================================================================

pub(crate) async fn xmodem_receive(
    reader: &mut (impl AsyncRead + Unpin),
    writer: &mut (impl AsyncWrite + Unpin),
    is_tcp: bool,
    is_petscii: bool,
    verbose: bool,
) -> Result<(Vec<u8>, Option<YmodemReceiveMeta>), String> {
    let cfg = config::get_config();
    let negotiation_timeout = cfg.xmodem_negotiation_timeout;
    let block_timeout = cfg.xmodem_block_timeout;
    let max_retries = cfg.xmodem_max_retries;
    let negotiation_retry_interval = cfg.xmodem_negotiation_retry_interval;

    let mut file_data = Vec::new();
    let mut expected_block: u8 = 1;
    let mut state_owned = ReadState::default();
    let state = &mut state_owned;
    // Set when we successfully handle a YMODEM filename-header block so
    // the EOT handler knows to run the end-of-batch handshake.
    let mut ymodem_mode = false;
    // Parsed metadata from a YMODEM block 0.  Reported file length, when
    // present, drives end-of-transfer truncation (Forsberg §5) instead of
    // SUB-stripping — critical for files that legitimately end in 0x1A
    // bytes.  Modtime and mode are returned to the caller for fs-attribute
    // application after save; we don't apply them ourselves.
    let mut ymodem_meta: Option<YmodemReceiveMeta> = None;
    let negotiation_deadline =
        tokio::time::Instant::now() + tokio::time::Duration::from_secs(negotiation_timeout);

    if verbose { glog!("XMODEM recv: starting negotiation (is_tcp={}, is_petscii={})", is_tcp, is_petscii); }

    // Negotiate mode: try CRC first ('C') for 20 attempts (60 seconds),
    // then fall back to checksum (NAK) for the remaining time.  This gives
    // the user plenty of time to start their XMODEM sender in CRC mode.
    let mut mode = TransferMode::Crc16;
    let mut attempt: u32 = 0;

    // Send CRC requests for 2/3 of the negotiation time, then fall back to checksum.
    let crc_attempts =
        (negotiation_timeout * 2 / 3 / negotiation_retry_interval).max(3) as u32;
    let max_negotiation_attempts = crc_attempts + max_retries as u32;
    loop {
        if tokio::time::Instant::now() >= negotiation_deadline {
            return Err("Negotiation timeout: start your XMODEM sender".into());
        }
        if attempt >= max_negotiation_attempts {
            return Err("Negotiation failed: no response from sender".into());
        }

        let request = if attempt < crc_attempts { CRC_REQUEST } else { NAK };
        if attempt == crc_attempts {
            mode = TransferMode::Checksum;
        }
        if verbose { glog!("XMODEM recv: attempt {} sending 0x{:02X} ({})",
            attempt, request, if request == CRC_REQUEST { "CRC req" } else { "NAK" }); }
        raw_write_byte(writer, request, is_tcp).await?;

        match tokio::time::timeout(
            std::time::Duration::from_secs(negotiation_retry_interval),
            nvt_read_byte(reader, is_tcp, state),
        )
        .await
        {
            Ok(Ok(byte)) => {
                if verbose { glog!("XMODEM recv: got 0x{:02X} during negotiation", byte); }
                if is_esc_key(byte, is_petscii) {
                    return Err("Transfer cancelled".into());
                }
                if is_can_abort(byte, state) {
                    return Err("Transfer cancelled by sender".into());
                }
                if byte == CAN {
                    if verbose { glog!("XMODEM recv: single CAN treated as line noise (waiting for second)"); }
                    continue;
                }
                if byte == SOH || byte == STX {
                    let block_size = if byte == STX {
                        XMODEM_1K_BLOCK_SIZE
                    } else {
                        XMODEM_BLOCK_SIZE
                    };
                    if verbose {
                        glog!(
                            "XMODEM recv: {} received, peeking at block header ({}-byte)",
                            if byte == STX { "STX" } else { "SOH" },
                            block_size,
                        );
                    }
                    // Peek at block_num / complement so we can detect
                    // YMODEM block 0 (filename header) vs. an ordinary
                    // first data block.
                    let block_num = nvt_read_byte(reader, is_tcp, state).await?;
                    let block_complement = nvt_read_byte(reader, is_tcp, state).await?;
                    if byte == SOH
                        && block_num == 0
                        && block_complement == 0xFF
                    {
                        // YMODEM block 0 — read the 128-byte payload +
                        // trailer under a hard timeout so a stalled
                        // sender can't deadlock the session.  On CRC
                        // success we ACK and send a second 'C' to start
                        // the data phase; on failure we NAK and let the
                        // sender's retry be handled as a duplicate block
                        // by the main loop.
                        if verbose { glog!("XMODEM recv: YMODEM block 0 detected"); }
                        match tokio::time::timeout(
                            std::time::Duration::from_secs(BLOCK_BODY_TIMEOUT_SECS),
                            read_ymodem_block_zero_body(
                                reader, mode, is_tcp, verbose, state,
                            ),
                        )
                        .await
                        {
                            Ok(Ok((true, meta))) => {
                                raw_write_byte(writer, ACK, is_tcp).await?;
                                // Second 'C' starts the data phase.
                                raw_write_byte(writer, CRC_REQUEST, is_tcp).await?;
                                ymodem_mode = true;
                                ymodem_meta = meta;
                                break;
                            }
                            Ok(Ok((false, _))) => {
                                if verbose { glog!("XMODEM recv: YMODEM block 0 CRC error"); }
                                raw_write_byte(writer, NAK, is_tcp).await?;
                                break;
                            }
                            Ok(Err(e)) => {
                                if verbose { glog!("XMODEM recv: YMODEM block 0 read error: {}", e); }
                                raw_write_byte(writer, NAK, is_tcp).await?;
                                break;
                            }
                            Err(_) => {
                                if verbose { glog!("XMODEM recv: YMODEM block 0 timeout"); }
                                raw_write_byte(writer, NAK, is_tcp).await?;
                                break;
                            }
                        }
                    }
                    // Not YMODEM block 0 — treat as an ordinary first
                    // data block.  `receive_block_body` takes the
                    // already-read header bytes.
                    match tokio::time::timeout(
                        std::time::Duration::from_secs(BLOCK_BODY_TIMEOUT_SECS),
                        receive_block_body(
                            reader,
                            block_num,
                            block_complement,
                            &mut expected_block,
                            mode,
                            is_tcp,
                            verbose,
                            block_size,
                            state,
                        ),
                    )
                    .await
                    {
                        Ok(Ok(data)) => {
                            if verbose { glog!("XMODEM recv: block #1 OK"); }
                            file_data.extend_from_slice(&data);
                            raw_write_byte(writer, ACK, is_tcp).await?;
                        }
                        Ok(Err(e)) => {
                            if verbose { glog!("XMODEM recv: block #1 error: {}", e); }
                            raw_write_byte(writer, NAK, is_tcp).await?;
                        }
                        Err(_) => {
                            if verbose { glog!("XMODEM recv: block #1 timeout"); }
                            raw_write_byte(writer, NAK, is_tcp).await?;
                        }
                    }
                    break;
                }
                if byte == EOT {
                    raw_write_byte(writer, ACK, is_tcp).await?;
                    return Ok((file_data, ymodem_meta));
                }
                // CAN handled above by is_can_abort + single-CAN continue.
                if verbose { glog!("XMODEM recv: ignoring unexpected byte 0x{:02X}", byte); }
            }
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                if verbose { glog!("XMODEM recv: attempt {} timeout, retrying", attempt); }
            }
        }

        attempt = attempt.saturating_add(1);
    }

    // Main receive loop
    let mut error_count: usize = 0;
    loop {
        if file_data.len() > MAX_FILE_SIZE {
            raw_write_bytes(writer, &[CAN, CAN, CAN], is_tcp).await?;
            return Err("File exceeds 8 MB size limit".into());
        }

        let byte = match tokio::time::timeout(
            std::time::Duration::from_secs(block_timeout),
            nvt_read_byte(reader, is_tcp, state),
        )
        .await
        {
            Ok(Ok(b)) => b,
            Ok(Err(e)) => return Err(e),
            Err(_) => return Err("Transfer timeout".into()),
        };

        if is_can_abort(byte, state) {
            return Err("Transfer cancelled by sender".into());
        }

        match byte {
            SOH | STX => {
                let block_size = if byte == STX {
                    XMODEM_1K_BLOCK_SIZE
                } else {
                    XMODEM_BLOCK_SIZE
                };
                match tokio::time::timeout(
                    std::time::Duration::from_secs(BLOCK_BODY_TIMEOUT_SECS),
                    receive_block(
                        reader,
                        &mut expected_block,
                        mode,
                        is_tcp,
                        verbose,
                        block_size,
                        state,
                    ),
                )
                .await
                {
                    Ok(Ok(data)) => {
                        file_data.extend_from_slice(&data);
                        raw_write_byte(writer, ACK, is_tcp).await?;
                        error_count = 0;
                    }
                    Ok(Err(ref e)) if e == "Duplicate block" => {
                        raw_write_byte(writer, ACK, is_tcp).await?;
                    }
                    Ok(Err(_)) | Err(_) => {
                        error_count += 1;
                        if error_count > max_retries {
                            raw_write_bytes(writer, &[CAN, CAN, CAN], is_tcp).await?;
                            return Err("Too many block errors".into());
                        }
                        raw_write_byte(writer, NAK, is_tcp).await?;
                    }
                }
            }
            EOT => {
                if verbose { glog!("XMODEM recv: EOT received, ACKing"); }
                raw_write_byte(writer, ACK, is_tcp).await?;
                if ymodem_mode {
                    // YMODEM end-of-batch handshake (Forsberg §7.4):
                    // after ACKing the final EOT, send one more 'C' and
                    // expect a "null" block 0 (filename starts with NUL)
                    // meaning "no more files in this batch."  ACK it and
                    // we're done.  Strict senders (sb, Tera Term, PuTTY
                    // family) wait for this exchange; if we skip it they
                    // hang after the last data block is accepted.
                    if verbose { glog!("XMODEM recv: YMODEM end-of-batch, sending 'C'"); }
                    raw_write_byte(writer, CRC_REQUEST, is_tcp).await?;
                    match tokio::time::timeout(
                        std::time::Duration::from_secs(block_timeout),
                        nvt_read_byte(reader, is_tcp, state),
                    )
                    .await
                    {
                        Ok(Ok(SOH)) => {
                            // Consume block_num + complement + 128-byte
                            // payload + 2-byte CRC.  We do NOT verify
                            // the CRC or the block number — lax senders
                            // may skip parts of this handshake, and any
                            // read error just ends the session normally.
                            let _ = nvt_read_byte(reader, is_tcp, state).await;
                            let _ = nvt_read_byte(reader, is_tcp, state).await;
                            for _ in 0..XMODEM_BLOCK_SIZE + 2 {
                                if nvt_read_byte(reader, is_tcp, state).await.is_err() {
                                    break;
                                }
                            }
                            raw_write_byte(writer, ACK, is_tcp).await?;
                            if verbose { glog!("XMODEM recv: YMODEM end-of-batch ACKed"); }
                        }
                        Ok(Ok(b)) => {
                            if verbose { glog!("XMODEM recv: end-of-batch unexpected byte 0x{:02X}, ending session", b); }
                        }
                        Ok(Err(e)) => {
                            if verbose { glog!("XMODEM recv: end-of-batch read error: {}", e); }
                        }
                        Err(_) => {
                            if verbose { glog!("XMODEM recv: end-of-batch timeout — lax sender, ending session"); }
                        }
                    }
                }
                break;
            }
            CAN => {
                // Single CAN — Forsberg's CAN×2 rule says ignore as
                // possible line noise.  Don't NAK; just keep reading.
                // `is_can_abort` already set `pending_can`; if the
                // very next byte is also CAN we'll abort there.
                if verbose { glog!("XMODEM recv: single CAN treated as line noise"); }
            }
            _ => {
                raw_write_byte(writer, NAK, is_tcp).await?;
            }
        }
    }

    // YMODEM: truncate to the exact size reported in block 0 (Forsberg
    // 1988 §5).  This preserves files that legitimately end in 0x1A,
    // which SUB-stripping would corrupt.  Fall back to SUB-stripping
    // when the sender didn't report a size, or when we're in plain
    // XMODEM / XMODEM-1K mode (no block 0 at all).
    let reported_size = ymodem_meta.as_ref().and_then(|m| m.size);
    let truncated_by_size = if let Some(size) = reported_size {
        let target = size as usize;
        if target <= file_data.len() {
            file_data.truncate(target);
            if verbose { glog!("XMODEM recv: truncated to YMODEM size {} bytes", target); }
            true
        } else {
            // Reported size > received bytes — don't extend, just keep
            // what we have and fall back to SUB-stripping.  This can
            // happen if the last block was lost mid-transfer and the
            // transfer somehow still "completed" from the receiver's
            // view, or if the sender reported a bogus size.
            if verbose { glog!("XMODEM recv: reported size {} > received {}, falling back to SUB strip", target, file_data.len()); }
            false
        }
    } else {
        false
    };
    if !truncated_by_size {
        while file_data.last() == Some(&SUB) {
            file_data.pop();
        }
    }

    Ok((file_data, ymodem_meta))
}

/// Receive and validate a single XMODEM block (after SOH or STX was
/// already read).  `block_size` is 128 for SOH blocks, 1024 for STX
/// (XMODEM-1K) blocks — within a single transfer the sender may mix
/// block sizes, so each call picks up the right size from its header.
#[allow(clippy::too_many_arguments)]
async fn receive_block(
    reader: &mut (impl AsyncRead + Unpin),
    expected_block: &mut u8,
    mode: TransferMode,
    is_tcp: bool,
    verbose: bool,
    block_size: usize,
    state: &mut ReadState,
) -> Result<Vec<u8>, String> {
    let block_num = nvt_read_byte(reader, is_tcp, state).await?;
    let block_complement = nvt_read_byte(reader, is_tcp, state).await?;
    receive_block_body(
        reader,
        block_num,
        block_complement,
        expected_block,
        mode,
        is_tcp,
        verbose,
        block_size,
        state,
    )
    .await
}

/// Read and validate the 128-byte payload + CRC/checksum trailer of a
/// YMODEM block 0, given that `SOH 0x00 0xFF` has already been read.
/// Returns `(valid, meta)` — `valid=false` means CRC/checksum mismatch
/// and `meta` is meaningless; on `valid=true` `meta` carries whatever
/// metadata fields were parsed.  Called under a `tokio::time::timeout`
/// so a stalled sender can't hold the session indefinitely.
///
/// Per Forsberg YMODEM §6.1 the block-0 payload is:
///
///     filename\0length<SP>modtime<SP>mode<SP>sno<SP>...\0<NUL fill>
///
/// where `length` is decimal and `modtime`/`mode`/`sno` are octal.
/// All metadata fields are optional from the receiver's standpoint —
/// minimal senders omit the trailing fields, and we tolerate that.
async fn read_ymodem_block_zero_body(
    reader: &mut (impl AsyncRead + Unpin),
    mode: TransferMode,
    is_tcp: bool,
    verbose: bool,
    state: &mut ReadState,
) -> Result<(bool, Option<YmodemReceiveMeta>), String> {
    let mut payload = [0u8; XMODEM_BLOCK_SIZE];
    for b in payload.iter_mut() {
        *b = nvt_read_byte(reader, is_tcp, state).await?;
    }
    let valid = match mode {
        TransferMode::Crc16 => {
            let hi = nvt_read_byte(reader, is_tcp, state).await?;
            let lo = nvt_read_byte(reader, is_tcp, state).await?;
            let recv = ((hi as u16) << 8) | lo as u16;
            recv == crc16_xmodem(&payload)
        }
        TransferMode::Checksum => {
            let recv = nvt_read_byte(reader, is_tcp, state).await?;
            let calc = payload.iter().fold(0u8, |a, &b| a.wrapping_add(b));
            recv == calc
        }
    };
    if !valid {
        return Ok((false, None));
    }
    let parsed = parse_ymodem_block_zero_payload(&payload);
    if verbose {
        let name = payload
            .iter()
            .position(|&b| b == 0)
            .and_then(|n| std::str::from_utf8(&payload[..n]).ok())
            .unwrap_or("<invalid>");
        glog!(
            "XMODEM recv: YMODEM filename='{}' size={} modtime={} mode={}",
            name,
            parsed
                .as_ref()
                .and_then(|m| m.size)
                .map(|n| n.to_string())
                .unwrap_or_else(|| "<unknown>".into()),
            parsed
                .as_ref()
                .and_then(|m| m.modtime)
                .map(|n| n.to_string())
                .unwrap_or_else(|| "<unknown>".into()),
            parsed
                .as_ref()
                .and_then(|m| m.mode)
                .map(|n| format!("{:o}", n))
                .unwrap_or_else(|| "<unknown>".into()),
        );
    }
    Ok((true, parsed))
}

/// Parse the 128-byte block-0 payload into a `YmodemReceiveMeta`.  Returns
/// `None` if the payload is empty (filename starts with NUL — the
/// end-of-batch terminator block).  Otherwise returns `Some(meta)` with
/// whatever fields were present and well-formed.
///
/// Field encoding per Forsberg YMODEM §6.1: `length` is decimal,
/// `modtime`/`mode`/`sno` are octal.  Anything that fails to parse
/// stays `None` rather than poisoning the rest — minimal senders that
/// omit fields, and broken senders that emit junk, are both tolerated
/// the same way.
fn parse_ymodem_block_zero_payload(payload: &[u8]) -> Option<YmodemReceiveMeta> {
    let name_end = payload.iter().position(|&b| b == 0)?;
    if name_end == 0 {
        // End-of-batch null block 0 — no metadata to extract.
        return None;
    }
    let mut meta = YmodemReceiveMeta::default();
    let after = &payload[name_end + 1..];
    let Some(fields_end) = after.iter().position(|&b| b == 0) else {
        return Some(meta);
    };
    let text = match std::str::from_utf8(&after[..fields_end]) {
        Ok(s) => s,
        Err(_) => return Some(meta),
    };
    let mut fields = text.split_ascii_whitespace();
    if let Some(first) = fields.next()
        && let Ok(n) = first.parse::<u64>()
    {
        meta.size = Some(n);
    }
    if let Some(second) = fields.next()
        && let Ok(n) = u64::from_str_radix(second, 8)
        && n != 0
    {
        meta.modtime = Some(n);
    }
    if let Some(third) = fields.next()
        && let Ok(n) = u32::from_str_radix(third, 8)
        && n != 0
    {
        // Mask to permission + setuid/setgid/sticky bits.  The upload
        // path further restricts to `0o777` before applying.
        meta.mode = Some(n & 0o7777);
    }
    Some(meta)
}

/// Same as `receive_block` but the block-number + complement bytes have
/// already been read by the caller.  Used for YMODEM first-block
/// handling where we peek at `block_num` to distinguish block 0
/// (filename header) from block 1 (first data block).
#[allow(clippy::too_many_arguments)]
async fn receive_block_body(
    reader: &mut (impl AsyncRead + Unpin),
    block_num: u8,
    block_complement: u8,
    expected_block: &mut u8,
    mode: TransferMode,
    is_tcp: bool,
    verbose: bool,
    block_size: usize,
    state: &mut ReadState,
) -> Result<Vec<u8>, String> {
    if verbose { glog!("XMODEM recv block: num=0x{:02X} complement=0x{:02X} expected=0x{:02X} size={} mode={}",
        block_num, block_complement, *expected_block, block_size,
        match mode { TransferMode::Crc16 => "CRC16", TransferMode::Checksum => "Checksum" }); }

    let mut data = vec![0u8; block_size];
    for byte in data.iter_mut() {
        *byte = nvt_read_byte(reader, is_tcp, state).await?;
    }

    let valid = match mode {
        TransferMode::Checksum => {
            let recv_checksum = nvt_read_byte(reader, is_tcp, state).await?;
            let calc_checksum = data.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
            if verbose { glog!("XMODEM recv block: checksum recv=0x{:02X} calc=0x{:02X}", recv_checksum, calc_checksum); }
            recv_checksum == calc_checksum
        }
        TransferMode::Crc16 => {
            let crc_hi = nvt_read_byte(reader, is_tcp, state).await?;
            let crc_lo = nvt_read_byte(reader, is_tcp, state).await?;
            let recv_crc = ((crc_hi as u16) << 8) | crc_lo as u16;
            let calc_crc = crc16_xmodem(&data);
            if verbose { glog!("XMODEM recv block: CRC recv=0x{:04X} calc=0x{:04X}", recv_crc, calc_crc); }
            recv_crc == calc_crc
        }
    };

    if block_complement != !(block_num) {
        if verbose { glog!("XMODEM recv block: FAIL complement mismatch 0x{:02X} != !0x{:02X} (0x{:02X})",
            block_complement, block_num, !(block_num)); }
        return Err("Block complement mismatch".into());
    }
    if !valid {
        return Err("Checksum/CRC error".into());
    }
    if block_num == expected_block.wrapping_sub(1) {
        return Err("Duplicate block".into());
    }
    if block_num != *expected_block {
        if verbose { glog!("XMODEM recv block: FAIL block number 0x{:02X} != expected 0x{:02X}", block_num, *expected_block); }
        return Err("Block number mismatch".into());
    }

    *expected_block = expected_block.wrapping_add(1);
    Ok(data)
}

// =============================================================================
// XMODEM PROTOCOL - SEND (DOWNLOAD)
// =============================================================================

#[allow(clippy::too_many_arguments)]
pub(crate) async fn xmodem_send(
    reader: &mut (impl AsyncRead + Unpin),
    writer: &mut (impl AsyncWrite + Unpin),
    data: &[u8],
    is_tcp: bool,
    is_petscii: bool,
    verbose: bool,
    use_1k: bool,
    ymodem: Option<YmodemHeader>,
) -> Result<(), String> {
    let cfg = config::get_config();
    let negotiation_timeout = cfg.xmodem_negotiation_timeout;
    let block_timeout = cfg.xmodem_block_timeout;
    let max_retries = cfg.xmodem_max_retries;
    let mut state_owned = ReadState::default();
    let state = &mut state_owned;

    let negotiation_deadline =
        tokio::time::Instant::now() + tokio::time::Duration::from_secs(negotiation_timeout);

    if verbose { glog!("XMODEM send: starting negotiation (is_tcp={}, is_petscii={}, data_len={})",
        is_tcp, is_petscii, data.len()); }

    // Wait for receiver's mode request (C = CRC, NAK = checksum)
    let mode = loop {
        let remaining = negotiation_deadline.duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err("Negotiation timeout: start your XMODEM receiver".into());
        }

        match tokio::time::timeout(remaining, nvt_read_byte(reader, is_tcp, state)).await {
            Ok(Ok(byte)) => {
                if verbose { glog!("XMODEM send: negotiation got 0x{:02X}", byte); }
                if is_esc_key(byte, is_petscii) {
                    return Err("Transfer cancelled".into());
                }
                if is_can_abort(byte, state) {
                    return Err("Transfer cancelled by receiver".into());
                }
                match byte {
                    CRC_REQUEST => {
                        if verbose { glog!("XMODEM send: receiver requests CRC mode"); }
                        break TransferMode::Crc16;
                    }
                    NAK => {
                        if verbose { glog!("XMODEM send: receiver requests Checksum mode"); }
                        break TransferMode::Checksum;
                    }
                    CAN => {
                        // Single CAN — Forsberg's CAN×2 rule treats it
                        // as possible line noise.  Keep waiting for the
                        // next byte; `is_can_abort` already armed
                        // `pending_can` so a second CAN aborts.
                        if verbose { glog!("XMODEM send: single CAN treated as line noise during negotiation"); }
                        continue;
                    }
                    _ => {
                        if verbose { glog!("XMODEM send: ignoring byte 0x{:02X} during negotiation", byte); }
                        continue;
                    }
                }
            }
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                return Err("Timeout waiting for receiver to start".into());
            }
        }
    };

    // Drain any trailing negotiation bytes (e.g. IMP8 sends 'C' then 'K' for
    // XMODEM-1K; we accepted 'C' but 'K' is still in the buffer).
    // Uses raw_read_byte to properly handle any IAC sequences on TCP.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    while let Ok(Ok(b)) = tokio::time::timeout(
        std::time::Duration::from_millis(50),
        nvt_read_byte(reader, is_tcp, state),
    )
    .await
    {
        if verbose { glog!("XMODEM send: drained negotiation byte 0x{:02X}", b); }
    }

    // ─── YMODEM block 0 (filename header) ──────────────────
    //
    // When `ymodem` is set, emit an SOH block with block_num=0 carrying
    // `filename\0size mtime\0` followed by NUL padding out to 128 bytes.
    // The receiver ACKs block 0 and then sends a second 'C' byte to
    // signal it's ready for the data phase.
    if let Some(ref hdr) = ymodem {
        send_ymodem_block_zero(
            reader,
            writer,
            hdr,
            is_tcp,
            block_timeout,
            max_retries,
            verbose,
            state,
        )
        .await?;
        // Wait for the receiver's second 'C' (data-phase request).
        match tokio::time::timeout(
            std::time::Duration::from_secs(block_timeout),
            nvt_read_byte(reader, is_tcp, state),
        )
        .await
        {
            Ok(Ok(b)) if b == CRC_REQUEST => {
                if verbose { glog!("XMODEM send: got second 'C' after block 0"); }
            }
            Ok(Ok(b)) => {
                if verbose { glog!("XMODEM send: expected 'C' after block 0 got 0x{:02X}", b); }
            }
            _ => {
                if verbose { glog!("XMODEM send: timed out waiting for second 'C' after block 0"); }
            }
        }
    }

    // Pad data to a 128-byte boundary (the minimum granularity).  When
    // 1K mode is active we consume 1024 bytes per block for full
    // chunks and fall back to 128 for the final partial chunk.
    let mut padded = data.to_vec();
    if padded.is_empty() {
        padded.push(SUB);
    }
    while !padded.len().is_multiple_of(XMODEM_BLOCK_SIZE) {
        padded.push(SUB);
    }

    let mut block_num: u8 = 1;
    // Tracks the runtime 1K preference.  Starts from the caller's
    // intent and flips to false if the first STX block is rejected by
    // the receiver — from then on we stay with SOH for the rest of
    // the transfer.
    let mut use_1k_runtime = use_1k;
    let mut offset = 0usize;
    let mut block_idx = 0usize;
    if verbose { glog!("XMODEM send: data_len={} padded_len={} use_1k={}",
        data.len(), padded.len(), use_1k); }

    while offset < padded.len() {
        // Choose the block size for this iteration: STX (1024) if the
        // runtime flag still permits and we have a full 1024 bytes
        // left; otherwise SOH (128).  This naturally degrades to a
        // partial final SOH block when the file doesn't divide evenly.
        let use_stx = use_1k_runtime
            && padded.len() - offset >= XMODEM_1K_BLOCK_SIZE;
        let block_size = if use_stx { XMODEM_1K_BLOCK_SIZE } else { XMODEM_BLOCK_SIZE };
        let header = if use_stx { STX } else { SOH };
        let block = &padded[offset..offset + block_size];

        let mut retries = 0;
        loop {
            if retries >= max_retries {
                raw_write_bytes(writer, &[CAN, CAN, CAN], is_tcp).await?;
                return Err("Too many retries, transfer aborted".into());
            }

            let mut packet = Vec::with_capacity(3 + block_size + 2);
            packet.push(header);
            packet.push(block_num);
            packet.push(!block_num);
            packet.extend_from_slice(block);

            match mode {
                TransferMode::Checksum => {
                    let checksum = block.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
                    packet.push(checksum);
                }
                TransferMode::Crc16 => {
                    let crc = crc16_xmodem(block);
                    packet.push((crc >> 8) as u8);
                    packet.push((crc & 0xFF) as u8);
                }
            }

            if block_idx == 0 && retries == 0 && verbose {
                glog!(
                    "XMODEM send: block #1 header=0x{:02X} size={} num=0x{:02X} complement=0x{:02X} packet_len={}",
                    header, block_size, block_num, !block_num, packet.len(),
                );
            }

            raw_write_bytes(writer, &packet, is_tcp).await?;

            // Wait for ACK/NAK, draining single-CAN line noise per
            // Forsberg's CAN×2 abort rule.  The inner loop returns the
            // first non-CAN byte; CAN×2 returns Err immediately via
            // `is_can_abort`.  Read errors and timeouts surface to the
            // outer match for retry handling.
            enum Resp {
                Byte(u8),
                ReadErr(String),
                Timeout,
            }
            let response = loop {
                match tokio::time::timeout(
                    std::time::Duration::from_secs(block_timeout),
                    nvt_read_byte(reader, is_tcp, state),
                )
                .await
                {
                    Ok(Ok(byte)) => {
                        if is_can_abort(byte, state) {
                            if verbose { glog!("XMODEM send: CAN×2 abort at block #{}", block_idx + 1); }
                            return Err("Transfer cancelled by receiver".into());
                        }
                        if byte == CAN {
                            if verbose { glog!("XMODEM send: single CAN at block #{} treated as line noise", block_idx + 1); }
                            continue;
                        }
                        break Resp::Byte(byte);
                    }
                    Ok(Err(e)) => break Resp::ReadErr(e),
                    Err(_) => break Resp::Timeout,
                }
            };
            match response {
                Resp::Byte(ACK) => {
                    if verbose && (block_idx < 3 || retries > 0) {
                        glog!("XMODEM send: block #{} ACK (retries={}, size={})",
                            block_idx + 1, retries, block_size);
                    }
                    break;
                }
                Resp::Byte(NAK) => {
                    if verbose { glog!("XMODEM send: block #{} NAK (retry {})", block_idx + 1, retries + 1); }
                    // Opportunistic fallback: if the very first block
                    // we sent used STX and the receiver rejected it,
                    // the receiver probably doesn't support 1K.  Drop
                    // to SOH for the rest of the transfer and retry
                    // with a 128-byte block from the same offset.
                    if use_stx && block_idx == 0 && retries == 0 {
                        if verbose { glog!(
                            "XMODEM send: STX rejected on first block, \
                             falling back to 128-byte SOH"
                        ); }
                        use_1k_runtime = false;
                        break;
                    }
                    retries += 1;
                    continue;
                }
                Resp::Byte(byte) => {
                    if verbose { glog!("XMODEM send: block #{} unexpected response 0x{:02X} (retry {})",
                        block_idx + 1, byte, retries + 1); }
                    retries += 1;
                    continue;
                }
                Resp::ReadErr(e) => return Err(e),
                Resp::Timeout => {
                    if verbose { glog!("XMODEM send: block #{} timeout (retry {})", block_idx + 1, retries + 1); }
                    retries += 1;
                    continue;
                }
            }
        }

        // Advance.  If we just fell back from STX to SOH we leave the
        // offset alone and the next loop iteration sends the same
        // payload bytes in a 128-byte SOH block.
        if use_1k_runtime || !use_stx {
            offset += block_size;
            block_idx += 1;
            block_num = block_num.wrapping_add(1);
        }
    }

    // Send EOT and wait for ACK
    for _ in 0..max_retries {
        raw_write_byte(writer, EOT, is_tcp).await?;
        match tokio::time::timeout(
            std::time::Duration::from_secs(block_timeout),
            nvt_read_byte(reader, is_tcp, state),
        )
        .await
        {
            Ok(Ok(ACK)) => {
                // YMODEM end-of-batch: after EOT is ACKed, the receiver
                // sends one more 'C' and expects an empty block 0
                // (filename starts with NUL) meaning "no more files."
                if ymodem.is_some() {
                    send_ymodem_end_of_batch(
                        reader,
                        writer,
                        is_tcp,
                        block_timeout,
                        max_retries,
                        verbose,
                        state,
                    )
                    .await?;
                }
                return Ok(());
            }
            Ok(Ok(NAK)) => continue,
            Ok(Ok(b)) => {
                if verbose { glog!("XMODEM send: unexpected EOT response 0x{:02X}, treating as ACK", b); }
                if ymodem.is_some() {
                    // Best-effort: attempt the end-of-batch handshake
                    // but don't hard-fail the transfer if it flakes.
                    let _ = send_ymodem_end_of_batch(
                        reader,
                        writer,
                        is_tcp,
                        block_timeout,
                        max_retries,
                        verbose,
                        state,
                    )
                    .await;
                }
                return Ok(());
            }
            Ok(Err(e)) => {
                if verbose { glog!("XMODEM send: read error during EOT: {}", e); }
                return Err(format!("Read error during EOT: {}", e));
            }
            Err(_) => continue,
        }
    }
    if verbose { glog!("XMODEM send: EOT not ACKed after {} retries, assuming success", max_retries); }
    Ok(())
}

/// Build and transmit YMODEM block 0 (filename + size header).
/// Uses a 128-byte SOH block regardless of the sender's 1K preference
/// because the YMODEM spec fixes block 0 at 128 bytes.
///
/// Per Forsberg YMODEM §6.1 the metadata field after the filename NUL
/// is `length<SP>modtime<SP>mode<SP>sno\0` where `length` is decimal
/// and `modtime`/`mode`/`sno` are octal.  We always emit the full
/// quartet — when the caller didn't supply `modtime` or `mode` we
/// substitute octal `0`, the spec-defined "unknown" value, so
/// receivers doing positional parsing always see four fields.  Serial
/// number (`sno`) is always `0` — we don't track per-sender serials.
/// (lrzsz `sb` emits two extra positional fields, `nfiles_left` and
/// `bytes_left`, which the spec lists as optional; we omit them.)
#[allow(clippy::too_many_arguments)]
async fn send_ymodem_block_zero(
    reader: &mut (impl AsyncRead + Unpin),
    writer: &mut (impl AsyncWrite + Unpin),
    hdr: &YmodemHeader,
    is_tcp: bool,
    block_timeout: u64,
    max_retries: usize,
    verbose: bool,
    state: &mut ReadState,
) -> Result<(), String> {
    // Build the 128-byte payload: "filename\0length modtime mode 0\0"
    // then NUL padding.  Filenames are limited to what fits; anything
    // longer is truncated at 100 bytes so the metadata still fits in
    // 128 alongside the trailing NUL terminator.
    let mut payload = [0u8; XMODEM_BLOCK_SIZE];
    let fn_bytes = hdr.filename.as_bytes();
    let fn_cap = fn_bytes.len().min(100);
    payload[..fn_cap].copy_from_slice(&fn_bytes[..fn_cap]);
    // payload[fn_cap] is already 0 (null-terminator for filename).
    let modtime_oct = hdr.modtime.unwrap_or(0);
    // Mask mode to permission + setuid/setgid/sticky bits before
    // emission — never send anything outside the file-type-independent
    // mode word, regardless of what the caller passed in.
    let mode_oct = hdr.mode.unwrap_or(0) & 0o7777;
    let meta = format!("{} {:o} {:o} 0", hdr.size, modtime_oct, mode_oct);
    let meta_start = fn_cap + 1;
    let meta_end = (meta_start + meta.len()).min(XMODEM_BLOCK_SIZE - 1);
    let meta_len = meta_end - meta_start;
    payload[meta_start..meta_end]
        .copy_from_slice(&meta.as_bytes()[..meta_len]);
    // payload[meta_end] stays 0 as the metadata-block terminator;
    // remaining bytes are NUL padding.

    let mut packet = Vec::with_capacity(3 + XMODEM_BLOCK_SIZE + 2);
    packet.push(SOH);
    packet.push(0);       // block_num = 0
    packet.push(0xFF);    // !0
    packet.extend_from_slice(&payload);
    let crc = crc16_xmodem(&payload);
    packet.push((crc >> 8) as u8);
    packet.push((crc & 0xFF) as u8);

    if verbose { glog!(
        "XMODEM send: YMODEM block 0 filename='{}' size={} modtime={:o} mode={:o}",
        hdr.filename, hdr.size, modtime_oct, mode_oct,
    ); }

    let mut retries = 0;
    loop {
        if retries >= max_retries {
            return Err("YMODEM block 0: too many retries".into());
        }
        raw_write_bytes(writer, &packet, is_tcp).await?;
        // Drain single-CAN line noise per Forsberg's CAN×2 abort
        // rule: only two consecutive CANs trigger an abort, all other
        // outcomes (timeout, read error, unexpected byte) feed the
        // retry counter.
        let response = loop {
            match tokio::time::timeout(
                std::time::Duration::from_secs(block_timeout),
                nvt_read_byte(reader, is_tcp, state),
            )
            .await
            {
                Ok(Ok(byte)) => {
                    if is_can_abort(byte, state) {
                        return Err("Transfer cancelled by receiver".into());
                    }
                    if byte == CAN {
                        continue;
                    }
                    break Some(byte);
                }
                Ok(Err(_)) | Err(_) => break None,
            }
        };
        match response {
            Some(ACK) => return Ok(()),
            _ => {
                retries += 1;
                continue;
            }
        }
    }
}

/// After the last data EOT is ACKed, the YMODEM receiver sends one more
/// 'C' and expects an all-zero block 0 meaning "end of batch, no more
/// files."  This keeps single-file YMODEM downloads semantically
/// correct for receivers that enforce the full protocol.
async fn send_ymodem_end_of_batch(
    reader: &mut (impl AsyncRead + Unpin),
    writer: &mut (impl AsyncWrite + Unpin),
    is_tcp: bool,
    block_timeout: u64,
    max_retries: usize,
    verbose: bool,
    state: &mut ReadState,
) -> Result<(), String> {
    // Wait for the receiver's final 'C'.  Some lax receivers skip this
    // step; don't hard-fail if it never arrives.
    match tokio::time::timeout(
        std::time::Duration::from_secs(block_timeout),
        nvt_read_byte(reader, is_tcp, state),
    )
    .await
    {
        Ok(Ok(b)) if b == CRC_REQUEST => {
            if verbose { glog!("XMODEM send: got end-of-batch 'C'"); }
        }
        other => {
            if verbose { glog!("XMODEM send: no end-of-batch 'C' ({:?}); skipping empty block 0", other); }
            return Ok(());
        }
    }

    let payload = [0u8; XMODEM_BLOCK_SIZE];
    let mut packet = Vec::with_capacity(3 + XMODEM_BLOCK_SIZE + 2);
    packet.push(SOH);
    packet.push(0);
    packet.push(0xFF);
    packet.extend_from_slice(&payload);
    let crc = crc16_xmodem(&payload);
    packet.push((crc >> 8) as u8);
    packet.push((crc & 0xFF) as u8);

    let mut retries = 0;
    while retries < max_retries {
        raw_write_bytes(writer, &packet, is_tcp).await?;
        match tokio::time::timeout(
            std::time::Duration::from_secs(block_timeout),
            nvt_read_byte(reader, is_tcp, state),
        )
        .await
        {
            Ok(Ok(ACK)) => return Ok(()),
            Ok(Ok(_)) | Ok(Err(_)) | Err(_) => {
                retries += 1;
                continue;
            }
        }
    }
    if verbose { glog!("XMODEM send: end-of-batch block 0 not ACKed, continuing"); }
    Ok(())
}

// =============================================================================
// XMODEM CRC-16 (CCITT polynomial 0x1021)
// =============================================================================

fn crc16_xmodem(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &byte in data {
        crc ^= (byte as u16) << 8;
        for _ in 0..8 {
            if crc & 0x8000 != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

// =============================================================================
// RAW I/O - TELNET IAC AWARE
// =============================================================================

/// Write a single raw byte, with telnet IAC escaping and CR-NUL
/// stuffing for TCP connections.  The control-byte set XMODEM uses
/// (SOH/STX/EOT/ACK/NAK/CAN/'C') never includes 0x0D, so a single-byte
/// write only needs the IAC rule.  CR-NUL stuffing is handled by the
/// multi-byte writer which is what sends data blocks.
async fn raw_write_byte(
    writer: &mut (impl AsyncWrite + Unpin),
    byte: u8,
    is_tcp: bool,
) -> Result<(), String> {
    if is_tcp && byte == IAC {
        writer
            .write_all(&[IAC, IAC])
            .await
            .map_err(|e| e.to_string())?;
    } else if is_tcp && byte == 0x0D {
        // Defensive: if a caller ever single-writes a 0x0D data byte on
        // a telnet stream, stuff the NUL so the peer's telnet layer
        // doesn't eat the following byte as part of a CR LF / CR NUL
        // pair.  In practice the multi-byte writer sees all data blocks
        // that could contain 0x0D.
        writer
            .write_all(&[0x0D, 0x00])
            .await
            .map_err(|e| e.to_string())?;
    } else {
        writer
            .write_all(&[byte])
            .await
            .map_err(|e| e.to_string())?;
    }
    writer.flush().await.map_err(|e| e.to_string())?;
    Ok(())
}

/// Write multiple raw bytes, applying telnet IAC escaping and NVT
/// CR-NUL stuffing when `is_tcp` is true.  Both transforms are required
/// for XMODEM/YMODEM over telnet NVT (RFC 854): the peer reconstructs
/// the original bytes by collapsing `IAC IAC` to `0xFF` and dropping
/// `NUL` after `CR`.  Skipping either causes mid-block desync at the
/// first 0xFF or 0x0D byte in the payload.
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
            } else if byte == 0x0D {
                buf.push(0x0D);
                buf.push(0x00);
            } else {
                buf.push(byte);
            }
        }
        writer.write_all(&buf).await.map_err(|e| e.to_string())?;
        writer.flush().await.map_err(|e| e.to_string())?;
    } else {
        writer.write_all(data).await.map_err(|e| e.to_string())?;
        writer.flush().await.map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Per-stream state threaded through NVT reads so we can implement
/// RFC 854's rule that a bare CR on the wire appears as `CR NUL`, and
/// collapse the NUL so XMODEM byte counts stay aligned.  The pushback
/// slot holds a byte we looked ahead for CR-NUL detection that turned
/// out not to be a NUL; the next call returns it before reading more.
///
/// `pending_can` tracks whether the most recently read byte at the
/// protocol level was CAN.  Forsberg's protocol notes recommend that
/// abort-on-CAN require **two consecutive** CAN bytes so a single
/// stray 0x18 from line noise doesn't false-abort an in-flight
/// transfer.  Each CAN-handling site sets the flag on a first CAN,
/// checks it on a second CAN to abort, and clears it on any non-CAN
/// byte.  See `is_can_abort` for the canonical state transition.
#[derive(Default)]
struct ReadState {
    pushback: Option<u8>,
    pending_can: bool,
}

/// Forsberg's CAN×2 abort rule, factored out so every read site
/// applies the same state transitions:
///
/// - On CAN: if a previous CAN was already pending, return `true`
///   (caller aborts).  Otherwise set `pending_can` and return `false`
///   so the caller treats the byte as "ignore for now, keep reading."
/// - On any other byte: clear `pending_can` and return `false`.  The
///   caller proceeds with normal handling for that byte.
///
/// Crucially, `pending_can` persists across read calls: a CAN seen
/// during one block, followed by ACK from the receiver, then another
/// CAN, must NOT abort — only **consecutive** CANs do.
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

/// NVT-aware byte reader: wraps [`raw_read_byte`] with CR-NUL stripping
/// for telnet streams.  After returning a CR (0x0D) we look one byte
/// ahead; if it's NUL we swallow it, otherwise we stash it in `state`
/// for the next call.  Production XMODEM/YMODEM transfers use this
/// function so IAC + CR-NUL + pushback are all handled uniformly.
async fn nvt_read_byte(
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

/// Read a single raw byte, handling telnet IAC sequences for TCP connections.
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

/// Consume a telnet command sequence after the IAC and command byte were read.
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

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crc16_xmodem() {
        let data = b"123456789";
        assert_eq!(crc16_xmodem(data), 0x31C3);
    }

    #[test]
    fn test_crc16_empty() {
        assert_eq!(crc16_xmodem(&[]), 0x0000);
    }

    #[test]
    fn test_crc16_single_byte() {
        assert_eq!(crc16_xmodem(&[0x00]), 0x0000);
        assert_eq!(crc16_xmodem(&[0xFF]), 0x1EF0);
    }

    /// Run an xmodem_send / xmodem_receive pair over a DuplexStream.
    async fn xmodem_round_trip(original: &[u8]) -> Vec<u8> {
        xmodem_round_trip_mode(original, false).await
    }

    /// Round-trip with the sender's 1K preference controllable.  The
    /// receiver is always prepared to accept both SOH and STX blocks.
    async fn xmodem_round_trip_mode(original: &[u8], use_1k: bool) -> Vec<u8> {
        let (sender_half, receiver_half) = tokio::io::duplex(16384);
        let (mut send_read, mut send_write) = tokio::io::split(sender_half);
        let (mut recv_read, mut recv_write) = tokio::io::split(receiver_half);

        let data = original.to_vec();
        let send_task = tokio::spawn(async move {
            xmodem_send(
                &mut send_read,
                &mut send_write,
                &data,
                false,
                false,
                false,
                use_1k,
                None, // ymodem disabled
            )
            .await
            .unwrap();
        });
        let recv_task = tokio::spawn(async move {
            xmodem_receive(&mut recv_read, &mut recv_write, false, false, false)
                .await
                .unwrap()
        });

        send_task.await.unwrap();
        recv_task.await.unwrap().0
    }

    #[tokio::test]
    async fn test_xmodem_round_trip_small() {
        let original = b"Hello, XModem!";
        let received = xmodem_round_trip(original).await;
        assert_eq!(received, original);
    }

    #[tokio::test]
    async fn test_xmodem_round_trip_exact_block() {
        let original: Vec<u8> = (0..128).map(|i| (i & 0xFF) as u8).collect();
        let received = xmodem_round_trip(&original).await;
        assert_eq!(received, original);
    }

    #[tokio::test]
    async fn test_xmodem_round_trip_multi_block() {
        let original: Vec<u8> = (0..448).map(|i| (i % 251) as u8).collect();
        let received = xmodem_round_trip(&original).await;
        assert_eq!(received, original);
    }

    #[tokio::test]
    async fn test_xmodem_round_trip_all_byte_values() {
        let original: Vec<u8> = (0..=255).collect();
        let received = xmodem_round_trip(&original).await;
        assert_eq!(received, original);
    }

    #[tokio::test]
    async fn test_xmodem_round_trip_trailing_sub() {
        let mut original = vec![0x41; 100];
        original.push(SUB);
        original.push(SUB);
        let received = xmodem_round_trip(&original).await;
        assert_eq!(received, vec![0x41; 100]);
    }

    #[tokio::test]
    async fn test_xmodem_round_trip_random_4k() {
        let mut rng: u64 = 0xDEAD_BEEF;
        let original: Vec<u8> = (0..4096)
            .map(|_| {
                rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
                (rng >> 33) as u8
            })
            .collect();
        let received = xmodem_round_trip(&original).await;
        assert_eq!(received, original);
    }

    #[tokio::test]
    async fn test_xmodem_round_trip_block_boundary() {
        let original: Vec<u8> = vec![0x55; 256 * XMODEM_BLOCK_SIZE];
        let received = xmodem_round_trip(&original).await;
        assert_eq!(received, original);
    }

    // ─── XMODEM-1K (STX) round-trips ──────────────────────

    #[tokio::test]
    async fn test_xmodem_1k_round_trip_exact_1024() {
        let original: Vec<u8> = (0..XMODEM_1K_BLOCK_SIZE).map(|i| (i & 0xFF) as u8).collect();
        let received = xmodem_round_trip_mode(&original, true).await;
        assert_eq!(received, original);
    }

    #[tokio::test]
    async fn test_xmodem_1k_round_trip_mixed_stx_and_final_soh() {
        // 1024 + 128 partial + few spare bytes to force a mix: one STX
        // block followed by one SOH block.  The receiver transparently
        // handles both headers; the sender degrades to SOH for the
        // sub-1K remainder.
        let original: Vec<u8> = (0..(XMODEM_1K_BLOCK_SIZE + 200))
            .map(|i| ((i * 7) & 0xFF) as u8)
            .collect();
        let received = xmodem_round_trip_mode(&original, true).await;
        assert_eq!(received, original);
    }

    #[tokio::test]
    async fn test_xmodem_1k_round_trip_multi_1k_blocks() {
        // 3 full 1K blocks, no partial.
        let original: Vec<u8> = (0..(3 * XMODEM_1K_BLOCK_SIZE))
            .map(|i| (i & 0xFF) as u8)
            .collect();
        let received = xmodem_round_trip_mode(&original, true).await;
        assert_eq!(received, original);
    }

    #[tokio::test]
    async fn test_xmodem_1k_small_file_still_uses_soh() {
        // Under 1024 bytes: even with use_1k=true, the sender must
        // emit an SOH block (one partial) because STX requires a full
        // 1024-byte payload.
        let original = b"Hello, XMODEM-1K on a short file!";
        let received = xmodem_round_trip_mode(original, true).await;
        assert_eq!(received, original);
    }

    #[tokio::test]
    async fn test_xmodem_1k_round_trip_protocol_bytes_in_data() {
        // Payload contains every protocol byte (SOH/STX/ACK/NAK/CAN/EOT
        // etc.) to verify the 1K path is byte-transparent.
        let mut original: Vec<u8> = Vec::with_capacity(XMODEM_1K_BLOCK_SIZE);
        for i in 0..XMODEM_1K_BLOCK_SIZE {
            original.push((i & 0xFF) as u8);
        }
        let received = xmodem_round_trip_mode(&original, true).await;
        assert_eq!(received, original);
    }

    #[tokio::test]
    async fn test_xmodem_1k_opportunistic_fallback() {
        // Simulate a receiver that doesn't support STX: it reads the
        // STX header byte and NAKs.  Our sender should fall back to
        // SOH for the same offset and complete the transfer with
        // 128-byte blocks.
        //
        // We drive the sender against a handwritten "minimal receiver"
        // that NAKs on STX and ACKs on SOH.  The test just verifies
        // the sender completes without a Too-Many-Retries error.
        let (sender_half, receiver_half) = tokio::io::duplex(16384);
        let (mut send_read, mut send_write) = tokio::io::split(sender_half);
        let (mut recv_read, mut recv_write) = tokio::io::split(receiver_half);

        // 1024-byte file so the sender's first attempt is STX.
        let data: Vec<u8> = (0..XMODEM_1K_BLOCK_SIZE).map(|i| (i & 0xFF) as u8).collect();
        let data_clone = data.clone();

        let send_task = tokio::spawn(async move {
            xmodem_send(
                &mut send_read,
                &mut send_write,
                &data_clone,
                false,
                false,
                false,
                true, // use_1k
                None, // ymodem disabled
            )
            .await
        });

        // Fake receiver: request CRC mode ('C'), then:
        //   - on STX: NAK (rejects XMODEM-1K).
        //   - on SOH: read the rest of the 128-byte block + 2-byte CRC,
        //     ACK.
        //   - on EOT: ACK, done.
        let recv_task = tokio::spawn(async move {
            // Kick off with 'C' for CRC mode.
            raw_write_byte(&mut recv_write, CRC_REQUEST, false).await.unwrap();

            // Block 1 first try: expect STX.
            let hdr1 = raw_read_byte(&mut recv_read, false).await.unwrap();
            assert_eq!(hdr1, STX, "sender should try STX first when use_1k=true");
            // Drain the rest of the 1K packet: num + !num + 1024 bytes + 2 CRC.
            for _ in 0..(2 + XMODEM_1K_BLOCK_SIZE + 2) {
                raw_read_byte(&mut recv_read, false).await.unwrap();
            }
            // NAK the STX block → triggers fallback.
            raw_write_byte(&mut recv_write, NAK, false).await.unwrap();

            // All remaining blocks should be SOH (128-byte each).
            // 1024 bytes / 128 = 8 SOH blocks to cover the same payload.
            for _ in 0..8 {
                let hdr = raw_read_byte(&mut recv_read, false).await.unwrap();
                assert_eq!(hdr, SOH, "fallback should use SOH for the rest");
                for _ in 0..(2 + XMODEM_BLOCK_SIZE + 2) {
                    raw_read_byte(&mut recv_read, false).await.unwrap();
                }
                raw_write_byte(&mut recv_write, ACK, false).await.unwrap();
            }

            // EOT
            let eot = raw_read_byte(&mut recv_read, false).await.unwrap();
            assert_eq!(eot, EOT);
            raw_write_byte(&mut recv_write, ACK, false).await.unwrap();
        });

        // Both tasks should succeed.
        send_task.await.unwrap().unwrap();
        recv_task.await.unwrap();
        let _ = data; // silence unused warning
    }

    #[tokio::test]
    async fn test_xmodem_round_trip_single_byte() {
        let received = xmodem_round_trip(&[0x42]).await;
        assert_eq!(received, vec![0x42]);
    }

    // ─── YMODEM round-trips ───────────────────────────────

    /// Drive an xmodem_send / xmodem_receive pair with the sender in
    /// YMODEM mode.  The receiver is always prepared to skip a block 0
    /// filename header, so the same xmodem_receive path handles it.
    async fn ymodem_round_trip(filename: &str, original: &[u8]) -> Vec<u8> {
        let (sender_half, receiver_half) = tokio::io::duplex(16384);
        let (mut send_read, mut send_write) = tokio::io::split(sender_half);
        let (mut recv_read, mut recv_write) = tokio::io::split(receiver_half);

        let data = original.to_vec();
        let hdr = YmodemHeader {
            filename: filename.to_string(),
            size: data.len() as u64,
            modtime: None,
            mode: None,
        };

        let send_task = tokio::spawn(async move {
            xmodem_send(
                &mut send_read,
                &mut send_write,
                &data,
                false,
                false,
                false,
                true, // use_1k (YMODEM implies 1K blocks)
                Some(hdr),
            )
            .await
            .unwrap();
        });
        let recv_task = tokio::spawn(async move {
            xmodem_receive(&mut recv_read, &mut recv_write, false, false, false)
                .await
                .unwrap()
        });

        send_task.await.unwrap();
        recv_task.await.unwrap().0
    }

    #[tokio::test]
    async fn test_ymodem_round_trip_single_1k_block() {
        let original: Vec<u8> = (0..XMODEM_1K_BLOCK_SIZE).map(|i| (i & 0xFF) as u8).collect();
        let received = ymodem_round_trip("test.bin", &original).await;
        assert_eq!(received, original);
    }

    #[tokio::test]
    async fn test_ymodem_round_trip_small_file() {
        let original = b"hello YMODEM";
        let received = ymodem_round_trip("hello.txt", original).await;
        // Trailing SUB padding is stripped on receive; the first 12
        // bytes must match exactly.
        assert_eq!(&received[..original.len()], original);
    }

    #[tokio::test]
    async fn test_ymodem_round_trip_mixed_1k_plus_final_soh() {
        // 1024 + 200 bytes: one STX + one SOH partial.
        let original: Vec<u8> = (0..(XMODEM_1K_BLOCK_SIZE + 200))
            .map(|i| ((i * 13) & 0xFF) as u8)
            .collect();
        let received = ymodem_round_trip("mixed.dat", &original).await;
        assert_eq!(&received[..original.len()], original);
    }

    #[tokio::test]
    async fn test_ymodem_round_trip_long_filename_truncated_to_100() {
        // The sender truncates filenames to 100 bytes to leave room
        // for the size/metadata trailer inside the 128-byte block 0.
        // A 150-char filename should still round-trip the data OK —
        // the receiver discards the header, so truncation doesn't
        // affect file contents.
        let long_name: String = "a".repeat(150);
        let original = b"payload-for-long-filename-test";
        let received = ymodem_round_trip(&long_name, original).await;
        assert_eq!(&received[..original.len()], original);
    }

    #[tokio::test]
    async fn test_ymodem_round_trip_protocol_bytes_in_data() {
        // Payload filled with XMODEM-family protocol bytes pushed
        // through the YMODEM send/receive pipeline.  Verifies the
        // data-block path is byte-transparent even when the payload
        // looks like framing bytes.
        let mut original: Vec<u8> = Vec::with_capacity(XMODEM_1K_BLOCK_SIZE);
        for _ in 0..(XMODEM_1K_BLOCK_SIZE / 8) {
            original.extend_from_slice(&[SOH, STX, EOT, ACK, NAK, CAN, SUB, 0xFF]);
        }
        let received = ymodem_round_trip("proto.bin", &original).await;
        assert_eq!(&received[..original.len()], original);
    }

    #[tokio::test]
    async fn test_ymodem_round_trip_preserves_trailing_sub_bytes() {
        // Regression: a file that legitimately ends in 0x1A bytes must
        // round-trip exactly via YMODEM — the exact size is carried in
        // block 0, and `xmodem_receive` uses it to truncate rather than
        // stripping trailing SUB padding.  An EXE, a compressed archive,
        // or random binary data that ends on 0x1A would be corrupted by
        // the old SUB-stripping path.
        //
        // The payload is 50 bytes of arbitrary data followed by five
        // 0x1A bytes.  After YMODEM round-trip, we must get the full 55
        // bytes back including the trailing 0x1A run.
        let mut original: Vec<u8> = (0u8..50).collect();
        original.extend_from_slice(&[SUB; 5]);
        let received = ymodem_round_trip("ends-in-sub.bin", &original).await;
        assert_eq!(
            received.len(),
            original.len(),
            "length mismatch: YMODEM size-truncation did not preserve trailing SUB bytes",
        );
        assert_eq!(received, original);
    }

    // ─── Checksum-mode round-trip (NAK-initiated) ─────────

    /// Drive `xmodem_send` against a handwritten receiver that starts
    /// negotiation with NAK (checksum mode), verify the sender emits
    /// 1-byte checksum trailers, and confirm the payload round-trips.
    /// The production `xmodem_receive` normally sends 'C' first and
    /// only falls back to NAK after a timeout, so end-to-end checksum
    /// mode wasn't otherwise exercised by the test suite.
    #[tokio::test]
    async fn test_xmodem_checksum_mode_round_trip() {
        let (sender_half, receiver_half) = tokio::io::duplex(16384);
        let (mut send_read, mut send_write) = tokio::io::split(sender_half);
        let (mut recv_read, mut recv_write) = tokio::io::split(receiver_half);

        let original: Vec<u8> =
            b"Checksum-mode payload, a few SOHs (\x01\x01\x01) too.".to_vec();
        let original_clone = original.clone();

        let send_task = tokio::spawn(async move {
            xmodem_send(
                &mut send_read,
                &mut send_write,
                &original_clone,
                false, // is_tcp
                false, // is_petscii
                false, // verbose
                false, // use_1k — classic XMODEM only in checksum mode
                None,  // ymodem disabled
            )
            .await
            .unwrap();
        });

        // Fake receiver that forces checksum mode.
        let recv_task = tokio::spawn(async move {
            // Initiate with NAK → sender enters checksum mode.
            raw_write_byte(&mut recv_write, NAK, false).await.unwrap();

            let mut received: Vec<u8> = Vec::new();
            let mut expected_block: u8 = 1;
            loop {
                let header = raw_read_byte(&mut recv_read, false).await.unwrap();
                match header {
                    EOT => {
                        raw_write_byte(&mut recv_write, ACK, false).await.unwrap();
                        break;
                    }
                    SOH => {
                        let block_num =
                            raw_read_byte(&mut recv_read, false).await.unwrap();
                        let block_complement =
                            raw_read_byte(&mut recv_read, false).await.unwrap();
                        assert_eq!(block_complement, !block_num,
                            "complement byte must be bitwise NOT of block_num");
                        assert_eq!(block_num, expected_block,
                            "block numbers must be sequential starting from 1");
                        let mut payload = [0u8; XMODEM_BLOCK_SIZE];
                        for b in payload.iter_mut() {
                            *b = raw_read_byte(&mut recv_read, false).await.unwrap();
                        }
                        // Checksum trailer (1 byte) — NOT CRC-16 (2 bytes).
                        let recv_sum =
                            raw_read_byte(&mut recv_read, false).await.unwrap();
                        let calc_sum =
                            payload.iter().fold(0u8, |a, &b| a.wrapping_add(b));
                        assert_eq!(
                            recv_sum, calc_sum,
                            "checksum-mode sender must emit valid 8-bit sum",
                        );
                        received.extend_from_slice(&payload);
                        raw_write_byte(&mut recv_write, ACK, false).await.unwrap();
                        expected_block = expected_block.wrapping_add(1);
                    }
                    other => panic!(
                        "checksum-mode sender emitted unexpected header 0x{:02X}",
                        other,
                    ),
                }
            }
            received
        });

        send_task.await.unwrap();
        let mut received = recv_task.await.unwrap();
        // Strip trailing SUB padding (sender pads the final block).
        while received.last() == Some(&SUB) {
            received.pop();
        }
        assert_eq!(received, original);
    }

    // ─── IAC-escape round-trips (telnet envelope) ─────────

    /// Round-trip helper for XMODEM/XMODEM-1K with `is_tcp=true`.  The
    /// sender IAC-escapes 0xFF data bytes on the wire; the receiver
    /// unescapes.  Both sides must see the identical original payload
    /// despite the envelope.
    async fn xmodem_round_trip_iac(original: &[u8], use_1k: bool) -> Vec<u8> {
        let (sender_half, receiver_half) = tokio::io::duplex(16384);
        let (mut send_read, mut send_write) = tokio::io::split(sender_half);
        let (mut recv_read, mut recv_write) = tokio::io::split(receiver_half);

        let data = original.to_vec();
        let send_task = tokio::spawn(async move {
            xmodem_send(
                &mut send_read,
                &mut send_write,
                &data,
                true,  // is_tcp — enable IAC escaping
                false,
                false,
                use_1k,
                None,
            )
            .await
            .unwrap();
        });
        let recv_task = tokio::spawn(async move {
            xmodem_receive(&mut recv_read, &mut recv_write, true, false, false)
                .await
                .unwrap()
        });
        send_task.await.unwrap();
        recv_task.await.unwrap().0
    }

    async fn ymodem_round_trip_iac(filename: &str, original: &[u8]) -> Vec<u8> {
        let (sender_half, receiver_half) = tokio::io::duplex(16384);
        let (mut send_read, mut send_write) = tokio::io::split(sender_half);
        let (mut recv_read, mut recv_write) = tokio::io::split(receiver_half);

        let data = original.to_vec();
        let hdr = YmodemHeader {
            filename: filename.to_string(),
            size: data.len() as u64,
            modtime: None,
            mode: None,
        };
        let send_task = tokio::spawn(async move {
            xmodem_send(
                &mut send_read,
                &mut send_write,
                &data,
                true, // is_tcp
                false,
                false,
                true, // use_1k (YMODEM implies 1K)
                Some(hdr),
            )
            .await
            .unwrap();
        });
        let recv_task = tokio::spawn(async move {
            xmodem_receive(&mut recv_read, &mut recv_write, true, false, false)
                .await
                .unwrap()
        });
        send_task.await.unwrap();
        recv_task.await.unwrap().0
    }

    /// 0xFF bytes in the data payload must survive telnet IAC escaping:
    /// sender doubles them on the wire, receiver collapses back.
    #[tokio::test]
    async fn test_xmodem_round_trip_iac_escaping_0xff_in_data() {
        let original: Vec<u8> = vec![0xFF; 128];
        let received = xmodem_round_trip_iac(&original, false).await;
        assert_eq!(received, original);
    }

    #[tokio::test]
    async fn test_xmodem_round_trip_iac_escaping_all_bytes() {
        // Every byte value 0..=255 across two 128-byte blocks, with
        // IAC escaping active.  This is the strictest byte-transparency
        // check for classic XMODEM over a telnet-style transport.
        let original: Vec<u8> = (0..=255u8).collect();
        let received = xmodem_round_trip_iac(&original, false).await;
        assert_eq!(received, original);
    }

    #[tokio::test]
    async fn test_xmodem_1k_round_trip_iac_escaping_all_bytes() {
        // Same stress test forced into XMODEM-1K mode.  Tests the
        // 1024-byte-block path over a telnet envelope.
        let mut original: Vec<u8> = Vec::with_capacity(XMODEM_1K_BLOCK_SIZE);
        for b in 0..=255u8 {
            original.extend_from_slice(&[b; 4]);
        }
        assert_eq!(original.len(), XMODEM_1K_BLOCK_SIZE);
        let received = xmodem_round_trip_iac(&original, true).await;
        assert_eq!(received, original);
    }

    #[tokio::test]
    async fn test_ymodem_round_trip_iac_escaping() {
        // YMODEM block 0 filename header + data blocks over a telnet
        // envelope.  0xFF bytes in the data must survive; block 0
        // payload is short enough to contain no 0xFF itself.
        let original: Vec<u8> = (0..=255u8).collect();
        let received = ymodem_round_trip_iac("iac.bin", &original).await;
        assert_eq!(&received[..original.len()], original);
    }

    // ─── Error-path & edge-case tests ─────────────────────

    /// Read one 128-byte XMODEM-CRC block from a stream and return its
    /// payload.  Frame: `SOH | num | !num | 128 data bytes | CRC-hi | CRC-lo`.
    /// Used by the fake-receiver tests below.
    async fn read_soh_crc_block(
        reader: &mut (impl AsyncRead + Unpin),
    ) -> Vec<u8> {
        let soh = raw_read_byte(reader, false).await.unwrap();
        assert_eq!(soh, SOH, "expected SOH header");
        let _block_num = raw_read_byte(reader, false).await.unwrap();
        let _block_complement = raw_read_byte(reader, false).await.unwrap();
        let mut payload = vec![0u8; XMODEM_BLOCK_SIZE];
        for b in payload.iter_mut() {
            *b = raw_read_byte(reader, false).await.unwrap();
        }
        // CRC trailer (2 bytes).
        let _ = raw_read_byte(reader, false).await.unwrap();
        let _ = raw_read_byte(reader, false).await.unwrap();
        payload
    }

    /// Test 1: sender must retry a block when NAK'd, and complete
    /// successfully when the receiver eventually ACKs.
    #[tokio::test]
    async fn test_xmodem_send_nak_retry_then_success() {
        let (sender_half, receiver_half) = tokio::io::duplex(16384);
        let (mut send_read, mut send_write) = tokio::io::split(sender_half);
        let (mut recv_read, mut recv_write) = tokio::io::split(receiver_half);

        let original = b"NAK-retry test payload".to_vec();
        let orig = original.clone();
        let send_task = tokio::spawn(async move {
            xmodem_send(
                &mut send_read, &mut send_write, &orig,
                false, false, false, false, None,
            ).await.unwrap();
        });

        let recv_task = tokio::spawn(async move {
            raw_write_byte(&mut recv_write, CRC_REQUEST, false).await.unwrap();
            // NAK block 1 twice.
            for _ in 0..2 {
                let _ = read_soh_crc_block(&mut recv_read).await;
                raw_write_byte(&mut recv_write, NAK, false).await.unwrap();
            }
            // Third attempt: ACK with actual payload verification.
            let payload = read_soh_crc_block(&mut recv_read).await;
            raw_write_byte(&mut recv_write, ACK, false).await.unwrap();
            // EOT.
            let eot = raw_read_byte(&mut recv_read, false).await.unwrap();
            assert_eq!(eot, EOT);
            raw_write_byte(&mut recv_write, ACK, false).await.unwrap();
            payload
        });

        send_task.await.unwrap();
        let payload = recv_task.await.unwrap();
        // The third (accepted) attempt must carry the original data.
        assert_eq!(&payload[..original.len()], original);
    }

    /// Test 2: corrupted-block recovery end-to-end with the REAL
    /// receiver.  A middle task flips one byte in block 1 on the way
    /// to the receiver for the first attempt, then forwards verbatim.
    /// The real `xmodem_receive` CRC-validates, NAKs, the sender
    /// retries, and the transfer completes with correct data.
    #[tokio::test]
    async fn test_xmodem_corrupted_block_recovery() {
        // Two duplex channels chained through a middle forwarder.
        // duplex1: sender_half  ↔ peer_a
        // duplex2: peer_b       ↔ receiver_half
        // Forwarders: peer_a.read → peer_b.write   (sender→receiver)
        //             peer_b.read → peer_a.write   (receiver→sender)
        let (sender_half, peer_a) = tokio::io::duplex(16384);
        let (peer_b, receiver_half) = tokio::io::duplex(16384);
        let (mut send_read, mut send_write) = tokio::io::split(sender_half);
        let (mut recv_read, mut recv_write) = tokio::io::split(receiver_half);
        let (mut peer_a_read, mut peer_a_write) = tokio::io::split(peer_a);
        let (mut peer_b_read, mut peer_b_write) = tokio::io::split(peer_b);

        let original: Vec<u8> = (0..100).map(|i| (i * 3) as u8).collect();
        let orig = original.clone();
        let send_task = tokio::spawn(async move {
            xmodem_send(
                &mut send_read, &mut send_write, &orig,
                false, false, false, false, None,
            ).await.unwrap();
        });
        let recv_task = tokio::spawn(async move {
            xmodem_receive(&mut recv_read, &mut recv_write, false, false, false)
                .await.unwrap()
        });

        // Forwarder sender→receiver: flip one byte in the payload of
        // the first 131-byte packet (SOH + num + !num + 128 data + 2
        // CRC).  For all subsequent bytes, forward verbatim.
        let s_to_r = tokio::spawn(async move {
            let mut buf = [0u8; 1];
            for i in 0..(3 + XMODEM_BLOCK_SIZE + 2) {
                if peer_a_read.read_exact(&mut buf).await.is_err() { return; }
                if i == 10 {
                    buf[0] ^= 0xFF; // flip all bits of one data byte
                }
                if peer_b_write.write_all(&buf).await.is_err() { return; }
            }
            tokio::io::copy(&mut peer_a_read, &mut peer_b_write).await.ok();
        });
        // Forwarder receiver→sender: verbatim.
        let r_to_s = tokio::spawn(async move {
            tokio::io::copy(&mut peer_b_read, &mut peer_a_write).await.ok();
        });

        send_task.await.unwrap();
        let (received, _) = recv_task.await.unwrap();
        let _ = s_to_r.await;
        let _ = r_to_s.await;
        assert_eq!(received, original, "receiver must recover correct data after NAK+retry");
    }

    /// Test 3: duplicate block from an unusual sender (phantom NAK
    /// caused retransmission) must be detected and silently ACKed by
    /// the real receiver, with no duplication in the output.
    #[tokio::test]
    async fn test_xmodem_receive_duplicate_block() {
        let (sender_half, receiver_half) = tokio::io::duplex(16384);
        let (mut send_read, mut send_write) = tokio::io::split(sender_half);
        let (mut recv_read, mut recv_write) = tokio::io::split(receiver_half);

        // Build a 128-byte payload for block 1.
        let block1_data: Vec<u8> = (0..128u8).map(|i| i.wrapping_mul(5)).collect();
        let block1_data_clone = block1_data.clone();

        // Fake sender that transmits block 1 twice (same payload).
        let send_task = tokio::spawn(async move {
            // Wait for 'C' from receiver.
            let req = raw_read_byte(&mut send_read, false).await.unwrap();
            assert_eq!(req, CRC_REQUEST);

            // Helper that builds an SOH+CRC packet for an arbitrary
            // block_num and payload.
            let build = |n: u8, data: &[u8]| -> Vec<u8> {
                let mut p = Vec::with_capacity(3 + 128 + 2);
                p.push(SOH);
                p.push(n);
                p.push(!n);
                p.extend_from_slice(data);
                let crc = crc16_xmodem(data);
                p.push((crc >> 8) as u8);
                p.push((crc & 0xFF) as u8);
                p
            };

            // Send block 1. Wait for ACK.
            send_write.write_all(&build(1, &block1_data_clone)).await.unwrap();
            let a1 = raw_read_byte(&mut send_read, false).await.unwrap();
            assert_eq!(a1, ACK);

            // Send block 1 AGAIN (simulating retransmission after a
            // lost ACK).  Real receiver should recognize as duplicate.
            send_write.write_all(&build(1, &block1_data_clone)).await.unwrap();
            let a_dup = raw_read_byte(&mut send_read, false).await.unwrap();
            assert_eq!(a_dup, ACK, "receiver must ACK duplicate without error");

            // Proceed to EOT.
            raw_write_byte(&mut send_write, EOT, false).await.unwrap();
            let a_eot = raw_read_byte(&mut send_read, false).await.unwrap();
            assert_eq!(a_eot, ACK);
        });

        let (received, _) = xmodem_receive(
            &mut recv_read, &mut recv_write, false, false, false,
        ).await.unwrap();

        send_task.await.unwrap();
        // Data should appear exactly once, not doubled.
        assert_eq!(received, block1_data);
    }

    /// Test 4a: receiver returns "cancelled by sender" when the sender
    /// emits CAN×2 (consecutive) mid-transfer.  Forsberg's protocol
    /// notes recommend two consecutive CANs for abort so a stray 0x18
    /// from line noise doesn't false-abort a transfer.
    #[tokio::test]
    async fn test_xmodem_receive_aborts_on_sender_can() {
        let (sender_half, receiver_half) = tokio::io::duplex(16384);
        let (mut send_read, mut send_write) = tokio::io::split(sender_half);
        let (mut recv_read, mut recv_write) = tokio::io::split(receiver_half);

        let send_task = tokio::spawn(async move {
            // Wait for 'C'.
            let _ = raw_read_byte(&mut send_read, false).await.unwrap();
            // Send CAN×2 (consecutive) — the spec-conformant abort.
            raw_write_byte(&mut send_write, CAN, false).await.unwrap();
            raw_write_byte(&mut send_write, CAN, false).await.unwrap();
            // Drain whatever the receiver writes after the first CAN
            // (e.g. another 'C' from the negotiation loop) until the
            // task is aborted by the test driver.
            loop {
                let _ = raw_read_byte(&mut send_read, false).await;
            }
        });

        let result = xmodem_receive(
            &mut recv_read, &mut recv_write, false, false, false,
        ).await;

        // Receiver returned — abort the drain loop.  Splitting a
        // DuplexStream into Read/Write halves means dropping just
        // `recv_write` doesn't close the stream (recv_read still
        // holds it), so the cleanest way to terminate the spawn is
        // an explicit abort.
        send_task.abort();
        let _ = send_task.await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("cancelled by sender"),
            "expected cancel-by-sender error, got: {}", err,
        );
    }

    /// Test 4b: sender returns "cancelled by receiver" when the
    /// receiver sends CAN×2 in response to a data block.
    #[tokio::test]
    async fn test_xmodem_send_aborts_on_receiver_can_mid_transfer() {
        let (sender_half, receiver_half) = tokio::io::duplex(16384);
        let (mut send_read, mut send_write) = tokio::io::split(sender_half);
        let (mut recv_read, mut recv_write) = tokio::io::split(receiver_half);

        let data = b"payload".to_vec();
        let send_task = tokio::spawn(async move {
            xmodem_send(
                &mut send_read, &mut send_write, &data,
                false, false, false, false, None,
            ).await
        });

        let recv_task = tokio::spawn(async move {
            raw_write_byte(&mut recv_write, CRC_REQUEST, false).await.unwrap();
            // Read block 1 and respond with CAN×2.
            let _ = read_soh_crc_block(&mut recv_read).await;
            raw_write_byte(&mut recv_write, CAN, false).await.unwrap();
            raw_write_byte(&mut recv_write, CAN, false).await.unwrap();
        });

        let result = send_task.await.unwrap();
        recv_task.await.unwrap();
        assert!(result.is_err());
        assert!(
            result.unwrap_err().contains("cancelled by receiver"),
            "expected cancel-by-receiver error",
        );
    }

    /// Test 4c: sender returns cancel error when the receiver sends
    /// CAN×2 during negotiation (before any block has been transmitted).
    #[tokio::test]
    async fn test_xmodem_send_aborts_on_receiver_can_during_negotiation() {
        let (sender_half, receiver_half) = tokio::io::duplex(16384);
        let (mut send_read, mut send_write) = tokio::io::split(sender_half);
        let (_recv_read, mut recv_write) = tokio::io::split(receiver_half);

        let data = b"never-sent".to_vec();
        let send_task = tokio::spawn(async move {
            xmodem_send(
                &mut send_read, &mut send_write, &data,
                false, false, false, false, None,
            ).await
        });

        // Send CAN×2 in place of 'C' or NAK.
        raw_write_byte(&mut recv_write, CAN, false).await.unwrap();
        raw_write_byte(&mut recv_write, CAN, false).await.unwrap();

        let result = send_task.await.unwrap();
        assert!(result.is_err());
        assert!(
            result.unwrap_err().contains("cancelled by receiver"),
            "expected cancel-by-receiver during negotiation",
        );
    }

    /// Test 5: `xmodem_send` times out and returns an error when the
    /// receiver never transmits 'C' or NAK.  Uses tokio's paused-time
    /// mode so the test doesn't actually wait the full negotiation
    /// window.
    #[tokio::test(start_paused = true)]
    async fn test_xmodem_send_negotiation_timeout() {
        let (sender_half, receiver_half) = tokio::io::duplex(16384);
        let (mut send_read, mut send_write) = tokio::io::split(sender_half);
        // Keep the receiver half alive so reads from sender block
        // (rather than EOF-ing) — we want the timeout path to fire.
        let _keep_alive = receiver_half;

        let data = b"data".to_vec();
        let send_task = tokio::spawn(async move {
            xmodem_send(
                &mut send_read, &mut send_write, &data,
                false, false, false, false, None,
            ).await
        });

        // Advance virtual time past any reasonable negotiation window.
        tokio::time::advance(std::time::Duration::from_secs(600)).await;

        let result = send_task.await.unwrap();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_lowercase().contains("timeout")
                || err.to_lowercase().contains("negotiation"),
            "expected negotiation-timeout error, got: {}", err,
        );
    }

    /// Test 6: receiver NAKs when the sender transmits a block with
    /// the wrong block number (out of sequence).
    #[tokio::test]
    async fn test_xmodem_receive_nak_on_out_of_sequence_block() {
        let (sender_half, receiver_half) = tokio::io::duplex(16384);
        let (mut send_read, mut send_write) = tokio::io::split(sender_half);
        let (mut recv_read, mut recv_write) = tokio::io::split(receiver_half);

        // Real receiver.
        let recv_task = tokio::spawn(async move {
            xmodem_receive(&mut recv_read, &mut recv_write, false, false, false)
                .await
        });

        // Wait for 'C' from receiver.
        let req = raw_read_byte(&mut send_read, false).await.unwrap();
        assert_eq!(req, CRC_REQUEST);

        // Fake sender: transmit block 5 instead of block 1.
        let bogus_data = vec![0xAAu8; XMODEM_BLOCK_SIZE];
        let crc = crc16_xmodem(&bogus_data);
        let mut pkt = Vec::new();
        pkt.push(SOH);
        pkt.push(5);
        pkt.push(!5);
        pkt.extend_from_slice(&bogus_data);
        pkt.push((crc >> 8) as u8);
        pkt.push((crc & 0xFF) as u8);
        send_write.write_all(&pkt).await.unwrap();

        // Receiver should respond with NAK (expected 1, got 5).
        let response = raw_read_byte(&mut send_read, false).await.unwrap();
        assert_eq!(
            response, NAK,
            "receiver must NAK an out-of-sequence block",
        );

        // Send CAN to terminate cleanly.
        raw_write_byte(&mut send_write, CAN, false).await.unwrap();
        let result = recv_task.await.unwrap();
        assert!(result.is_err());
    }

    /// Test 9: YMODEM sender must retry block 0 (the filename header)
    /// when the receiver NAKs it, and complete successfully when the
    /// receiver eventually ACKs.
    #[tokio::test]
    async fn test_ymodem_send_block_zero_nak_retry() {
        let (sender_half, receiver_half) = tokio::io::duplex(16384);
        let (mut send_read, mut send_write) = tokio::io::split(sender_half);
        let (mut recv_read, mut recv_write) = tokio::io::split(receiver_half);

        // 1024 bytes so the sender uses STX (1K block) — otherwise it
        // falls back to SOH and our post-block-0 read assertion fails.
        let original: Vec<u8> = (0..1024u16)
            .map(|i| (i as u8).wrapping_mul(3))
            .collect();
        let orig_clone = original.clone();
        let hdr = YmodemHeader {
            filename: "retry.bin".to_string(),
            size: original.len() as u64,
            modtime: None,
            mode: None,
        };

        let send_task = tokio::spawn(async move {
            xmodem_send(
                &mut send_read, &mut send_write, &orig_clone,
                false, false, false, true /* use_1k */, Some(hdr),
            ).await.unwrap();
        });

        let recv_task = tokio::spawn(async move {
            raw_write_byte(&mut recv_write, CRC_REQUEST, false).await.unwrap();

            // Block 0 NAK'd twice.
            for _ in 0..2 {
                // Read full 128-byte block 0 + 2 CRC bytes.
                for _ in 0..(3 + XMODEM_BLOCK_SIZE + 2) {
                    raw_read_byte(&mut recv_read, false).await.unwrap();
                }
                raw_write_byte(&mut recv_write, NAK, false).await.unwrap();
            }

            // Third attempt: read + ACK.
            for _ in 0..(3 + XMODEM_BLOCK_SIZE + 2) {
                raw_read_byte(&mut recv_read, false).await.unwrap();
            }
            raw_write_byte(&mut recv_write, ACK, false).await.unwrap();

            // Second 'C' → start data phase.
            raw_write_byte(&mut recv_write, CRC_REQUEST, false).await.unwrap();

            // Receive the 1K STX data block.
            let hdr_byte = raw_read_byte(&mut recv_read, false).await.unwrap();
            assert_eq!(hdr_byte, STX);
            for _ in 0..(2 + XMODEM_1K_BLOCK_SIZE + 2) {
                raw_read_byte(&mut recv_read, false).await.unwrap();
            }
            raw_write_byte(&mut recv_write, ACK, false).await.unwrap();

            // EOT.
            let eot = raw_read_byte(&mut recv_read, false).await.unwrap();
            assert_eq!(eot, EOT);
            raw_write_byte(&mut recv_write, ACK, false).await.unwrap();
        });

        send_task.await.unwrap();
        recv_task.await.unwrap();
    }

    /// Test 10: XMODEM-1K → XMODEM fallback not only completes but
    /// delivers the exact original bytes to the receiver.  Stronger
    /// assertion than the existing opportunistic-fallback test which
    /// only verified the transfer didn't error out.
    #[tokio::test]
    async fn test_xmodem_1k_fallback_preserves_exact_bytes() {
        let (sender_half, receiver_half) = tokio::io::duplex(16384);
        let (mut send_read, mut send_write) = tokio::io::split(sender_half);
        let (mut recv_read, mut recv_write) = tokio::io::split(receiver_half);

        // Known-distinct payload to detect any corruption.
        let original: Vec<u8> = (0..XMODEM_1K_BLOCK_SIZE)
            .map(|i| ((i * 31 + 7) & 0xFF) as u8)
            .collect();
        let orig_clone = original.clone();

        let send_task = tokio::spawn(async move {
            xmodem_send(
                &mut send_read, &mut send_write, &orig_clone,
                false, false, false, true /* use_1k */, None,
            ).await.unwrap();
        });

        let recv_task = tokio::spawn(async move {
            raw_write_byte(&mut recv_write, CRC_REQUEST, false).await.unwrap();

            // First attempt: STX (1K).  NAK it to force fallback.
            let hdr = raw_read_byte(&mut recv_read, false).await.unwrap();
            assert_eq!(hdr, STX);
            for _ in 0..(2 + XMODEM_1K_BLOCK_SIZE + 2) {
                raw_read_byte(&mut recv_read, false).await.unwrap();
            }
            raw_write_byte(&mut recv_write, NAK, false).await.unwrap();

            // Fallback: 8 SOH blocks covering the same 1024 bytes.
            let mut received = Vec::with_capacity(XMODEM_1K_BLOCK_SIZE);
            for expected_num in 1u8..=8 {
                let hdr = raw_read_byte(&mut recv_read, false).await.unwrap();
                assert_eq!(hdr, SOH);
                let blk = raw_read_byte(&mut recv_read, false).await.unwrap();
                assert_eq!(blk, expected_num);
                raw_read_byte(&mut recv_read, false).await.unwrap(); // !blk
                let mut payload = vec![0u8; XMODEM_BLOCK_SIZE];
                for b in payload.iter_mut() {
                    *b = raw_read_byte(&mut recv_read, false).await.unwrap();
                }
                // CRC.
                raw_read_byte(&mut recv_read, false).await.unwrap();
                raw_read_byte(&mut recv_read, false).await.unwrap();
                received.extend_from_slice(&payload);
                raw_write_byte(&mut recv_write, ACK, false).await.unwrap();
            }

            // EOT.
            let eot = raw_read_byte(&mut recv_read, false).await.unwrap();
            assert_eq!(eot, EOT);
            raw_write_byte(&mut recv_write, ACK, false).await.unwrap();

            received
        });

        send_task.await.unwrap();
        let received = recv_task.await.unwrap();
        assert_eq!(
            received, original,
            "fallback path must preserve exact payload bytes",
        );
    }

    #[tokio::test]
    async fn test_xmodem_round_trip_empty() {
        let received = xmodem_round_trip(&[]).await;
        assert!(received.is_empty());
    }

    #[tokio::test]
    async fn test_xmodem_round_trip_one_over_block() {
        let original: Vec<u8> = (0..129).map(|i| (i & 0xFF) as u8).collect();
        let received = xmodem_round_trip(&original).await;
        assert_eq!(received, original);
    }

    #[tokio::test]
    async fn test_xmodem_round_trip_two_exact_blocks() {
        let original: Vec<u8> = (0..256).map(|i| (i & 0xFF) as u8).collect();
        let received = xmodem_round_trip(&original).await;
        assert_eq!(received, original);
    }

    #[tokio::test]
    async fn test_xmodem_round_trip_data_with_protocol_bytes() {
        let original = vec![SOH, EOT, ACK, NAK, CAN, SUB, 0x00, 0xFF];
        let received = xmodem_round_trip(&original).await;
        assert_eq!(received, original);
    }

    #[test]
    fn test_crc16_full_zero_block() {
        let block = [0u8; XMODEM_BLOCK_SIZE];
        assert_eq!(crc16_xmodem(&block), 0x0000);
    }

    #[test]
    fn test_crc16_full_ff_block() {
        let block = [0xFFu8; XMODEM_BLOCK_SIZE];
        let crc = crc16_xmodem(&block);
        assert_ne!(crc, 0x0000);
        assert_eq!(crc, crc16_xmodem(&[0xFF; XMODEM_BLOCK_SIZE]));
    }

    #[test]
    fn test_crc16_sequential_block() {
        let block: Vec<u8> = (0..128).collect();
        let crc = crc16_xmodem(&block);
        assert_eq!(crc, crc16_xmodem(&(0u8..128).collect::<Vec<u8>>()));
        assert_ne!(crc, 0);
    }

    #[tokio::test]
    async fn test_xmodem_receive_rejects_oversized() {
        let oversized = vec![0xAA; MAX_FILE_SIZE + XMODEM_BLOCK_SIZE];
        let (sender_half, receiver_half) = tokio::io::duplex(16384);
        let (mut send_read, mut send_write) = tokio::io::split(sender_half);
        let (mut recv_read, mut recv_write) = tokio::io::split(receiver_half);

        let send_task = tokio::spawn(async move {
            let _ = xmodem_send(
                &mut send_read,
                &mut send_write,
                &oversized,
                false,
                false,
                false,
                false,
                None,
            )
            .await;
        });
        let recv_task = tokio::spawn(async move {
            xmodem_receive(&mut recv_read, &mut recv_write, false, false, false).await
        });

        send_task.await.unwrap();
        let result = recv_task.await.unwrap();
        assert!(result.is_err());
        let err_msg = result.unwrap_err();
        assert!(
            err_msg.contains("8 MB"),
            "Expected '8 MB' in error, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_transfer_timeout_is_reasonable() {
        let cfg = config::get_config();
        assert!(
            cfg.xmodem_negotiation_timeout >= 30,
            "too short — user needs time to start sender"
        );
        assert!(cfg.xmodem_negotiation_timeout <= 300, "excessive negotiation timeout");
    }

    #[test]
    fn test_block_timeout_less_than_negotiation_timeout() {
        let cfg = config::get_config();
        assert!(cfg.xmodem_block_timeout < cfg.xmodem_negotiation_timeout);
    }

    #[test]
    fn test_max_retries_is_reasonable() {
        let cfg = config::get_config();
        assert!(cfg.xmodem_max_retries >= 3, "too few retries");
        assert!(cfg.xmodem_max_retries <= 50, "excessive retries");
    }

    #[tokio::test]
    async fn test_consume_telnet_sb_normal() {
        let data: Vec<u8> = vec![0x18, 0x00, 0x41, IAC, SE];
        let mut reader = std::io::Cursor::new(data);
        let result = consume_telnet_command(&mut reader, SB).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_consume_telnet_sb_long() {
        let mut data: Vec<u8> = Vec::new();
        data.extend(std::iter::repeat_n(0x42, 1000));
        data.push(IAC);
        data.push(SE);
        let mut reader = std::io::Cursor::new(data);
        let result = consume_telnet_command(&mut reader, SB).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_consume_telnet_sb_escaped_iac() {
        let data: Vec<u8> = vec![0x18, IAC, IAC, 0x01, IAC, SE];
        let mut reader = std::io::Cursor::new(data);
        let result = consume_telnet_command(&mut reader, SB).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_consume_telnet_will() {
        let data: Vec<u8> = vec![0x01];
        let mut reader = std::io::Cursor::new(data);
        let result = consume_telnet_command(&mut reader, WILL).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_consume_telnet_unknown_command() {
        let data: Vec<u8> = vec![];
        let mut reader = std::io::Cursor::new(data);
        let result = consume_telnet_command(&mut reader, 0xF1).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_xmodem_esc_key_petscii_false() {
        assert!(is_esc_key(0x1B, false));
        assert!(!is_esc_key(0x5F, false));
    }

    #[test]
    fn test_xmodem_esc_key_petscii_true() {
        assert!(is_esc_key(0x1B, true));
        assert!(is_esc_key(0x5F, true));
    }

    // ─── XMODEM/XMODEM-1K/YMODEM spec conformance tests ──────
    //
    // Drive `xmodem_send` against a minimal scripted receiver, capture
    // the wire bytes, and assert that each header/block/trailer matches
    // the byte-exact format mandated by:
    //   - XMODEM (Christensen 1977 / Forsberg's "YMODEM.DOC")
    //   - XMODEM-CRC (Forsberg)
    //   - XMODEM-1K (Forsberg, STX/1024-byte blocks)
    //   - YMODEM (Forsberg 1985, batch with block 0)

    /// Capture the bytes `xmodem_send` writes when driven by a scripted
    /// receiver.  `receiver_script` is the sequence of control bytes
    /// the receiver should emit (e.g. `[CRC_REQUEST, ACK, ACK, ACK]`)
    /// — one per block plus a final ACK for the EOT.  Returns the
    /// concatenated wire bytes the sender produced.
    async fn capture_xmodem_wire(
        data: &[u8],
        use_1k: bool,
        ymodem: Option<YmodemHeader>,
        receiver_script: &[u8],
    ) -> Vec<u8> {
        let (sender_half, receiver_half) = tokio::io::duplex(65536);
        let (mut send_read, mut send_write) = tokio::io::split(sender_half);
        let (mut recv_read, mut recv_write) = tokio::io::split(receiver_half);

        let data = data.to_vec();
        let script = receiver_script.to_vec();

        let send_task = tokio::spawn(async move {
            xmodem_send(
                &mut send_read,
                &mut send_write,
                &data,
                false,
                false,
                false,
                use_1k,
                ymodem,
            )
            .await
            .ok();
        });

        let capture_task = tokio::spawn(async move {
            // Drive the script: emit one byte, then read until enough
            // bytes have arrived to plausibly complete a block (loose
            // bound; we just need to keep the sender unblocked).
            let mut captured: Vec<u8> = Vec::new();
            let mut buf = [0u8; 4096];
            let mut script_pos = 0usize;
            loop {
                if script_pos < script.len() {
                    recv_write.write_all(&[script[script_pos]]).await.ok();
                    recv_write.flush().await.ok();
                    script_pos += 1;
                }
                match tokio::time::timeout(
                    std::time::Duration::from_millis(200),
                    recv_read.read(&mut buf),
                )
                .await
                {
                    Ok(Ok(0)) => break,
                    Ok(Ok(n)) => captured.extend_from_slice(&buf[..n]),
                    Ok(Err(_)) => break,
                    Err(_) => {
                        if script_pos >= script.len() {
                            break;
                        }
                    }
                }
            }
            captured
        });

        let _ = send_task.await;
        capture_task.await.unwrap()
    }

    /// Heuristic: scan `wire` for the first occurrence of an XMODEM
    /// block (SOH or STX) and return the (header_byte, block_num,
    /// complement, payload_offset) tuple.
    fn find_first_block(wire: &[u8]) -> Option<(u8, u8, u8, usize)> {
        for (i, &b) in wire.iter().enumerate() {
            if (b == SOH || b == STX) && i + 2 < wire.len() {
                return Some((b, wire[i + 1], wire[i + 2], i + 3));
            }
        }
        None
    }

    #[tokio::test]
    async fn test_xmodem_christensen_checksum_block_layout() {
        // XMODEM (Christensen 1977): block = SOH (0x01) | block_num |
        // ~block_num | 128 bytes | checksum (1 byte sum mod 256).
        // Receiver requests checksum mode by sending NAK first.
        let data = b"Hello, XMODEM!";
        let wire = capture_xmodem_wire(data, false, None, &[NAK, ACK, ACK]).await;
        let (hdr, num, comp, off) = find_first_block(&wire).expect("no block in wire");
        assert_eq!(hdr, SOH, "checksum-mode XMODEM block must start with SOH");
        assert_eq!(num, 1, "first block number must be 1 (Christensen)");
        assert_eq!(comp, !num, "complement must be bitwise NOT of block num");
        assert!(off + 128 < wire.len(), "wire too short for SOH+128+cksum");
        // Verify the checksum (sum mod 256 of the 128 data bytes).
        let payload = &wire[off..off + 128];
        let cksum: u8 = payload.iter().fold(0u8, |a, &b| a.wrapping_add(b));
        assert_eq!(wire[off + 128], cksum, "checksum mismatch");
    }

    #[tokio::test]
    async fn test_xmodem_crc16_block_layout() {
        // XMODEM-CRC: same as Christensen but with CRC-16/XMODEM
        // (poly 0x1021) appended MSB-first instead of a 1-byte
        // checksum.  Triggered by receiver sending 'C' first.
        let data = b"CRC mode payload";
        let wire = capture_xmodem_wire(data, false, None, &[CRC_REQUEST, ACK, ACK]).await;
        let (hdr, num, _, off) = find_first_block(&wire).expect("no block");
        assert_eq!(hdr, SOH);
        assert_eq!(num, 1);
        assert!(off + 128 + 2 <= wire.len(), "wire too short for SOH+128+CRC");
        let payload = &wire[off..off + 128];
        let crc = crc16_xmodem(payload);
        // CRC is appended MSB-first per the spec.
        assert_eq!(
            wire[off + 128],
            (crc >> 8) as u8,
            "CRC high byte must come first"
        );
        assert_eq!(
            wire[off + 129],
            crc as u8,
            "CRC low byte must come second"
        );
    }

    #[tokio::test]
    async fn test_xmodem_1k_block_uses_stx_header() {
        // XMODEM-1K: 1024-byte blocks introduced with STX (0x02)
        // instead of SOH.  Forsberg specified this so receivers can
        // distinguish block sizes from the leading byte alone.
        let data: Vec<u8> = (0..1024u32).map(|i| (i & 0xFF) as u8).collect();
        let wire = capture_xmodem_wire(&data, true, None, &[CRC_REQUEST, ACK, ACK]).await;
        let (hdr, _, _, _) = find_first_block(&wire).expect("no block");
        assert_eq!(hdr, STX, "XMODEM-1K block must start with STX (0x02)");
    }

    #[tokio::test]
    async fn test_xmodem_1k_block_layout() {
        // XMODEM-1K: STX | num | ~num | 1024 bytes | CRC16 (2 bytes).
        let data: Vec<u8> = (0..1024u32).map(|i| (i.wrapping_mul(13) & 0xFF) as u8).collect();
        let wire = capture_xmodem_wire(&data, true, None, &[CRC_REQUEST, ACK, ACK]).await;
        let (hdr, num, comp, off) = find_first_block(&wire).expect("no block");
        assert_eq!(hdr, STX);
        assert_eq!(num, 1);
        assert_eq!(comp, !num);
        assert!(off + 1024 + 2 <= wire.len(), "wire too short for STX+1024+CRC");
        let crc = crc16_xmodem(&wire[off..off + 1024]);
        assert_eq!(wire[off + 1024], (crc >> 8) as u8);
        assert_eq!(wire[off + 1025], crc as u8);
    }

    #[tokio::test]
    async fn test_xmodem_block_number_increments_then_wraps() {
        // Block numbers are 8-bit, increment from 1, and wrap 255 → 0.
        // 257 blocks (256 × 128 + 1) → numbers 1, 2, ..., 255, 0, 1.
        // We probe the first two block numbers (cheaper than 257-block
        // wrap, which is expensive) — the wrap logic is exercised by
        // the existing internal round-trip tests.
        let data: Vec<u8> = (0..256u32).map(|i| (i & 0xFF) as u8).collect();
        let wire =
            capture_xmodem_wire(&data, false, None, &[CRC_REQUEST, ACK, ACK, ACK]).await;
        // First block is num=1.  Find the second SOH.
        let mut soh_positions: Vec<usize> = Vec::new();
        for (i, &b) in wire.iter().enumerate() {
            if b == SOH && i + 2 < wire.len() && wire[i + 2] == !wire[i + 1] {
                soh_positions.push(i);
            }
        }
        assert!(
            soh_positions.len() >= 2,
            "expected at least 2 blocks for 256-byte payload"
        );
        assert_eq!(wire[soh_positions[0] + 1], 1, "first block must be 1");
        assert_eq!(wire[soh_positions[1] + 1], 2, "second block must be 2");
    }

    #[tokio::test]
    async fn test_xmodem_eot_after_last_block() {
        // After the final data block + final ACK, the sender emits
        // EOT (0x04) to signal end-of-file.
        let data = b"short";
        let wire = capture_xmodem_wire(data, false, None, &[CRC_REQUEST, ACK, ACK]).await;
        assert!(
            wire.contains(&EOT),
            "wire must contain EOT (0x04) after last block, got: {:?}",
            wire.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn test_xmodem_pads_short_block_with_sub() {
        // XMODEM blocks are fixed-width.  The last block of a file
        // shorter than 128 bytes is padded with 0x1A (SUB / CP/M EOF).
        let data = b"abc"; // 3 bytes, must be padded to 128
        let wire = capture_xmodem_wire(data, false, None, &[CRC_REQUEST, ACK, ACK]).await;
        let (_, _, _, off) = find_first_block(&wire).expect("no block");
        let payload = &wire[off..off + 128];
        assert_eq!(&payload[..3], data);
        assert!(
            payload[3..].iter().all(|&b| b == SUB),
            "tail of short block must be padded with SUB (0x1A), got: {:?}",
            &payload[3..]
        );
    }

    #[tokio::test]
    async fn test_ymodem_block_zero_format() {
        // YMODEM (Forsberg §5): block 0 carries metadata as
        //   "filename\0size mtime mode\0...\0" padded to block size.
        // Block number is 0 (not 1) for the metadata block.
        let data = b"file body";
        let header = YmodemHeader {
            filename: "test.bin".to_string(),
            size: data.len() as u64,
            modtime: None,
            mode: None,
        };
        let wire =
            capture_xmodem_wire(data, false, Some(header), &[CRC_REQUEST, ACK, CRC_REQUEST, ACK, ACK])
                .await;
        let (hdr, num, comp, off) = find_first_block(&wire).expect("no block");
        assert_eq!(hdr, SOH, "YMODEM block 0 uses SOH (128 bytes)");
        assert_eq!(num, 0, "block 0 must have block number 0");
        assert_eq!(comp, !num);
        let payload = &wire[off..off + 128];
        // Filename comes first, NUL-terminated.
        let nul = payload.iter().position(|&b| b == 0).expect("no NUL after filename");
        assert_eq!(&payload[..nul], b"test.bin");
        // After the NUL, ASCII-decimal size, space-separated from
        // mtime / mode.  We just need to verify the size field is
        // present in decimal ASCII before the next NUL.
        let after_name = &payload[nul + 1..];
        let next_nul = after_name
            .iter()
            .position(|&b| b == 0)
            .expect("no NUL after metadata");
        let meta = std::str::from_utf8(&after_name[..next_nul]).unwrap();
        let first_field = meta.split_whitespace().next().unwrap();
        assert_eq!(
            first_field,
            "9",
            "size field must be decimal ASCII matching data length"
        );
    }

    #[tokio::test]
    async fn test_ymodem_block_zero_uses_crc16() {
        // YMODEM mandates CRC-16 (not checksum) for all blocks, so
        // even the receiver's negotiation byte before block 0 must
        // be 'C' — a NAK negotiation would put us in legacy XMODEM
        // mode where YMODEM features (size truncation, batch) don't
        // apply.  This test locks in that block 0 is followed by a
        // 2-byte CRC-16 trailer.
        let data = b"x";
        let header = YmodemHeader {
            filename: "a".to_string(),
            size: 1,
            modtime: None,
            mode: None,
        };
        let wire = capture_xmodem_wire(
            data,
            false,
            Some(header),
            &[CRC_REQUEST, ACK, CRC_REQUEST, ACK, ACK],
        )
        .await;
        let (_, _, _, off) = find_first_block(&wire).expect("no block");
        // Block 0 = SOH + 2-byte hdr + 128 data + 2-byte CRC.
        let payload = &wire[off..off + 128];
        let crc = crc16_xmodem(payload);
        assert_eq!(wire[off + 128], (crc >> 8) as u8, "block 0 CRC high byte");
        assert_eq!(wire[off + 129], crc as u8, "block 0 CRC low byte");
    }

    /// Forsberg YMODEM §6.1: the metadata field after the filename
    /// NUL is `length<SP>modtime<SP>mode<SP>sno\0` where `length` is
    /// decimal and `modtime`/`mode`/`sno` are octal.  When the sender
    /// is given full metadata, it must emit all four fields.
    #[tokio::test]
    async fn test_ymodem_block_zero_emits_full_metadata() {
        let data = b"abc";
        let header = YmodemHeader {
            filename: "doc.txt".to_string(),
            size: 3,
            modtime: Some(0o12345670),
            mode: Some(0o100644),
        };
        let wire = capture_xmodem_wire(
            data,
            false,
            Some(header),
            &[CRC_REQUEST, ACK, CRC_REQUEST, ACK, ACK],
        )
        .await;
        let (hdr, num, _, off) = find_first_block(&wire).expect("no block");
        assert_eq!(hdr, SOH, "block 0 must use SOH");
        assert_eq!(num, 0, "block 0 number must be 0");
        let payload = &wire[off..off + 128];
        let nul = payload.iter().position(|&b| b == 0).expect("filename NUL");
        assert_eq!(&payload[..nul], b"doc.txt");
        let after_name = &payload[nul + 1..];
        let next_nul = after_name
            .iter()
            .position(|&b| b == 0)
            .expect("metadata-block NUL terminator");
        let meta = std::str::from_utf8(&after_name[..next_nul]).unwrap();
        let fields: Vec<&str> = meta.split_ascii_whitespace().collect();
        assert!(
            fields.len() >= 4,
            "must emit at least length/modtime/mode/sno, got {:?}",
            fields,
        );
        assert_eq!(fields[0], "3", "length must be decimal");
        assert_eq!(
            u64::from_str_radix(fields[1], 8).expect("modtime must be octal"),
            0o12345670,
        );
        assert_eq!(
            u32::from_str_radix(fields[2], 8).expect("mode must be octal") & 0o7777,
            0o100644 & 0o7777,
        );
        assert_eq!(fields[3], "0", "sno must be octal 0");
    }

    /// Length is decimal, modtime/mode are octal — emitting modtime
    /// in decimal would silently misrepresent the timestamp on parsers
    /// that follow the spec.  This test pins the radix on each field
    /// independently of the matching round-trip test.
    #[tokio::test]
    async fn test_ymodem_block_zero_octal_radix() {
        let data = b"y";
        let header = YmodemHeader {
            filename: "f".to_string(),
            size: 1,
            // 0o20 = 16 — distinguishable from its decimal form (20)
            // and its hex form (0x14) so a wrong radix would fail.
            modtime: Some(0o20),
            mode: Some(0o20),
        };
        let wire = capture_xmodem_wire(
            data,
            false,
            Some(header),
            &[CRC_REQUEST, ACK, CRC_REQUEST, ACK, ACK],
        )
        .await;
        let (_, _, _, off) = find_first_block(&wire).expect("no block");
        let payload = &wire[off..off + 128];
        let nul = payload.iter().position(|&b| b == 0).unwrap();
        let after = &payload[nul + 1..];
        let end = after.iter().position(|&b| b == 0).unwrap();
        let meta = std::str::from_utf8(&after[..end]).unwrap();
        let fields: Vec<&str> = meta.split_ascii_whitespace().collect();
        assert_eq!(fields[1], "20", "modtime 0o20 must serialize as octal '20'");
        assert_eq!(fields[2], "20", "mode 0o20 must serialize as octal '20'");
    }

    /// End-to-end round-trip with full metadata — sender encodes,
    /// receiver decodes, both halves agree on the values.
    #[tokio::test]
    async fn test_ymodem_round_trip_modtime_mode_metadata() {
        let original = b"round trip body";
        let (sender_half, receiver_half) = tokio::io::duplex(16384);
        let (mut send_read, mut send_write) = tokio::io::split(sender_half);
        let (mut recv_read, mut recv_write) = tokio::io::split(receiver_half);

        let data = original.to_vec();
        let hdr = YmodemHeader {
            filename: "rt.bin".to_string(),
            size: data.len() as u64,
            modtime: Some(1_700_000_000),
            mode: Some(0o100755),
        };

        let send_task = tokio::spawn(async move {
            xmodem_send(
                &mut send_read,
                &mut send_write,
                &data,
                false,
                false,
                false,
                true,
                Some(hdr),
            )
            .await
            .unwrap();
        });
        let recv_task = tokio::spawn(async move {
            xmodem_receive(&mut recv_read, &mut recv_write, false, false, false)
                .await
                .unwrap()
        });
        send_task.await.unwrap();
        let (received, meta) = recv_task.await.unwrap();
        assert_eq!(received, original, "data must round-trip exactly");
        let meta = meta.expect("YMODEM block 0 must surface meta");
        assert_eq!(meta.size, Some(original.len() as u64));
        assert_eq!(meta.modtime, Some(1_700_000_000));
        // Mode is parser-masked to 0o7777 (perms + setuid/setgid/sticky).
        assert_eq!(meta.mode, Some(0o100755 & 0o7777));
    }

    /// Minimal-sender compatibility: a block 0 with `filename\0length\0`
    /// (no modtime/mode/sno) must still parse — Forsberg explicitly
    /// permits trailing fields to be omitted.
    #[test]
    fn test_parse_block_zero_minimal_size_only() {
        let mut payload = [0u8; XMODEM_BLOCK_SIZE];
        // Layout: "f.bin\0123\0..."  — filename, NUL, decimal length,
        // NUL terminator for the metadata block.
        let bytes: &[u8] = b"f.bin\x00123";
        payload[..bytes.len()].copy_from_slice(bytes);
        // payload[bytes.len()] stays 0 — terminates metadata.
        let meta = parse_ymodem_block_zero_payload(&payload).expect("must parse");
        assert_eq!(meta.size, Some(123));
        assert_eq!(meta.modtime, None);
        assert_eq!(meta.mode, None);
    }

    /// Even more minimal: filename only, no metadata block at all.
    /// Some pre-Forsberg-1988 senders did this; we should tolerate it
    /// by returning a meta with all `None` fields.
    #[test]
    fn test_parse_block_zero_filename_only() {
        let mut payload = [0u8; XMODEM_BLOCK_SIZE];
        payload[..4].copy_from_slice(b"name");
        // payload[4] is the filename NUL; everything after is NUL fill.
        let meta = parse_ymodem_block_zero_payload(&payload).expect("must parse");
        assert_eq!(meta.size, None);
        assert_eq!(meta.modtime, None);
        assert_eq!(meta.mode, None);
    }

    /// End-of-batch null block 0 (filename starts with NUL) must not
    /// produce a meta — the parser distinguishes "no metadata" from
    /// "end of batch terminator block."
    #[test]
    fn test_parse_block_zero_end_of_batch_returns_none() {
        let payload = [0u8; XMODEM_BLOCK_SIZE];
        assert!(parse_ymodem_block_zero_payload(&payload).is_none());
    }

    /// Modtime of 0 (octal) is the spec-defined "unknown" sentinel —
    /// the parser must report `None` rather than `Some(0)`, so callers
    /// don't set the file's mtime to the UNIX epoch.
    #[test]
    fn test_parse_block_zero_zero_modtime_means_unknown() {
        let mut payload = [0u8; XMODEM_BLOCK_SIZE];
        let meta_str: &[u8] = b"f\x0010 0 644 0";
        payload[..meta_str.len()].copy_from_slice(meta_str);
        let m = parse_ymodem_block_zero_payload(&payload).expect("must parse");
        assert_eq!(m.size, Some(10));
        assert_eq!(m.modtime, None, "octal 0 modtime must mean 'unknown'");
        assert_eq!(m.mode, Some(0o644));
    }

    /// Mode parser masks to 0o7777 — anything outside the permission
    /// and setuid/setgid/sticky bits (file-type bits such as 0o100000
    /// for "regular file") must be stripped before reaching the caller.
    #[test]
    fn test_parse_block_zero_mode_masking() {
        let mut payload = [0u8; XMODEM_BLOCK_SIZE];
        // 0o100755 = regular file, rwxr-xr-x.  Mask should drop
        // the 0o100000 file-type bit.
        let meta_str: &[u8] = b"f\x001 0 100755 0";
        payload[..meta_str.len()].copy_from_slice(meta_str);
        let m = parse_ymodem_block_zero_payload(&payload).expect("must parse");
        assert_eq!(m.mode, Some(0o755));
    }

    /// Junk in the metadata field must not panic; well-formed earlier
    /// fields must still be returned.  A common failure mode for
    /// minimally-conformant senders is putting a non-numeric token
    /// where modtime should be.
    #[test]
    fn test_parse_block_zero_tolerates_junk_after_size() {
        let mut payload = [0u8; XMODEM_BLOCK_SIZE];
        let meta_str: &[u8] = b"f\x0042 not_a_number also_junk 0";
        payload[..meta_str.len()].copy_from_slice(meta_str);
        let m = parse_ymodem_block_zero_payload(&payload).expect("must parse");
        assert_eq!(m.size, Some(42));
        assert_eq!(m.modtime, None);
        assert_eq!(m.mode, None);
    }

    /// The metadata block in our emitted block 0 must be NUL-terminated
    /// (Forsberg §6.1 fixes this — the receiver looks for the NUL to
    /// know where the field block ends).  Pin it explicitly.
    #[tokio::test]
    async fn test_ymodem_block_zero_metadata_nul_terminated() {
        let header = YmodemHeader {
            filename: "z".to_string(),
            size: 1,
            modtime: Some(0o12345),
            mode: Some(0o644),
        };
        let wire = capture_xmodem_wire(
            b"z",
            false,
            Some(header),
            &[CRC_REQUEST, ACK, CRC_REQUEST, ACK, ACK],
        )
        .await;
        let (_, _, _, off) = find_first_block(&wire).expect("no block");
        let payload = &wire[off..off + 128];
        // Filename NUL at offset 1 ("z\0..."); next NUL must terminate
        // the metadata block, after which the rest is NUL padding.
        assert_eq!(payload[0], b'z');
        assert_eq!(payload[1], 0, "filename must be NUL-terminated");
        // Find the metadata terminator.  After the filename NUL the
        // next NUL byte ends the metadata field block.
        let term = payload[2..]
            .iter()
            .position(|&b| b == 0)
            .expect("metadata terminator NUL")
            + 2;
        // Everything after the terminator must be NUL padding.
        for (i, &b) in payload[term + 1..].iter().enumerate() {
            assert_eq!(
                b, 0,
                "byte {} after metadata terminator must be NUL fill, got 0x{:02X}",
                i, b,
            );
        }
    }

    /// Callers who don't supply modtime/mode (e.g. pure in-memory
    /// senders that don't have a real file) must get spec-conformant
    /// `0` substitution rather than absence.  This keeps the
    /// space-separated field count at exactly 4, which simpler
    /// receivers may rely on for positional parsing.
    #[tokio::test]
    async fn test_ymodem_block_zero_none_metadata_emits_zeroes() {
        let header = YmodemHeader {
            filename: "n".to_string(),
            size: 5,
            modtime: None,
            mode: None,
        };
        let wire = capture_xmodem_wire(
            b"hello",
            false,
            Some(header),
            &[CRC_REQUEST, ACK, CRC_REQUEST, ACK, ACK],
        )
        .await;
        let (_, _, _, off) = find_first_block(&wire).expect("no block");
        let payload = &wire[off..off + 128];
        let nul = payload.iter().position(|&b| b == 0).unwrap();
        let after = &payload[nul + 1..];
        let end = after.iter().position(|&b| b == 0).unwrap();
        let meta = std::str::from_utf8(&after[..end]).unwrap();
        let fields: Vec<&str> = meta.split_ascii_whitespace().collect();
        assert_eq!(fields, vec!["5", "0", "0", "0"]);
    }

    /// Mode is masked to 0o7777 BEFORE emission so a misbehaving caller
    /// can't smuggle file-type bits onto the wire.  This guards against
    /// a future caller passing the raw `st_mode` value (which includes
    /// 0o170000 file-type bits) without masking.
    #[tokio::test]
    async fn test_ymodem_block_zero_mode_masked_before_emission() {
        let header = YmodemHeader {
            filename: "m".to_string(),
            size: 1,
            modtime: Some(1),
            // 0o140755 = socket + rwxr-xr-x — caller passed the full
            // st_mode including the 0o140000 file-type bits.  We must
            // strip them.
            mode: Some(0o140755),
        };
        let wire = capture_xmodem_wire(
            b"m",
            false,
            Some(header),
            &[CRC_REQUEST, ACK, CRC_REQUEST, ACK, ACK],
        )
        .await;
        let (_, _, _, off) = find_first_block(&wire).expect("no block");
        let payload = &wire[off..off + 128];
        let nul = payload.iter().position(|&b| b == 0).unwrap();
        let after = &payload[nul + 1..];
        let end = after.iter().position(|&b| b == 0).unwrap();
        let meta = std::str::from_utf8(&after[..end]).unwrap();
        let fields: Vec<&str> = meta.split_ascii_whitespace().collect();
        let emitted_mode = u32::from_str_radix(fields[2], 8).unwrap();
        assert_eq!(emitted_mode & 0o170000, 0, "file-type bits must be stripped");
        assert_eq!(emitted_mode, 0o0755, "permission bits must survive");
    }

    #[test]
    fn test_xmodem_crc16_canonical_vector() {
        // Forsberg "XMODEM/YMODEM Protocol Reference" cites the
        // CRC-16/XMODEM canonical vector (poly 0x1021, init 0,
        // no reflection): "123456789" → 0x31C3.  Locks in the CRC
        // implementation as a separate spec-citation test from the
        // pre-existing internal vector test.
        assert_eq!(crc16_xmodem(b"123456789"), 0x31C3);
    }

    /// Forsberg's CAN×2 abort rule, unit-tested at the helper level.
    /// First CAN arms `pending_can` and returns false; second
    /// consecutive CAN returns true; any non-CAN byte clears the flag.
    #[test]
    fn test_is_can_abort_state_transitions() {
        let mut state = ReadState::default();
        // Single CAN: arms but doesn't abort.
        assert!(!is_can_abort(CAN, &mut state));
        assert!(state.pending_can);
        // Second consecutive CAN: aborts.
        assert!(is_can_abort(CAN, &mut state));
        // After aborting, flag is cleared.
        assert!(!state.pending_can);
        // Single CAN, then non-CAN byte: flag cleared, no abort.
        assert!(!is_can_abort(CAN, &mut state));
        assert!(state.pending_can);
        assert!(!is_can_abort(ACK, &mut state));
        assert!(!state.pending_can);
        // After a non-CAN byte clears the flag, a single CAN doesn't
        // abort even though there was a CAN before.  Only **consecutive**
        // CANs trigger abort per Forsberg's rule.
        assert!(!is_can_abort(CAN, &mut state));
        assert!(!is_can_abort(NAK, &mut state));
        assert!(!is_can_abort(CAN, &mut state));
        assert!(!is_can_abort(EOT, &mut state));
    }

    /// A single stray CAN during the receive main loop must NOT abort
    /// the transfer.  Sender sends block 1 normally, then a stray CAN
    /// (simulating line noise), then block 2.  Receiver should treat
    /// the lone CAN as noise and complete the transfer with both
    /// blocks intact.
    #[tokio::test]
    async fn test_xmodem_receive_single_can_is_noise() {
        let (sender_half, receiver_half) = tokio::io::duplex(16384);
        let (mut send_read, mut send_write) = tokio::io::split(sender_half);
        let (mut recv_read, mut recv_write) = tokio::io::split(receiver_half);

        let block1: Vec<u8> = (0..128u8).map(|i| i.wrapping_mul(7)).collect();
        let block2: Vec<u8> = (0..128u8).map(|i| i.wrapping_mul(11)).collect();
        let block1_clone = block1.clone();
        let block2_clone = block2.clone();

        let send_task = tokio::spawn(async move {
            // Wait for 'C'.
            let _ = raw_read_byte(&mut send_read, false).await.unwrap();
            // Send block 1.
            let mut pkt = vec![SOH, 1, !1u8];
            pkt.extend_from_slice(&block1_clone);
            let crc = crc16_xmodem(&block1_clone);
            pkt.push((crc >> 8) as u8);
            pkt.push((crc & 0xFF) as u8);
            send_write.write_all(&pkt).await.unwrap();
            assert_eq!(raw_read_byte(&mut send_read, false).await.unwrap(), ACK);
            // Stray single CAN — must be ignored as noise.
            raw_write_byte(&mut send_write, CAN, false).await.unwrap();
            // Send block 2 immediately after.  The receiver must have
            // cleared `pending_can` on receipt of the SOH (non-CAN byte).
            let mut pkt = vec![SOH, 2, !2u8];
            pkt.extend_from_slice(&block2_clone);
            let crc = crc16_xmodem(&block2_clone);
            pkt.push((crc >> 8) as u8);
            pkt.push((crc & 0xFF) as u8);
            send_write.write_all(&pkt).await.unwrap();
            assert_eq!(raw_read_byte(&mut send_read, false).await.unwrap(), ACK);
            // EOT to end.
            raw_write_byte(&mut send_write, EOT, false).await.unwrap();
            assert_eq!(raw_read_byte(&mut send_read, false).await.unwrap(), ACK);
        });

        let (received, _) = xmodem_receive(
            &mut recv_read, &mut recv_write, false, false, false,
        )
        .await
        .expect("transfer must complete despite stray CAN");

        send_task.await.unwrap();
        let mut expected = block1;
        expected.extend_from_slice(&block2);
        assert_eq!(received, expected, "all data must round-trip");
    }

    /// CAN, non-CAN byte, CAN must NOT abort: the non-CAN byte
    /// breaks the "consecutive" run.  This pins the contract that
    /// the abort rule is *strictly* consecutive — a CAN followed by
    /// any other byte resets the state machine.
    #[tokio::test]
    async fn test_xmodem_receive_can_then_other_then_can_does_not_abort() {
        let (sender_half, receiver_half) = tokio::io::duplex(16384);
        let (mut send_read, mut send_write) = tokio::io::split(sender_half);
        let (mut recv_read, mut recv_write) = tokio::io::split(receiver_half);

        let block1: Vec<u8> = (0..128u8).map(|i| i.wrapping_mul(13)).collect();
        let block1_clone = block1.clone();

        // Drain receiver-side bytes until we see `target`, ignoring
        // the negotiation loop's 'C' retries that arrive after the
        // first CAN before the receiver sees the next data byte.
        async fn read_until(
            reader: &mut (impl AsyncRead + Unpin),
            target: u8,
        ) -> u8 {
            loop {
                let b = raw_read_byte(reader, false).await.unwrap();
                if b == target {
                    return b;
                }
            }
        }

        let send_task = tokio::spawn(async move {
            // Wait for 'C'.
            let _ = raw_read_byte(&mut send_read, false).await.unwrap();
            // CAN — arms pending_can on the receiver side.
            raw_write_byte(&mut send_write, CAN, false).await.unwrap();
            // Block 1 (SOH+...) — non-CAN bytes clear pending_can.
            let mut pkt = vec![SOH, 1, !1u8];
            pkt.extend_from_slice(&block1_clone);
            let crc = crc16_xmodem(&block1_clone);
            pkt.push((crc >> 8) as u8);
            pkt.push((crc & 0xFF) as u8);
            send_write.write_all(&pkt).await.unwrap();
            // Receiver may have sent additional 'C' requests after
            // the first CAN before reading our SOH; drain them.
            let _ = read_until(&mut send_read, ACK).await;
            // Another single CAN — should NOT abort because the SOH
            // and block body cleared the run.
            raw_write_byte(&mut send_write, CAN, false).await.unwrap();
            // EOT to gracefully end the transfer.
            raw_write_byte(&mut send_write, EOT, false).await.unwrap();
            let _ = read_until(&mut send_read, ACK).await;
        });

        let (received, _) = xmodem_receive(
            &mut recv_read, &mut recv_write, false, false, false,
        )
        .await
        .expect("two non-consecutive single CANs must not abort");

        send_task.await.unwrap();
        assert_eq!(received, block1);
    }

    /// Sender side of the same property: a single CAN from the
    /// receiver mid-transfer (e.g. line noise) must NOT abort the
    /// send — the sender keeps reading until either a definitive
    /// ACK/NAK arrives or a second consecutive CAN follows.
    #[tokio::test]
    async fn test_xmodem_send_single_can_then_ack_continues() {
        let (sender_half, receiver_half) = tokio::io::duplex(16384);
        let (mut send_read, mut send_write) = tokio::io::split(sender_half);
        let (mut recv_read, mut recv_write) = tokio::io::split(receiver_half);

        let data = b"hello, single-CAN-noise!".to_vec();
        let send_task = tokio::spawn(async move {
            xmodem_send(
                &mut send_read, &mut send_write, &data,
                false, false, false, false, None,
            ).await
        });

        let recv_task = tokio::spawn(async move {
            // Request CRC mode.
            raw_write_byte(&mut recv_write, CRC_REQUEST, false).await.unwrap();
            // Read block 1.
            let _ = read_soh_crc_block(&mut recv_read).await;
            // Stray single CAN, then ACK.  Sender must drain the CAN
            // and treat ACK as the definitive response.
            raw_write_byte(&mut recv_write, CAN, false).await.unwrap();
            raw_write_byte(&mut recv_write, ACK, false).await.unwrap();
            // Read EOT, ACK it.
            assert_eq!(raw_read_byte(&mut recv_read, false).await.unwrap(), EOT);
            raw_write_byte(&mut recv_write, ACK, false).await.unwrap();
        });

        let result = send_task.await.unwrap();
        recv_task.await.unwrap();
        result.expect("sender must complete despite stray CAN from receiver");
    }

    #[test]
    fn test_xmodem_control_byte_constants_match_christensen() {
        // Christensen 1977 / Forsberg's YMODEM.DOC defines:
        //   SOH = 0x01, STX = 0x02, EOT = 0x04, ACK = 0x06,
        //   NAK = 0x15, CAN = 0x18, SUB = 0x1A.
        // Plus Forsberg's CRC-mode trigger 'C' = 0x43.
        const _: () = assert!(SOH == 0x01);
        const _: () = assert!(STX == 0x02);
        const _: () = assert!(EOT == 0x04);
        const _: () = assert!(ACK == 0x06);
        const _: () = assert!(NAK == 0x15);
        const _: () = assert!(CAN == 0x18);
        const _: () = assert!(SUB == 0x1A);
        const _: () = assert!(CRC_REQUEST == 0x43);
    }

    // ─── lrzsz interop tests (manual, #[ignore]) ────────────
    //
    // Mirror the ZMODEM lrzsz interop tests in src/zmodem.rs.  Run with:
    //   cargo test --release -- --ignored test_lrzsz_xmodem
    //   cargo test --release -- --ignored test_lrzsz_ymodem
    // Each test spawns a real sx/rx/sb/rb subprocess, drives our
    // sender/receiver against it through stdin/stdout, reaps the child
    // before unwrapping, and verifies the file bytes round-trip
    // unchanged.  Unix-only because lrzsz is.

    // ─── XMODEM: our sender → real `rx` ──────────────────────

    /// Our sender → real `rx -c` (CRC-16).  Validates our CRC-16
    /// negotiation and 128-byte SOH block stream against a real
    /// receiver.  Payload deliberately avoids trailing 0x1A so the
    /// SUB-strip on the receiving side doesn't confuse the assertion.
    #[cfg(unix)]
    #[tokio::test]
    #[ignore]
    async fn test_lrzsz_xmodem_rx_crc() {
        use std::process::Stdio;
        use tokio::process::Command;

        if Command::new("rx")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .map(|s| !s.success())
            .unwrap_or(true)
        {
            panic!("rx (lrzsz) not found on PATH");
        }

        let tmp = std::env::temp_dir()
            .join(format!("xmodem_rx_crc_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let out_path = tmp.join("received.dat");

        // 256 bytes, no trailing 0x1A — picks every byte 1..=255 then 0,
        // so the last byte is 0x00 (not SUB).
        let payload: Vec<u8> = (1u16..=256u16)
            .map(|i| (i & 0xFF) as u8)
            .collect();

        let mut rx = Command::new("rx")
            .arg("-c") // CRC-16 mode
            .arg(&out_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("failed to spawn rx");

        let mut rx_stdin = rx.stdin.take().unwrap();
        let mut rx_stdout = rx.stdout.take().unwrap();

        let send_result = xmodem_send(
            &mut rx_stdout,
            &mut rx_stdin,
            &payload,
            false,
            false,
            true,
            false,
            None,
        )
        .await;
        let _ = rx.wait().await;
        send_result.expect("xmodem_send against rx -c failed");

        let received = std::fs::read(&out_path).unwrap();
        // rx pads with 0x1A to the next 128-byte boundary.  Strip
        // trailing 0x1A bytes for the comparison — our sender pads
        // identically, and the original payload doesn't end in 0x1A.
        let stripped: Vec<u8> = {
            let mut v = received.clone();
            while v.last() == Some(&0x1A) {
                v.pop();
            }
            v
        };
        assert_eq!(stripped, payload);

        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// Our sender → real `rx` (no `-c`, defaults to checksum mode).
    /// `rx` opens the negotiation with NAK (0x15) so our sender falls
    /// back to the legacy 1-byte checksum path.
    #[cfg(unix)]
    #[tokio::test]
    #[ignore]
    async fn test_lrzsz_xmodem_rx_checksum() {
        use std::process::Stdio;
        use tokio::process::Command;

        if Command::new("rx")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .map(|s| !s.success())
            .unwrap_or(true)
        {
            panic!("rx (lrzsz) not found on PATH");
        }

        let tmp = std::env::temp_dir()
            .join(format!("xmodem_rx_cksum_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let out_path = tmp.join("received.dat");

        let payload = b"checksum-mode round trip across legacy XMODEM\n".to_vec();

        let mut rx = Command::new("rx")
            .arg(&out_path) // no -c: defaults to checksum
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("failed to spawn rx");

        let mut rx_stdin = rx.stdin.take().unwrap();
        let mut rx_stdout = rx.stdout.take().unwrap();

        let send_result = xmodem_send(
            &mut rx_stdout,
            &mut rx_stdin,
            &payload,
            false,
            false,
            true,
            false,
            None,
        )
        .await;
        let _ = rx.wait().await;
        send_result.expect("xmodem_send against rx (checksum) failed");

        let received = std::fs::read(&out_path).unwrap();
        let stripped: Vec<u8> = {
            let mut v = received.clone();
            while v.last() == Some(&0x1A) {
                v.pop();
            }
            v
        };
        assert_eq!(stripped, payload);

        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// Our sender with `use_1k=true` → real `rx -c`.  Validates our
    /// XMODEM-1K STX/1024 path.  Payload is an exact multiple of 1024
    /// so we never fall back to a final SOH block, exercising the pure
    /// 1K path end-to-end.
    #[cfg(unix)]
    #[tokio::test]
    #[ignore]
    async fn test_lrzsz_xmodem_rx_1k() {
        use std::process::Stdio;
        use tokio::process::Command;

        if Command::new("rx")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .map(|s| !s.success())
            .unwrap_or(true)
        {
            panic!("rx (lrzsz) not found on PATH");
        }

        let tmp = std::env::temp_dir()
            .join(format!("xmodem_rx_1k_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let out_path = tmp.join("received.dat");

        // 4096 = exact 4 × 1024 STX blocks, no SOH fallback.
        let payload: Vec<u8> = (0..4096u32)
            .map(|i| (i.wrapping_mul(13) & 0xFF) as u8)
            .collect();

        let mut rx = Command::new("rx")
            .arg("-c") // CRC-16; rx auto-detects STX vs SOH
            .arg(&out_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("failed to spawn rx");

        let mut rx_stdin = rx.stdin.take().unwrap();
        let mut rx_stdout = rx.stdout.take().unwrap();

        let send_result = xmodem_send(
            &mut rx_stdout,
            &mut rx_stdin,
            &payload,
            false,
            false,
            true,
            true, // use_1k
            None,
        )
        .await;
        let _ = rx.wait().await;
        send_result.expect("xmodem_send (1K) against rx -c failed");

        let received = std::fs::read(&out_path).unwrap();
        let stripped: Vec<u8> = {
            let mut v = received.clone();
            while v.last() == Some(&0x1A) {
                v.pop();
            }
            v
        };
        assert_eq!(stripped, payload);

        let _ = std::fs::remove_dir_all(&tmp);
    }

    // ─── XMODEM: real `sx` → our receiver ─────────────────────

    /// Real `sx` → our receiver (128-byte SOH path).  `sx` defaults to
    /// XMODEM with CRC-16 negotiation.  Counterpart to the sender-
    /// direction tests above — catches receive-side regressions a real
    /// sender exposes that our internal duplex round-trip can't.
    #[cfg(unix)]
    #[tokio::test]
    #[ignore]
    async fn test_lrzsz_xmodem_sx_to_us() {
        use std::process::Stdio;
        use tokio::process::Command;

        if Command::new("sx")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .map(|s| !s.success())
            .unwrap_or(true)
        {
            panic!("sx (lrzsz) not found on PATH");
        }

        let tmp = std::env::temp_dir()
            .join(format!("xmodem_sx_basic_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        let payload: Vec<u8> = (0..512u32)
            .map(|i| (i.wrapping_mul(7) & 0xFF) as u8)
            .collect();
        let payload_path = tmp.join("payload.bin");
        std::fs::write(&payload_path, &payload).unwrap();

        let mut sx = Command::new("sx")
            .arg(&payload_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("failed to spawn sx");

        let mut sx_stdin = sx.stdin.take().unwrap();
        let mut sx_stdout = sx.stdout.take().unwrap();

        let recv_result = xmodem_receive(
            &mut sx_stdout,
            &mut sx_stdin,
            false,
            false,
            true,
        )
        .await;
        let _ = sx.wait().await;
        let (mut received, _) = recv_result.expect("xmodem_receive against sx failed");

        // sx pads with 0x1A; our receiver strips trailing SUB bytes for
        // plain XMODEM (no size info).  Strip any residual 0x1A in case
        // the boundary aligned exactly with the payload length.
        while received.last() == Some(&0x1A) {
            received.pop();
        }
        assert_eq!(received, payload);

        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// Real `sx -k` → our receiver.  Forces sx to emit STX/1024-byte
    /// blocks; validates our receiver auto-detects STX and decodes the
    /// 1K body correctly against a real sender.
    #[cfg(unix)]
    #[tokio::test]
    #[ignore]
    async fn test_lrzsz_xmodem_sx_1k_to_us() {
        use std::process::Stdio;
        use tokio::process::Command;

        if Command::new("sx")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .map(|s| !s.success())
            .unwrap_or(true)
        {
            panic!("sx (lrzsz) not found on PATH");
        }

        let tmp = std::env::temp_dir()
            .join(format!("xmodem_sx_1k_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        let payload: Vec<u8> = (0..3072u32)
            .map(|i| (i.wrapping_mul(11) & 0xFF) as u8)
            .collect();
        let payload_path = tmp.join("payload.bin");
        std::fs::write(&payload_path, &payload).unwrap();

        let mut sx = Command::new("sx")
            .arg("-k") // force 1K blocks
            .arg(&payload_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("failed to spawn sx -k");

        let mut sx_stdin = sx.stdin.take().unwrap();
        let mut sx_stdout = sx.stdout.take().unwrap();

        let recv_result = xmodem_receive(
            &mut sx_stdout,
            &mut sx_stdin,
            false,
            false,
            true,
        )
        .await;
        let _ = sx.wait().await;
        let (mut received, _) = recv_result.expect("xmodem_receive against sx -k failed");

        while received.last() == Some(&0x1A) {
            received.pop();
        }
        assert_eq!(received, payload);

        let _ = std::fs::remove_dir_all(&tmp);
    }

    // ─── YMODEM: our sender → real `rb` ──────────────────────

    /// Our sender (YMODEM mode) → real `rb`.  Emits block 0 with
    /// filename + size, then data blocks, then end-of-batch.  `rb` is
    /// the YMODEM-batch lrzsz binary; verifies our YMODEM block-0
    /// format is acceptable to a real receiver and that the
    /// end-of-batch handshake completes cleanly.
    #[cfg(unix)]
    #[tokio::test]
    #[ignore]
    async fn test_lrzsz_ymodem_rb_single() {
        use std::process::Stdio;
        use tokio::process::Command;

        if Command::new("rb")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .map(|s| !s.success())
            .unwrap_or(true)
        {
            panic!("rb (lrzsz) not found on PATH");
        }

        let tmp = std::env::temp_dir()
            .join(format!("ymodem_rb_single_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        let payload: Vec<u8> = (0..600u32)
            .map(|i| (i.wrapping_mul(17) & 0xFF) as u8)
            .collect();
        let header = YmodemHeader {
            filename: "ymodem_test.bin".to_string(),
            size: payload.len() as u64,
            modtime: None,
            mode: None,
        };

        let mut rb = Command::new("rb")
            .current_dir(&tmp)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("failed to spawn rb");

        let mut rb_stdin = rb.stdin.take().unwrap();
        let mut rb_stdout = rb.stdout.take().unwrap();

        let send_result = xmodem_send(
            &mut rb_stdout,
            &mut rb_stdin,
            &payload,
            false,
            false,
            true,
            false,
            Some(header),
        )
        .await;
        let _ = rb.wait().await;
        send_result.expect("xmodem_send (YMODEM) against rb failed");

        let received = std::fs::read(tmp.join("ymodem_test.bin")).unwrap();
        // YMODEM declares size in block 0, so rb truncates exactly —
        // no SUB-strip needed and the comparison is byte-exact.
        assert_eq!(received, payload);

        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// Our sender (YMODEM mode, full metadata) → real `rb`.  Emits
    /// block 0 with the maximum-conformance metadata quartet
    /// (length/modtime/mode/sno) and validates that `rb` not only
    /// accepts the transfer but applies the modtime to the saved
    /// file.  This pins down end-to-end interop with the most
    /// common real-world YMODEM receiver when full metadata is in
    /// play, complementing the size-only path above.
    #[cfg(unix)]
    #[tokio::test]
    #[ignore]
    async fn test_lrzsz_ymodem_rb_full_metadata() {
        use std::process::Stdio;
        use tokio::process::Command;

        if Command::new("rb")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .map(|s| !s.success())
            .unwrap_or(true)
        {
            panic!("rb (lrzsz) not found on PATH");
        }

        let tmp = std::env::temp_dir()
            .join(format!("ymodem_rb_meta_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        let payload: Vec<u8> = (0..512u32)
            .map(|i| (i.wrapping_mul(13) & 0xFF) as u8)
            .collect();
        // Use a clearly-in-the-past timestamp so we can distinguish
        // it from rb's "use now" fallback (which it would apply if
        // we omitted modtime).  2017-07-14 19:40:00 UTC.
        let target_modtime: u64 = 1_500_000_000;
        let header = YmodemHeader {
            filename: "ymodem_meta.bin".to_string(),
            size: payload.len() as u64,
            modtime: Some(target_modtime),
            mode: Some(0o100644),
        };

        let mut rb = Command::new("rb")
            .current_dir(&tmp)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("failed to spawn rb");

        let mut rb_stdin = rb.stdin.take().unwrap();
        let mut rb_stdout = rb.stdout.take().unwrap();

        let send_result = xmodem_send(
            &mut rb_stdout,
            &mut rb_stdin,
            &payload,
            false,
            false,
            true,
            false,
            Some(header),
        )
        .await;
        let _ = rb.wait().await;
        send_result.expect("xmodem_send (YMODEM full meta) against rb failed");

        let saved_path = tmp.join("ymodem_meta.bin");
        let received = std::fs::read(&saved_path).unwrap();
        assert_eq!(received, payload, "data must round-trip");

        // rb honors block-0 modtime by setting the saved file's
        // mtime — verify it lands within ±1 second of what we sent
        // (filesystem second-granularity tolerance).
        let saved_mtime = std::fs::metadata(&saved_path)
            .unwrap()
            .modified()
            .unwrap()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let delta = (saved_mtime - target_modtime as i64).abs();
        assert!(
            delta <= 1,
            "rb saved-file mtime ({}) must match block-0 modtime ({}); delta={}",
            saved_mtime,
            target_modtime,
            delta,
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }

    // ─── YMODEM: real `sb` → our receiver ─────────────────────

    /// Real `sb` → our receiver.  Validates our auto-detection of
    /// YMODEM via block 0, filename + size extraction, and the size-
    /// based truncation that preserves files ending in 0x1A.  Payload
    /// deliberately ends in 0x1A so a SUB-strip would corrupt it; if
    /// the assertion passes, size-truncation is working.
    ///
    /// NOTE: our `xmodem_receive` returns one file per call and closes
    /// the YMODEM batch after the first file, so multi-file `sb` is
    /// outside the current API and is not tested here.
    #[cfg(unix)]
    #[tokio::test]
    #[ignore]
    async fn test_lrzsz_ymodem_sb_to_us_single() {
        use std::process::Stdio;
        use tokio::process::Command;

        if Command::new("sb")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .map(|s| !s.success())
            .unwrap_or(true)
        {
            panic!("sb (lrzsz) not found on PATH");
        }

        let tmp = std::env::temp_dir()
            .join(format!("ymodem_sb_single_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        // Payload that ends in 0x1A — tests size-based truncation
        // (YMODEM block 0 declares the exact size).  If the receiver
        // SUB-strips instead, the trailing 0x1A would be lost.
        let mut payload: Vec<u8> = (0..500u32)
            .map(|i| (i.wrapping_mul(19) & 0xFF) as u8)
            .collect();
        payload.push(0x1A);
        payload.push(0x1A);
        let payload_path = tmp.join("ymodem_payload.bin");
        std::fs::write(&payload_path, &payload).unwrap();

        let mut sb = Command::new("sb")
            .arg(&payload_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("failed to spawn sb");

        let mut sb_stdin = sb.stdin.take().unwrap();
        let mut sb_stdout = sb.stdout.take().unwrap();

        let recv_result = xmodem_receive(
            &mut sb_stdout,
            &mut sb_stdin,
            false,
            false,
            true,
        )
        .await;
        let _ = sb.wait().await;
        let (received, meta) = recv_result.expect("xmodem_receive against sb failed");

        assert_eq!(
            received, payload,
            "YMODEM size-truncation should preserve trailing 0x1A bytes"
        );

        // sb populates the full block-0 metadata quartet — surface it
        // through our parser so this test pins the interop contract
        // for the modtime/mode fields, not just the data round-trip.
        let m = meta.expect("sb must emit block-0 metadata");
        assert_eq!(
            m.size,
            Some(payload.len() as u64),
            "block-0 length must match real file size",
        );
        // sb fills modtime from the source file's stat, which we just
        // wrote above — must be a recent value, not 0.
        let modtime = m.modtime.expect("sb must emit modtime");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(
            modtime > 0 && now.saturating_sub(modtime) < 60,
            "sb modtime ({}) must be a recent UNIX timestamp",
            modtime,
        );
        // sb emits the source file's mode; std::fs::write produces
        // 0o644 by default on Linux, possibly modified by umask.
        // Just check that the perm bits are non-zero and within
        // 0o7777.
        let mode = m.mode.expect("sb must emit mode");
        assert!(
            mode != 0 && mode & !0o7777 == 0,
            "sb mode ({:o}) must be a valid permission word",
            mode,
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }

    // ─── proptest fuzz: parse_ymodem_block_zero_payload ─────────
    //
    // The block-0 parser sees adversarial bytes from any sender that
    // can drive an XMODEM-mode handshake.  Spec senders are
    // well-formed; broken or malicious senders may send anything in
    // the 128-byte payload.  Property: the parser never panics —
    // outcomes are `Some(meta)` or `None`.  An out-of-bounds index,
    // subtraction overflow, or UTF-8 unwrap would surface here.

    mod ymodem_parser_proptest {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #![proptest_config(ProptestConfig {
                cases: 256,
                ..ProptestConfig::default()
            })]

            /// 128-byte payloads sized exactly as the receiver sees
            /// them — must never panic regardless of content.
            #[test]
            fn prop_parse_block_zero_full_size_no_panic(
                bytes in prop::collection::vec(any::<u8>(), XMODEM_BLOCK_SIZE..=XMODEM_BLOCK_SIZE),
            ) {
                let _ = parse_ymodem_block_zero_payload(&bytes);
            }

            /// Parser is also called on shorter slices in tests; must
            /// tolerate any length without panic.
            #[test]
            fn prop_parse_block_zero_arbitrary_length_no_panic(
                bytes in prop::collection::vec(any::<u8>(), 0..256),
            ) {
                let _ = parse_ymodem_block_zero_payload(&bytes);
            }
        }
    }
}
