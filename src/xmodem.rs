//! XMODEM Protocol Module
//!
//! Implements the XMODEM file transfer protocol with CRC-16 and checksum modes:
//! - xmodem_receive: receive file data from a sender (upload)
//! - xmodem_send: send file data to a receiver (download)
//! - Raw I/O helpers with telnet IAC escaping
//! - CRC-16 (CCITT polynomial 0x1021) computation

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::config;
use crate::telnet::is_esc_key;

// XMODEM protocol constants
const SOH: u8 = 0x01;
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

const MAX_FILE_SIZE: usize = 8 * 1024 * 1024;
/// Time allowed for the full 131-byte block body (after SOH) to arrive.
const BLOCK_BODY_TIMEOUT_SECS: u64 = 60;

#[derive(Clone, Copy)]
enum TransferMode {
    Checksum,
    Crc16,
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
) -> Result<Vec<u8>, String> {
    let cfg = config::get_config();
    let negotiation_timeout = cfg.xmodem_negotiation_timeout;
    let block_timeout = cfg.xmodem_block_timeout;
    let max_retries = cfg.xmodem_max_retries;

    let mut file_data = Vec::new();
    let mut expected_block: u8 = 1;
    let negotiation_deadline =
        tokio::time::Instant::now() + tokio::time::Duration::from_secs(negotiation_timeout);

    if verbose { eprintln!("XMODEM recv: starting negotiation (is_tcp={}, is_petscii={})", is_tcp, is_petscii); }

    // Negotiate mode: try CRC first ('C') for 20 attempts (60 seconds),
    // then fall back to checksum (NAK) for the remaining time.  This gives
    // the user plenty of time to start their XMODEM sender in CRC mode.
    let mut mode = TransferMode::Crc16;
    let mut attempt: u32 = 0;

    // Send CRC requests for 2/3 of the negotiation time, then fall back to checksum.
    let crc_attempts = (negotiation_timeout * 2 / 3 / 3).max(3) as u32;
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
        if verbose { eprintln!("XMODEM recv: attempt {} sending 0x{:02X} ({})",
            attempt, request, if request == CRC_REQUEST { "CRC req" } else { "NAK" }); }
        raw_write_byte(writer, request, is_tcp).await?;

        match tokio::time::timeout(
            std::time::Duration::from_secs(3),
            raw_read_byte(reader, is_tcp),
        )
        .await
        {
            Ok(Ok(byte)) => {
                if verbose { eprintln!("XMODEM recv: got 0x{:02X} during negotiation", byte); }
                if is_esc_key(byte, is_petscii) {
                    return Err("Transfer cancelled".into());
                }
                if byte == SOH {
                    if verbose { eprintln!("XMODEM recv: SOH received, reading block #1"); }
                    match tokio::time::timeout(
                        std::time::Duration::from_secs(BLOCK_BODY_TIMEOUT_SECS),
                        receive_block(reader, &mut expected_block, mode, is_tcp, verbose),
                    )
                    .await
                    {
                        Ok(Ok(data)) => {
                            if verbose { eprintln!("XMODEM recv: block #1 OK"); }
                            file_data.extend_from_slice(&data);
                            raw_write_byte(writer, ACK, is_tcp).await?;
                        }
                        Ok(Err(e)) => {
                            if verbose { eprintln!("XMODEM recv: block #1 error: {}", e); }
                            raw_write_byte(writer, NAK, is_tcp).await?;
                        }
                        Err(_) => {
                            if verbose { eprintln!("XMODEM recv: block #1 timeout"); }
                            raw_write_byte(writer, NAK, is_tcp).await?;
                        }
                    }
                    break;
                }
                if byte == EOT {
                    raw_write_byte(writer, ACK, is_tcp).await?;
                    return Ok(file_data);
                }
                if byte == CAN {
                    return Err("Transfer cancelled by sender".into());
                }
                if verbose { eprintln!("XMODEM recv: ignoring unexpected byte 0x{:02X}", byte); }
            }
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                if verbose { eprintln!("XMODEM recv: attempt {} timeout, retrying", attempt); }
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
            raw_read_byte(reader, is_tcp),
        )
        .await
        {
            Ok(Ok(b)) => b,
            Ok(Err(e)) => return Err(e),
            Err(_) => return Err("Transfer timeout".into()),
        };

        match byte {
            SOH => match tokio::time::timeout(
                std::time::Duration::from_secs(BLOCK_BODY_TIMEOUT_SECS),
                receive_block(reader, &mut expected_block, mode, is_tcp, verbose),
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
            },
            EOT => {
                raw_write_byte(writer, ACK, is_tcp).await?;
                break;
            }
            CAN => {
                return Err("Transfer cancelled by sender".into());
            }
            _ => {
                raw_write_byte(writer, NAK, is_tcp).await?;
            }
        }
    }

    // Strip trailing SUB (0x1A) padding from last block.
    while file_data.last() == Some(&SUB) {
        file_data.pop();
    }

    Ok(file_data)
}

/// Receive and validate a single XMODEM block (after SOH was already read).
async fn receive_block(
    reader: &mut (impl AsyncRead + Unpin),
    expected_block: &mut u8,
    mode: TransferMode,
    is_tcp: bool,
    verbose: bool,
) -> Result<[u8; XMODEM_BLOCK_SIZE], String> {
    let block_num = raw_read_byte(reader, is_tcp).await?;
    let block_complement = raw_read_byte(reader, is_tcp).await?;

    if verbose { eprintln!("XMODEM recv block: num=0x{:02X} complement=0x{:02X} expected=0x{:02X} mode={}",
        block_num, block_complement, *expected_block,
        match mode { TransferMode::Crc16 => "CRC16", TransferMode::Checksum => "Checksum" }); }

    let mut data = [0u8; XMODEM_BLOCK_SIZE];
    for byte in data.iter_mut() {
        *byte = raw_read_byte(reader, is_tcp).await?;
    }

    let valid = match mode {
        TransferMode::Checksum => {
            let recv_checksum = raw_read_byte(reader, is_tcp).await?;
            let calc_checksum = data.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
            if verbose { eprintln!("XMODEM recv block: checksum recv=0x{:02X} calc=0x{:02X}", recv_checksum, calc_checksum); }
            recv_checksum == calc_checksum
        }
        TransferMode::Crc16 => {
            let crc_hi = raw_read_byte(reader, is_tcp).await?;
            let crc_lo = raw_read_byte(reader, is_tcp).await?;
            let recv_crc = ((crc_hi as u16) << 8) | crc_lo as u16;
            let calc_crc = crc16_xmodem(&data);
            if verbose { eprintln!("XMODEM recv block: CRC recv=0x{:04X} calc=0x{:04X}", recv_crc, calc_crc); }
            recv_crc == calc_crc
        }
    };

    if block_complement != !(block_num) {
        if verbose { eprintln!("XMODEM recv block: FAIL complement mismatch 0x{:02X} != !0x{:02X} (0x{:02X})",
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
        if verbose { eprintln!("XMODEM recv block: FAIL block number 0x{:02X} != expected 0x{:02X}", block_num, *expected_block); }
        return Err("Block number mismatch".into());
    }

    *expected_block = expected_block.wrapping_add(1);
    Ok(data)
}

// =============================================================================
// XMODEM PROTOCOL - SEND (DOWNLOAD)
// =============================================================================

pub(crate) async fn xmodem_send(
    reader: &mut (impl AsyncRead + Unpin),
    writer: &mut (impl AsyncWrite + Unpin),
    data: &[u8],
    is_tcp: bool,
    is_petscii: bool,
    verbose: bool,
) -> Result<(), String> {
    let cfg = config::get_config();
    let negotiation_timeout = cfg.xmodem_negotiation_timeout;
    let block_timeout = cfg.xmodem_block_timeout;
    let max_retries = cfg.xmodem_max_retries;

    let negotiation_deadline =
        tokio::time::Instant::now() + tokio::time::Duration::from_secs(negotiation_timeout);

    if verbose { eprintln!("XMODEM send: starting negotiation (is_tcp={}, is_petscii={}, data_len={})",
        is_tcp, is_petscii, data.len()); }

    // Wait for receiver's mode request (C = CRC, NAK = checksum)
    let mode = loop {
        let remaining = negotiation_deadline.duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err("Negotiation timeout: start your XMODEM receiver".into());
        }

        match tokio::time::timeout(remaining, raw_read_byte(reader, is_tcp)).await {
            Ok(Ok(byte)) => {
                if verbose { eprintln!("XMODEM send: negotiation got 0x{:02X}", byte); }
                if is_esc_key(byte, is_petscii) {
                    return Err("Transfer cancelled".into());
                }
                match byte {
                    CRC_REQUEST => {
                        if verbose { eprintln!("XMODEM send: receiver requests CRC mode"); }
                        break TransferMode::Crc16;
                    }
                    NAK => {
                        if verbose { eprintln!("XMODEM send: receiver requests Checksum mode"); }
                        break TransferMode::Checksum;
                    }
                    CAN => {
                        return Err("Transfer cancelled by receiver".into());
                    }
                    _ => {
                        if verbose { eprintln!("XMODEM send: ignoring byte 0x{:02X} during negotiation", byte); }
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
        raw_read_byte(reader, is_tcp),
    )
    .await
    {
        if verbose { eprintln!("XMODEM send: drained negotiation byte 0x{:02X}", b); }
    }

    // Pad data to block boundary
    let mut padded = data.to_vec();
    if padded.is_empty() {
        padded.push(SUB);
    }
    while !padded.len().is_multiple_of(XMODEM_BLOCK_SIZE) {
        padded.push(SUB);
    }

    let total_blocks = padded.len() / XMODEM_BLOCK_SIZE;
    let mut block_num: u8 = 1;
    if verbose { eprintln!("XMODEM send: {} total blocks", total_blocks); }

    for block_idx in 0..total_blocks {
        let block_offset = block_idx * XMODEM_BLOCK_SIZE;
        let block = &padded[block_offset..block_offset + XMODEM_BLOCK_SIZE];

        let mut retries = 0;
        loop {
            if retries >= max_retries {
                raw_write_bytes(writer, &[CAN, CAN, CAN], is_tcp).await?;
                return Err("Too many retries, transfer aborted".into());
            }

            // Build packet
            let mut packet = Vec::with_capacity(3 + XMODEM_BLOCK_SIZE + 2);
            packet.push(SOH);
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

            if block_idx == 0 && retries == 0 {
                if verbose { eprintln!("XMODEM send: block #1 header: SOH=0x{:02X} num=0x{:02X} complement=0x{:02X} packet_len={}",
                    SOH, block_num, !block_num, packet.len()); }
                if verbose { eprintln!("XMODEM send: block #1 first 8 data bytes: {:02X?}", &block[..8.min(block.len())]); }
            }

            raw_write_bytes(writer, &packet, is_tcp).await?;

            // Wait for ACK/NAK
            match tokio::time::timeout(
                std::time::Duration::from_secs(block_timeout),
                raw_read_byte(reader, is_tcp),
            )
            .await
            {
                Ok(Ok(ACK)) => {
                    if verbose && (block_idx < 3 || retries > 0) {
                        eprintln!("XMODEM send: block #{} ACK (retries={})", block_idx + 1, retries);
                    }
                    break;
                }
                Ok(Ok(CAN)) => {
                    if verbose { eprintln!("XMODEM send: CAN received at block #{}", block_idx + 1); }
                    return Err("Transfer cancelled by receiver".into());
                }
                Ok(Ok(NAK)) => {
                    if verbose { eprintln!("XMODEM send: block #{} NAK (retry {})", block_idx + 1, retries + 1); }
                    retries += 1;
                    continue;
                }
                Ok(Ok(byte)) => {
                    if verbose { eprintln!("XMODEM send: block #{} unexpected response 0x{:02X} (retry {})",
                        block_idx + 1, byte, retries + 1); }
                    retries += 1;
                    continue;
                }
                Ok(Err(e)) => return Err(e),
                Err(_) => {
                    if verbose { eprintln!("XMODEM send: block #{} timeout (retry {})", block_idx + 1, retries + 1); }
                    retries += 1;
                    continue;
                }
            }
        }

        block_num = block_num.wrapping_add(1);
    }

    // Send EOT and wait for ACK
    for _ in 0..max_retries {
        raw_write_byte(writer, EOT, is_tcp).await?;
        match tokio::time::timeout(
            std::time::Duration::from_secs(block_timeout),
            raw_read_byte(reader, is_tcp),
        )
        .await
        {
            Ok(Ok(ACK)) => return Ok(()),
            Ok(Ok(NAK)) => continue,
            Ok(Ok(b)) => {
                if verbose { eprintln!("XMODEM send: unexpected EOT response 0x{:02X}, treating as ACK", b); }
                return Ok(());
            }
            Ok(Err(e)) => {
                if verbose { eprintln!("XMODEM send: read error during EOT: {}", e); }
                return Err(format!("Read error during EOT: {}", e));
            }
            Err(_) => continue,
        }
    }
    if verbose { eprintln!("XMODEM send: EOT not ACKed after {} retries, assuming success", max_retries); }
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

/// Write a single raw byte, with telnet IAC escaping for TCP connections.
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
    } else {
        writer
            .write_all(&[byte])
            .await
            .map_err(|e| e.to_string())?;
    }
    writer.flush().await.map_err(|e| e.to_string())?;
    Ok(())
}

/// Write multiple raw bytes, with telnet IAC escaping for TCP connections.
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
            }
            buf.push(byte);
        }
        writer.write_all(&buf).await.map_err(|e| e.to_string())?;
        writer.flush().await.map_err(|e| e.to_string())?;
    } else {
        writer.write_all(data).await.map_err(|e| e.to_string())?;
        writer.flush().await.map_err(|e| e.to_string())?;
    }
    Ok(())
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
        let (sender_half, receiver_half) = tokio::io::duplex(16384);
        let (mut send_read, mut send_write) = tokio::io::split(sender_half);
        let (mut recv_read, mut recv_write) = tokio::io::split(receiver_half);

        let data = original.to_vec();
        let send_task = tokio::spawn(async move {
            xmodem_send(&mut send_read, &mut send_write, &data, false, false, false)
                .await
                .unwrap();
        });
        let recv_task = tokio::spawn(async move {
            xmodem_receive(&mut recv_read, &mut recv_write, false, false, false)
                .await
                .unwrap()
        });

        send_task.await.unwrap();
        recv_task.await.unwrap()
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

    #[tokio::test]
    async fn test_xmodem_round_trip_single_byte() {
        let received = xmodem_round_trip(&[0x42]).await;
        assert_eq!(received, vec![0x42]);
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
            let _ = xmodem_send(&mut send_read, &mut send_write, &oversized, false, false, false).await;
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
        data.extend(std::iter::repeat(0x42).take(1000));
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
}
