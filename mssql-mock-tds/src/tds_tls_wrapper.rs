//! TDS-TLS wrapper that handles TDS packet encapsulation for TLS data
//!
//! SQL Server wraps TLS handshake data in TDS packets for TDS 7.4 connections.
//! This module provides a wrapper that transparently handles the wrapping/unwrapping
//! for the server side:
//! - During handshake: Unwraps incoming TDS PreLogin packets (0x12) to extract TLS data
//!   and wraps outgoing TLS data in TDS TabularResult packets (0x04)
//! - After handshake: Passes data through directly (no wrapping/unwrapping)
//!
//! The key insight is that during TLS handshake, TLS records are wrapped in TDS packets,
//! but after the handshake completes, raw TLS records (Application Data 0x17) are sent
//! directly without TDS wrapping.

use bytes::{Buf, BufMut, BytesMut};
use std::io::{self, ErrorKind};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tracing::{debug, trace};

/// TDS packet header size
const TDS_HEADER_SIZE: usize = 8;

/// TDS packet types
const TDS_PRELOGIN: u8 = 0x12;
const TDS_TABULAR_RESULT: u8 = 0x04;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WrapperRole {
    Server,
    Client,
}

impl WrapperRole {
    fn incoming_packet_type(self) -> u8 {
        match self {
            Self::Server => TDS_PRELOGIN,
            Self::Client => TDS_TABULAR_RESULT,
        }
    }

    fn outgoing_packet_type(self) -> u8 {
        match self {
            Self::Server => TDS_TABULAR_RESULT,
            Self::Client => TDS_PRELOGIN,
        }
    }
}

/// TLS record types (for detecting raw TLS records after handshake)
const TLS_CHANGE_CIPHER_SPEC: u8 = 0x14;
#[allow(dead_code)]
const TLS_ALERT: u8 = 0x15;
#[allow(dead_code)]
const TLS_HANDSHAKE: u8 = 0x16;
const TLS_APPLICATION_DATA: u8 = 0x17;

/// Check if a byte looks like a TLS record type
fn is_tls_record_type(byte: u8) -> bool {
    matches!(byte, TLS_CHANGE_CIPHER_SPEC..=TLS_APPLICATION_DATA)
}

/// Read phase for state machine - simplified to avoid borrow conflicts
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadPhase {
    /// Reading the first byte to determine if TDS or raw TLS
    DetectType,
    /// Reading the rest of TDS header (already read first byte)
    ReadingTdsHeader,
    /// Reading the TDS payload
    ReadingTdsPayload,
    /// Have data buffered to return
    HaveData,
    /// Pass-through mode - forward data directly
    PassThrough,
}

/// Write phase for state machine
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WritePhase {
    /// Ready for new data
    Idle,
    /// Writing packet
    Writing,
}

/// Mode for the TDS wrapper
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WrapperMode {
    /// During TLS handshake - wrap/unwrap TDS packets
    Handshake,
    /// After TLS handshake - pass through directly
    PassThrough,
}

/// Wraps a TcpStream to handle TDS packet encapsulation for TLS handshake (server side)
///
/// During the TLS handshake phase:
/// - Incoming data is expected to be wrapped in TDS PreLogin packets
/// - Outgoing data is wrapped in TDS TabularResult packets
///
/// After handshake completes (when raw TLS record is seen), switches to
/// pass-through mode where data flows directly without TDS wrapping.
pub struct TdsTlsWrapper {
    inner: TcpStream,
    role: WrapperRole,
    mode: WrapperMode,
    handshake_complete: Arc<AtomicBool>,
    // Read state
    read_buffer: BytesMut,
    read_phase: ReadPhase,
    header_buf: [u8; TDS_HEADER_SIZE],
    header_bytes_read: usize,
    payload_remaining: usize,
    // Write state
    write_phase: WritePhase,
    write_buffer: BytesMut,
    write_bytes_written: usize,
    write_payload_len: usize,
    packet_id: u8,
}

impl TdsTlsWrapper {
    pub fn new(stream: TcpStream) -> Self {
        Self::new_with_role(
            stream,
            WrapperRole::Server,
            Arc::new(AtomicBool::new(false)),
        )
    }

    /// Create the client-side wrapper used while initiating TLS to SQL Server.
    pub(crate) fn new_client(stream: TcpStream) -> (Self, Arc<AtomicBool>) {
        let handshake_complete = Arc::new(AtomicBool::new(false));
        (
            Self::new_with_role(stream, WrapperRole::Client, handshake_complete.clone()),
            handshake_complete,
        )
    }

    fn new_with_role(
        stream: TcpStream,
        role: WrapperRole,
        handshake_complete: Arc<AtomicBool>,
    ) -> Self {
        Self {
            inner: stream,
            role,
            mode: WrapperMode::Handshake,
            handshake_complete,
            read_buffer: BytesMut::with_capacity(8192),
            read_phase: ReadPhase::DetectType,
            header_buf: [0u8; TDS_HEADER_SIZE],
            header_bytes_read: 0,
            payload_remaining: 0,
            write_phase: WritePhase::Idle,
            write_buffer: BytesMut::new(),
            write_bytes_written: 0,
            write_payload_len: 0,
            packet_id: 1,
        }
    }

    /// Consume the wrapper and return the inner TcpStream
    pub fn into_inner(self) -> TcpStream {
        self.inner
    }
}

impl AsyncRead for TdsTlsWrapper {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        if this.handshake_complete.load(Ordering::Acquire) {
            this.mode = WrapperMode::PassThrough;
            this.read_phase = ReadPhase::PassThrough;
        }

        loop {
            match this.read_phase {
                ReadPhase::PassThrough => {
                    // First return any buffered data
                    if !this.read_buffer.is_empty() {
                        let to_read = std::cmp::min(buf.remaining(), this.read_buffer.len());
                        buf.put_slice(&this.read_buffer[..to_read]);
                        this.read_buffer.advance(to_read);
                        return Poll::Ready(Ok(()));
                    }
                    // Then read directly from inner stream
                    return Pin::new(&mut this.inner).poll_read(cx, buf);
                }

                ReadPhase::HaveData => {
                    // Return buffered data
                    if this.read_buffer.is_empty() {
                        // Need to read more - go back to detection phase
                        this.read_phase = ReadPhase::DetectType;
                        this.header_bytes_read = 0;
                        this.header_buf = [0u8; TDS_HEADER_SIZE];
                        continue;
                    }

                    let to_read = std::cmp::min(buf.remaining(), this.read_buffer.len());
                    buf.put_slice(&this.read_buffer[..to_read]);
                    this.read_buffer.advance(to_read);
                    trace!("TdsTlsWrapper: returned {} bytes of TLS data", to_read);
                    return Poll::Ready(Ok(()));
                }

                ReadPhase::DetectType => {
                    // Read the first byte to determine packet type
                    let mut first_byte = [0u8; 1];
                    let mut first_byte_buf = ReadBuf::new(&mut first_byte);

                    match Pin::new(&mut this.inner).poll_read(cx, &mut first_byte_buf) {
                        Poll::Ready(Ok(())) => {
                            if first_byte_buf.filled().is_empty() {
                                return Poll::Ready(Err(io::Error::new(
                                    ErrorKind::UnexpectedEof,
                                    "Connection closed while reading first byte",
                                )));
                            }

                            let first = first_byte[0];

                            // Check if this is a raw TLS record (not wrapped in TDS)
                            if is_tls_record_type(first) {
                                debug!(
                                    "TdsTlsWrapper: detected raw TLS record type 0x{:02x}, switching to pass-through mode",
                                    first
                                );
                                this.mode = WrapperMode::PassThrough;
                                this.read_phase = ReadPhase::PassThrough;

                                // Return the first byte we already read
                                buf.put_slice(&[first]);
                                return Poll::Ready(Ok(()));
                            }

                            // It's a TDS packet - store first byte and continue reading header
                            this.header_buf[0] = first;
                            this.header_bytes_read = 1;

                            if first == this.role.incoming_packet_type() {
                                debug!(
                                    "TdsTlsWrapper: detected expected TDS TLS packet type 0x{:02x}",
                                    first
                                );
                                this.read_phase = ReadPhase::ReadingTdsHeader;
                            } else {
                                debug!(
                                    "TdsTlsWrapper: unexpected TDS packet type 0x{:02x}, expected 0x{:02x}",
                                    first,
                                    this.role.incoming_packet_type()
                                );
                                // Still try to read as TDS packet
                                this.read_phase = ReadPhase::ReadingTdsHeader;
                            }
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }
                }

                ReadPhase::ReadingTdsHeader => {
                    // Read remaining header bytes (we already have the first byte)
                    while this.header_bytes_read < TDS_HEADER_SIZE {
                        let mut header_slice =
                            ReadBuf::new(&mut this.header_buf[this.header_bytes_read..]);
                        match Pin::new(&mut this.inner).poll_read(cx, &mut header_slice) {
                            Poll::Ready(Ok(())) => {
                                if header_slice.filled().is_empty() {
                                    return Poll::Ready(Err(io::Error::new(
                                        ErrorKind::UnexpectedEof,
                                        "Connection closed while reading TDS header",
                                    )));
                                }
                                this.header_bytes_read += header_slice.filled().len();
                            }
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => return Poll::Pending,
                        }
                    }

                    // Parse header
                    let packet_type = this.header_buf[0];
                    let _status = this.header_buf[1];
                    let length =
                        u16::from_be_bytes([this.header_buf[2], this.header_buf[3]]) as usize;

                    debug!(
                        "TdsTlsWrapper: TDS packet type=0x{:02x}, length={}",
                        packet_type, length
                    );

                    if length < TDS_HEADER_SIZE {
                        return Poll::Ready(Err(io::Error::new(
                            ErrorKind::InvalidData,
                            format!("Invalid TDS packet length: {}", length),
                        )));
                    }

                    let payload_len = length - TDS_HEADER_SIZE;
                    if payload_len == 0 {
                        // Empty packet, go back to detection phase
                        this.read_phase = ReadPhase::DetectType;
                        this.header_bytes_read = 0;
                        this.header_buf = [0u8; TDS_HEADER_SIZE];
                        continue;
                    }

                    this.payload_remaining = payload_len;
                    this.read_phase = ReadPhase::ReadingTdsPayload;
                }

                ReadPhase::ReadingTdsPayload => {
                    // Read payload directly into our buffer
                    let current_len = this.read_buffer.len();
                    this.read_buffer
                        .resize(current_len + this.payload_remaining, 0);

                    let read_slice = &mut this.read_buffer[current_len..];
                    let mut read_buf = ReadBuf::new(read_slice);

                    match Pin::new(&mut this.inner).poll_read(cx, &mut read_buf) {
                        Poll::Ready(Ok(())) => {
                            let bytes_read = read_buf.filled().len();
                            if bytes_read == 0 {
                                return Poll::Ready(Err(io::Error::new(
                                    ErrorKind::UnexpectedEof,
                                    "Connection closed while reading TDS payload",
                                )));
                            }

                            // Adjust buffer to actual size read
                            this.read_buffer.truncate(current_len + bytes_read);
                            this.payload_remaining -= bytes_read;

                            trace!(
                                "TdsTlsWrapper: read {} bytes of payload, {} remaining",
                                bytes_read, this.payload_remaining
                            );

                            if this.payload_remaining == 0 {
                                this.read_phase = ReadPhase::HaveData;
                            }
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => {
                            // Restore buffer to original size
                            this.read_buffer.truncate(current_len);
                            return Poll::Pending;
                        }
                    }
                }
            }
        }
    }
}

impl AsyncWrite for TdsTlsWrapper {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        if this.handshake_complete.load(Ordering::Acquire) {
            this.mode = WrapperMode::PassThrough;
        }

        // If in pass-through mode, write directly to inner stream
        if this.mode == WrapperMode::PassThrough {
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        }

        loop {
            match this.write_phase {
                WritePhase::Idle => {
                    // Wrap data in TDS TabularResult packet
                    let packet_len = buf.len() + TDS_HEADER_SIZE;
                    this.write_buffer = BytesMut::with_capacity(packet_len);

                    // Server responses use TabularResult; client handshake
                    // records use PreLogin packets.
                    this.write_buffer.put_u8(this.role.outgoing_packet_type());
                    this.write_buffer.put_u8(0x01); // status: EOM
                    this.write_buffer.put_u16(packet_len as u16); // length (big endian)
                    this.write_buffer.put_u16(0); // SPID
                    this.write_buffer.put_u8(this.packet_id);
                    this.write_buffer.put_u8(0); // window

                    this.write_buffer.extend_from_slice(buf);

                    debug!(
                        "TdsTlsWrapper: wrapping {} bytes of TLS data in TDS packet (total {})",
                        buf.len(),
                        packet_len
                    );

                    this.packet_id = this.packet_id.wrapping_add(1);
                    this.write_bytes_written = 0;
                    this.write_payload_len = buf.len();
                    this.write_phase = WritePhase::Writing;
                }

                WritePhase::Writing => {
                    let remaining = &this.write_buffer[this.write_bytes_written..];
                    match Pin::new(&mut this.inner).poll_write(cx, remaining) {
                        Poll::Ready(Ok(n)) => {
                            this.write_bytes_written += n;
                            if this.write_bytes_written >= this.write_buffer.len() {
                                // Done writing this packet
                                let result_len = this.write_payload_len;
                                this.write_phase = WritePhase::Idle;
                                this.write_buffer.clear();
                                return Poll::Ready(Ok(result_len));
                            }
                            // Continue writing
                        }
                        Poll::Ready(Err(e)) => {
                            this.write_phase = WritePhase::Idle;
                            this.write_buffer.clear();
                            return Poll::Ready(Err(e));
                        }
                        Poll::Pending => return Poll::Pending,
                    }
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
