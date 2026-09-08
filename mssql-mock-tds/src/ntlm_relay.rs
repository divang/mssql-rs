// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Forward NTLM Type 1/2/3 blobs between a TDS client and an upstream SQL Server.
//!
//! The mock server still owns PreLogin (and optional TLS) with the client. After
//! that, LOGIN7 and SSPI packets are sent verbatim to SQL Server so that SQL
//! Server issues the NTLM challenge and validates the client's response.

use crate::protocol::{
    ENCRYPT_ON, ENCRYPT_REQ, LoginRelayOutcome, PACKET_HEADER_SIZE, PacketHeader, ProtocolError,
    build_client_prelogin, parse_prelogin_encryption,
};
use crate::tds_tls_wrapper::TdsTlsWrapper;
use bytes::BytesMut;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_native_tls::TlsStream;
use tracing::{debug, info, warn};

const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(15);

/// One TDS session to the upstream SQL Server used only for NTLM handshake.
pub struct NtlmRelaySession {
    stream: RelayStream,
    sql_server: String,
    trust_server_certificate: bool,
}

enum RelayStream {
    Plain(TcpStream),
    Tls(TlsStream<TdsTlsWrapper>),
    Transitioning,
}

impl NtlmRelaySession {
    pub async fn connect(
        sql_server: &str,
        trust_server_certificate: bool,
    ) -> Result<Self, ProtocolError> {
        info!(sql_server, "Connecting NTLM relay to upstream SQL Server");
        let stream = tokio::time::timeout(UPSTREAM_TIMEOUT, TcpStream::connect(sql_server))
            .await
            .map_err(|_| {
                ProtocolError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("Timed out connecting to SQL Server at {sql_server}"),
                ))
            })?
            .map_err(|error| {
                ProtocolError::Io(std::io::Error::new(
                    error.kind(),
                    format!("Failed to connect to SQL Server at {sql_server}: {error}"),
                ))
            })?;

        let mut session = Self {
            stream: RelayStream::Plain(stream),
            sql_server: sql_server.to_string(),
            trust_server_certificate,
        };
        session.prelogin().await?;
        Ok(session)
    }

    pub fn sql_server(&self) -> &str {
        &self.sql_server
    }

    async fn prelogin(&mut self) -> Result<(), ProtocolError> {
        let request = build_client_prelogin();
        self.write_all(&request).await?;
        let response = self.read_message().await?;
        let encryption = parse_prelogin_encryption(&response)?;
        if encryption == ENCRYPT_ON || encryption == ENCRYPT_REQ {
            self.enable_tls().await?;
        }
        debug!(
            sql_server = %self.sql_server,
            encryption,
            "Upstream PreLogin completed without TLS"
        );
        Ok(())
    }

    async fn enable_tls(&mut self) -> Result<(), ProtocolError> {
        let RelayStream::Plain(stream) =
            std::mem::replace(&mut self.stream, RelayStream::Transitioning)
        else {
            return Ok(());
        };

        let mut builder = native_tls::TlsConnector::builder();
        if self.trust_server_certificate {
            builder.danger_accept_invalid_certs(true);
            builder.danger_accept_invalid_hostnames(true);
        }
        let connector = builder.build().map_err(|error| {
            ProtocolError::Protocol(format!("TLS configuration failed: {error}"))
        })?;
        let domain = upstream_host(&self.sql_server);
        let (wrapper, handshake_complete) = TdsTlsWrapper::new_client(stream);
        let tls = tokio::time::timeout(
            UPSTREAM_TIMEOUT,
            tokio_native_tls::TlsConnector::from(connector).connect(domain, wrapper),
        )
        .await
        .map_err(|_| {
            ProtocolError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!(
                    "Timed out negotiating TLS with SQL Server at {}",
                    self.sql_server
                ),
            ))
        })?
        .map_err(|error| ProtocolError::Protocol(format!("Upstream TLS failed: {error}")))?;
        handshake_complete.store(true, Ordering::Release);
        self.stream = RelayStream::Tls(tls);
        info!(sql_server = %self.sql_server, "Upstream TLS negotiation completed");
        Ok(())
    }

    /// Send a complete client TDS packet (LOGIN7 or SSPI) and read the SQL reply.
    pub async fn exchange(&mut self, packet: &[u8]) -> Result<BytesMut, ProtocolError> {
        self.write_all(packet).await?;
        self.read_message().await
    }

    async fn write_all(&mut self, packet: &[u8]) -> Result<(), ProtocolError> {
        let write = async {
            match &mut self.stream {
                RelayStream::Plain(stream) => stream.write_all(packet).await,
                RelayStream::Tls(stream) => stream.write_all(packet).await,
                RelayStream::Transitioning => Err(std::io::Error::other(
                    "relay stream is transitioning to TLS",
                )),
            }
        };
        tokio::time::timeout(UPSTREAM_TIMEOUT, write)
            .await
            .map_err(|_| {
                ProtocolError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("Timed out writing to SQL Server at {}", self.sql_server),
                ))
            })??;
        Ok(())
    }

    async fn read_message(&mut self) -> Result<BytesMut, ProtocolError> {
        let read = async {
            let mut out = BytesMut::new();
            loop {
                let mut header_buf = [0u8; PACKET_HEADER_SIZE];
                match &mut self.stream {
                    RelayStream::Plain(stream) => stream.read_exact(&mut header_buf).await?,
                    RelayStream::Tls(stream) => stream.read_exact(&mut header_buf).await?,
                    RelayStream::Transitioning => {
                        return Err(ProtocolError::Protocol(
                            "relay stream is transitioning to TLS".to_string(),
                        ));
                    }
                };
                let mut header_bytes: &[u8] = &header_buf;
                let header = PacketHeader::parse(&mut header_bytes)?;
                if (header.length as usize) < PACKET_HEADER_SIZE {
                    return Err(ProtocolError::InvalidPacketSize(header.length as usize));
                }
                let remaining = header.length as usize - PACKET_HEADER_SIZE;
                let mut body = vec![0u8; remaining];
                if remaining > 0 {
                    match &mut self.stream {
                        RelayStream::Plain(stream) => stream.read_exact(&mut body).await?,
                        RelayStream::Tls(stream) => stream.read_exact(&mut body).await?,
                        RelayStream::Transitioning => {
                            return Err(ProtocolError::Protocol(
                                "relay stream is transitioning to TLS".to_string(),
                            ));
                        }
                    };
                }
                out.extend_from_slice(&header_buf);
                out.extend_from_slice(&body);
                if header.status.is_end_of_message() {
                    return Ok(out);
                }
            }
        };
        tokio::time::timeout(UPSTREAM_TIMEOUT, read)
            .await
            .map_err(|_| {
                ProtocolError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("Timed out reading from SQL Server at {}", self.sql_server),
                ))
            })?
    }
}

fn upstream_host(sql_server: &str) -> &str {
    if let Some(rest) = sql_server.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest);
    }
    sql_server
        .rsplit_once(':')
        .map_or(sql_server, |(host, _)| host)
}

/// Apply handshake-state updates after an upstream login response is received.
pub fn apply_relay_outcome(
    outcome: LoginRelayOutcome,
    sql_server: &str,
) -> (bool, Option<String>, bool) {
    match outcome {
        LoginRelayOutcome::Continue => {
            debug!(sql_server, "SQL Server returned an NTLM challenge");
            (false, None, false)
        }
        LoginRelayOutcome::Complete => {
            info!(sql_server, "SQL Server accepted the NTLM response");
            (true, Some(format!("ntlm-relay:{sql_server}")), false)
        }
        LoginRelayOutcome::Failed => {
            warn!(sql_server, "SQL Server rejected NTLM authentication");
            (false, None, true)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{
        PacketType, build_done_token, build_login_ack, build_prelogin_response,
        build_sspi_challenge_response, classify_login_relay_response, wrap_in_packet,
    };
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    #[test]
    fn apply_relay_outcome_closes_on_complete_or_fail() {
        let (authed, identity, drop_session) =
            apply_relay_outcome(LoginRelayOutcome::Complete, "sql:1433");
        assert!(authed);
        assert_eq!(identity.as_deref(), Some("ntlm-relay:sql:1433"));
        assert!(!drop_session);

        let (authed, identity, drop_session) =
            apply_relay_outcome(LoginRelayOutcome::Failed, "sql:1433");
        assert!(!authed);
        assert!(identity.is_none());
        assert!(drop_session);

        let (authed, _, drop_session) =
            apply_relay_outcome(LoginRelayOutcome::Continue, "sql:1433");
        assert!(!authed);
        assert!(!drop_session);
    }

    #[tokio::test]
    async fn relay_forwards_type1_challenge_and_type3() {
        let sql_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("fake SQL listener");
        let sql_addr = sql_listener.local_addr().expect("sql addr");

        let sql_task = tokio::spawn(async move {
            let (mut sock, _) = sql_listener.accept().await.expect("sql accept");
            let mut header = [0u8; PACKET_HEADER_SIZE];
            sock.read_exact(&mut header).await.expect("prelogin header");
            let remaining =
                u16::from_be_bytes([header[2], header[3]]) as usize - PACKET_HEADER_SIZE;
            let mut body = vec![0u8; remaining];
            sock.read_exact(&mut body).await.expect("prelogin body");
            sock.write_all(&build_prelogin_response())
                .await
                .expect("prelogin response");

            sock.read_exact(&mut header).await.expect("login7 header");
            let remaining =
                u16::from_be_bytes([header[2], header[3]]) as usize - PACKET_HEADER_SIZE;
            let mut body = vec![0u8; remaining];
            sock.read_exact(&mut body).await.expect("login7 body");
            assert_eq!(header[0], PacketType::Login7 as u8);
            sock.write_all(
                &build_sspi_challenge_response(b"sql-type2-challenge").expect("challenge"),
            )
            .await
            .expect("write challenge");

            sock.read_exact(&mut header).await.expect("sspi header");
            let remaining =
                u16::from_be_bytes([header[2], header[3]]) as usize - PACKET_HEADER_SIZE;
            let mut body = vec![0u8; remaining];
            sock.read_exact(&mut body).await.expect("sspi body");
            assert_eq!(header[0], PacketType::Sspi as u8);
            assert_eq!(body, b"client-type3");
            let mut ack = build_login_ack();
            ack.extend_from_slice(&build_done_token(0));
            sock.write_all(&wrap_in_packet(PacketType::TabularResult, ack))
                .await
                .expect("login ack");
        });

        let mut relay = NtlmRelaySession::connect(&sql_addr.to_string(), false)
            .await
            .expect("connect relay");
        let login7 = wrap_in_packet(PacketType::Login7, BytesMut::from(&b"type1"[..]));
        let challenge = relay.exchange(&login7).await.expect("type1 exchange");
        assert_eq!(
            classify_login_relay_response(&challenge),
            LoginRelayOutcome::Continue
        );

        let type3 =
            crate::protocol::build_sspi_message_packet(b"client-type3").expect("type3 packet");
        let ack = relay.exchange(&type3).await.expect("type3 exchange");
        assert_eq!(
            classify_login_relay_response(&ack),
            LoginRelayOutcome::Complete
        );
        sql_task.await.expect("fake SQL finished");
    }
}
