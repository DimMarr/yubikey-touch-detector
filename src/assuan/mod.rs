//! A minimal pure-Rust Assuan protocol client: just enough to send a
//! command to gpg-agent (only `LEARN` is used, to busy-check the card) and
//! read back its terminating status line. This is the entire reason for
//! the rewrite: it removes the `libgpgme`/`gpgme-devel` C build dependency
//! that motivated replacing the original Go tool's `gpgme` binding.
//!
//! Assuan is a simple newline-delimited text protocol: the server sends a
//! greeting line on connect, the client sends a command line, and the
//! server replies with zero or more `D`/`S`/`#` lines followed by a
//! terminating `OK` or `ERR <code> <description>` line. A server may also
//! send `INQUIRE <keyword>` mid-response to ask the client for more data;
//! since `LEARN` needs none, this client always answers with an empty
//! `END` (matching the original Go implementation's no-op inquiry
//! callback).
//!
//! Deliberately **not** built on `tokio::time::timeout` around the whole
//! exchange: the caller (the GPG detector) needs to race the exchange
//! against a short "is the card busy" timer without aborting the exchange
//! itself when that timer fires, since the original Go behavior lets the
//! real Assuan round trip run to completion in the background and only
//! uses the timer to decide *whether to notify*, not whether to cancel.
//! `send_command` therefore runs to true completion; the detector spawns
//! it and races a timeout against the `JoinHandle` instead.

pub mod discovery;

use std::path::Path;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};

#[derive(Debug)]
pub enum AssuanError {
    Io(std::io::Error),
    /// The peer violated the expected framing (bad greeting, connection
    /// closed mid-response, ...).
    Protocol(String),
    /// The peer answered the command with `ERR <code> <description>`.
    Server {
        code: String,
        description: String,
    },
}

impl std::fmt::Display for AssuanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AssuanError::Io(err) => write!(f, "assuan I/O error: {err}"),
            AssuanError::Protocol(msg) => write!(f, "assuan protocol error: {msg}"),
            AssuanError::Server { code, description } => {
                write!(f, "assuan server error {code}: {description}")
            }
        }
    }
}

impl std::error::Error for AssuanError {}

impl From<std::io::Error> for AssuanError {
    fn from(err: std::io::Error) -> Self {
        AssuanError::Io(err)
    }
}

pub struct AssuanClient {
    reader: BufReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
}

impl AssuanClient {
    /// Connects to the gpg-agent Assuan socket at `socket_path` and
    /// consumes its initial greeting line.
    pub async fn connect(socket_path: &Path) -> Result<Self, AssuanError> {
        let stream = UnixStream::connect(socket_path).await?;
        Self::from_stream(stream).await
    }

    /// Same as [`Self::connect`] but over an already-established stream;
    /// split out so tests can exercise the protocol logic over an in-memory
    /// socket pair instead of a real gpg-agent.
    async fn from_stream(stream: UnixStream) -> Result<Self, AssuanError> {
        let (read_half, write_half) = stream.into_split();
        let mut client = Self {
            reader: BufReader::new(read_half),
            writer: write_half,
        };
        client.read_greeting().await?;
        Ok(client)
    }

    async fn read_greeting(&mut self) -> Result<(), AssuanError> {
        let line = self.read_line().await?;
        match classify_line(&line) {
            LineKind::Ok => Ok(()),
            other => Err(AssuanError::Protocol(format!(
                "expected an OK greeting, got: {line:?} ({other:?})"
            ))),
        }
    }

    async fn read_line(&mut self) -> Result<String, AssuanError> {
        let mut line = String::new();
        let bytes_read = self.reader.read_line(&mut line).await?;
        if bytes_read == 0 {
            return Err(AssuanError::Protocol(
                "connection closed before a terminating status line".into(),
            ));
        }
        while line.ends_with(['\n', '\r']) {
            line.pop();
        }
        Ok(line)
    }

    async fn write_line(&mut self, line: &str) -> Result<(), AssuanError> {
        self.writer.write_all(line.as_bytes()).await?;
        self.writer.write_all(b"\n").await?;
        self.writer.flush().await?;
        Ok(())
    }

    /// Sends a no-argument command (only `LEARN` is used) and waits for the
    /// terminating `OK`/`ERR` line, transparently answering any `INQUIRE`
    /// with an empty response. Runs to true completion — see the module
    /// docs for why callers must not wrap this in `tokio::time::timeout`.
    pub async fn send_command(&mut self, command: &str) -> Result<(), AssuanError> {
        self.write_line(command).await?;

        loop {
            let line = self.read_line().await?;
            match classify_line(&line) {
                LineKind::Ok => return Ok(()),
                LineKind::Err { code, description } => {
                    return Err(AssuanError::Server { code, description });
                }
                LineKind::Inquire => self.write_line("END").await?,
                LineKind::DataStatusOrComment => {
                    // Ignored: the original Go inquiry/status callback is a
                    // no-op too, it only logs.
                }
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum LineKind {
    Ok,
    Err { code: String, description: String },
    Inquire,
    DataStatusOrComment,
}

/// Pure line classifier, kept separate from any I/O so it can be
/// exhaustively unit tested against fixture strings.
fn classify_line(line: &str) -> LineKind {
    if line == "OK" || line.starts_with("OK ") {
        return LineKind::Ok;
    }
    if line == "ERR" {
        return LineKind::Err {
            code: String::new(),
            description: String::new(),
        };
    }
    if let Some(rest) = line.strip_prefix("ERR ") {
        let mut parts = rest.splitn(2, ' ');
        let code = parts.next().unwrap_or_default().to_string();
        let description = parts.next().unwrap_or_default().to_string();
        return LineKind::Err { code, description };
    }
    if line == "INQUIRE" || line.starts_with("INQUIRE ") {
        return LineKind::Inquire;
    }
    LineKind::DataStatusOrComment
}

#[cfg(test)]
mod tests {
    use super::*;

    mod classify_line_tests {
        use super::*;

        #[test]
        fn bare_ok_is_ok() {
            assert_eq!(classify_line("OK"), LineKind::Ok);
        }

        #[test]
        fn ok_with_trailing_text_is_ok() {
            assert_eq!(classify_line("OK Pleased to meet you"), LineKind::Ok);
        }

        #[test]
        fn err_with_code_and_description() {
            assert_eq!(
                classify_line("ERR 100663404 Card error <GPG Agent>"),
                LineKind::Err {
                    code: "100663404".to_string(),
                    description: "Card error <GPG Agent>".to_string(),
                }
            );
        }

        #[test]
        fn bare_err_has_empty_code_and_description() {
            assert_eq!(
                classify_line("ERR"),
                LineKind::Err {
                    code: String::new(),
                    description: String::new(),
                }
            );
        }

        #[test]
        fn err_with_code_but_no_description() {
            assert_eq!(
                classify_line("ERR 1"),
                LineKind::Err {
                    code: "1".to_string(),
                    description: String::new(),
                }
            );
        }

        #[test]
        fn inquire_is_recognized() {
            assert_eq!(classify_line("INQUIRE KEYPARAM"), LineKind::Inquire);
            assert_eq!(classify_line("INQUIRE"), LineKind::Inquire);
        }

        #[test]
        fn data_status_and_comment_lines_are_ignored() {
            assert_eq!(
                classify_line("D some-percent-encoded-data"),
                LineKind::DataStatusOrComment
            );
            assert_eq!(
                classify_line("S KEYINFO abcdef D - - - -"),
                LineKind::DataStatusOrComment
            );
            assert_eq!(classify_line("# a comment"), LineKind::DataStatusOrComment);
        }

        #[test]
        fn strings_that_merely_contain_ok_or_err_are_not_misclassified() {
            // "OKAY" must not be treated as an OK line, and "ERRATA" must
            // not be treated as an ERR line - both require a following
            // space or exact match.
            assert_eq!(classify_line("OKAY"), LineKind::DataStatusOrComment);
            assert_eq!(classify_line("ERRATA"), LineKind::DataStatusOrComment);
        }
    }

    use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};

    /// Runs a fake Assuan server on one end of an in-memory socket pair,
    /// scripted by `server_script`, and returns the `AssuanClient` attached
    /// to the other end after a successful handshake.
    ///
    /// The script is handed a persistent reader/writer pair (rather than
    /// re-wrapping the raw stream in a fresh `BufReader` per call), since a
    /// throwaway `BufReader` can silently discard any bytes it buffered
    /// past the line it returned once dropped.
    async fn client_with_fake_server<F, Fut>(server_script: F) -> AssuanClient
    where
        F: FnOnce(FakeServerReader, FakeServerWriter) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        let (client_side, server_side) = UnixStream::pair().expect("socketpair");
        let (server_read, server_write) = server_side.into_split();
        tokio::spawn(server_script(
            tokio::io::BufReader::new(server_read),
            server_write,
        ));
        AssuanClient::from_stream(client_side)
            .await
            .expect("handshake should succeed")
    }

    type FakeServerReader = tokio::io::BufReader<OwnedReadHalf>;
    type FakeServerWriter = OwnedWriteHalf;

    async fn write_line(writer: &mut FakeServerWriter, line: &str) {
        writer.write_all(line.as_bytes()).await.unwrap();
        writer.write_all(b"\n").await.unwrap();
    }

    async fn read_line(reader: &mut FakeServerReader) -> String {
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        line.trim_end().to_string()
    }

    #[tokio::test]
    async fn successful_command_returns_ok() {
        let mut client = client_with_fake_server(|mut reader, mut writer| async move {
            write_line(&mut writer, "OK Pleased to meet you").await;
            let command = read_line(&mut reader).await;
            assert_eq!(command, "LEARN");
            write_line(&mut writer, "OK").await;
        })
        .await;

        assert!(client.send_command("LEARN").await.is_ok());
    }

    #[tokio::test]
    async fn server_error_is_surfaced() {
        let mut client = client_with_fake_server(|mut reader, mut writer| async move {
            write_line(&mut writer, "OK Pleased to meet you").await;
            let _command = read_line(&mut reader).await;
            write_line(&mut writer, "ERR 100663404 Card error <GPG Agent>").await;
        })
        .await;

        let err = client.send_command("LEARN").await.unwrap_err();
        match err {
            AssuanError::Server { code, description } => {
                assert_eq!(code, "100663404");
                assert_eq!(description, "Card error <GPG Agent>");
            }
            other => panic!("expected Server error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn data_and_status_lines_before_ok_are_skipped() {
        let mut client = client_with_fake_server(|mut reader, mut writer| async move {
            write_line(&mut writer, "OK Pleased to meet you").await;
            let _command = read_line(&mut reader).await;
            write_line(&mut writer, "S KEYINFO abcdef").await;
            write_line(&mut writer, "D some-data").await;
            write_line(&mut writer, "OK").await;
        })
        .await;

        assert!(client.send_command("LEARN").await.is_ok());
    }

    #[tokio::test]
    async fn inquire_is_answered_with_empty_end() {
        let mut client = client_with_fake_server(|mut reader, mut writer| async move {
            write_line(&mut writer, "OK Pleased to meet you").await;
            let _command = read_line(&mut reader).await;
            write_line(&mut writer, "INQUIRE KEYPARAM").await;
            let answer = read_line(&mut reader).await;
            assert_eq!(answer, "END");
            write_line(&mut writer, "OK").await;
        })
        .await;

        assert!(client.send_command("LEARN").await.is_ok());
    }

    #[tokio::test]
    async fn bad_greeting_fails_the_handshake() {
        let (client_side, server_side) = UnixStream::pair().expect("socketpair");
        let (_server_read, mut server_write) = server_side.into_split();
        tokio::spawn(async move {
            write_line(&mut server_write, "ERR 1 not a greeting").await;
        });

        let result = AssuanClient::from_stream(client_side).await;
        assert!(matches!(result, Err(AssuanError::Protocol(_))));
    }

    #[tokio::test]
    async fn connection_closed_mid_response_is_a_protocol_error() {
        let mut client = client_with_fake_server(|mut reader, mut writer| async move {
            write_line(&mut writer, "OK Pleased to meet you").await;
            let _command = read_line(&mut reader).await;
            drop(writer);
        })
        .await;

        let err = client.send_command("LEARN").await.unwrap_err();
        assert!(matches!(err, AssuanError::Protocol(_)));
    }
}
