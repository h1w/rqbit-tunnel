pub mod protocol;
#[cfg(unix)]
pub mod unix;

#[cfg(windows)]
pub mod windows;

#[cfg(all(test, unix))]
mod tests {
    use tokio::{io::AsyncWriteExt, net::UnixStream};

    use super::{
        protocol::{ServerRequest, ServerResponse},
        unix::{UnixControlClient, read_response},
    };
    use crate::runtime::server::spawn_test_server;

    #[tokio::test]
    async fn snapshot_request_round_trips_over_a_unix_socket() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("server.sock");
        let server = spawn_test_server(&socket).await;
        let response = UnixControlClient::connect(&socket)
            .await
            .unwrap()
            .request(ServerRequest::Snapshot)
            .await
            .unwrap();
        assert!(matches!(response, ServerResponse::Snapshot(_)));
        server.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn version_mismatch_returns_a_typed_error_response() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("server.sock");
        let server = spawn_test_server(&socket).await;
        let mut stream = UnixStream::connect(&socket).await.unwrap();
        let body = br#"{"protocol_version":2,"request":{"type":"snapshot"}}"#;
        stream
            .write_all(&(body.len() as u32).to_be_bytes())
            .await
            .unwrap();
        stream.write_all(body).await.unwrap();

        let response = read_response(&mut stream).await.unwrap();

        match response {
            ServerResponse::Error(error) => {
                assert_eq!(error.code, "unsupported_protocol_version");
                assert!(!error.message.is_empty());
                assert!(!error.recovery.is_empty());
            }
            other => panic!("expected a typed protocol error, got {other:?}"),
        }
        server.shutdown().await.unwrap();
    }
}
