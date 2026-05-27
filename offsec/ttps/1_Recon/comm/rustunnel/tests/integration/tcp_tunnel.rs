//! TCP tunnel end-to-end integration test.
//!
//! # What this tests
//!
//! Full TCP proxy chain:
//!   Public TCP client
//!     → rustunnel TCP edge (dynamic port listener)
//!       → yamux stream (injected directly via `core.resolve_pending_conn`)
//!         → local TCP echo server
//!
//! Same yamux injection strategy as the HTTP tests.

#[path = "../common/mod.rs"]
mod common;

use std::net::SocketAddr;

use common::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::oneshot;

// ── local TCP echo server ─────────────────────────────────────────────────────

async fn start_echo_server() -> (SocketAddr, oneshot::Sender<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind echo server");
    let addr = listener.local_addr().unwrap();

    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                result = listener.accept() => {
                    let Ok((mut stream, _)) = result else { break };
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 4096];
                        loop {
                            let n = match stream.read(&mut buf).await {
                                Ok(0)  => break,          // EOF
                                Ok(n)  => n,
                                Err(_) => break,
                            };
                            if stream.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    });
                }
            }
        }
    });

    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    (addr, shutdown_tx)
}

// ── main test ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn tcp_tunnel_echoes_data() {
    init_tracing();

    // 1. Start the local echo server.
    let (local_addr, _echo_shutdown) = start_echo_server().await;

    // 2. Start the rustunnel server.
    let server = TestServer::start().await;

    // 3. Connect client and register a TCP tunnel.
    let mut client = TestClient::connect(&server).await.expect("auth");
    let session_id = client.session_id.unwrap();
    let (_tunnel_id, assigned_port) = client
        .register_tcp_tunnel()
        .await
        .expect("TCP tunnel registration");

    // 4. Connect the data WebSocket bridge and wait for it to be ready.
    connect_data_bridge(&server, session_id, local_addr)
        .await
        .expect("data bridge ready");

    // 5. Connect to the assigned TCP port on the server.
    let tunnel_addr: SocketAddr = format!("127.0.0.1:{assigned_port}").parse().unwrap();
    let mut conn = tokio::net::TcpStream::connect(tunnel_addr)
        .await
        .expect("connect to tunnel TCP port");

    // 6. Send "ping" and read back the echo.
    conn.write_all(b"ping").await.expect("write ping");

    let mut response = vec![0u8; 4];
    conn.read_exact(&mut response).await.expect("read echo");

    assert_eq!(&response, b"ping", "echo server should return exact bytes");
}

// ── echo with larger payload ──────────────────────────────────────────────────

#[tokio::test]
async fn tcp_tunnel_echoes_larger_payload() {
    init_tracing();

    let (local_addr, _echo_shutdown) = start_echo_server().await;
    let server = TestServer::start().await;

    let mut client = TestClient::connect(&server).await.expect("auth");
    let session_id = client.session_id.unwrap();
    let (_, assigned_port) = client.register_tcp_tunnel().await.expect("register");

    connect_data_bridge(&server, session_id, local_addr)
        .await
        .expect("data bridge ready");

    let mut conn = tokio::net::TcpStream::connect(
        format!("127.0.0.1:{assigned_port}")
            .parse::<SocketAddr>()
            .unwrap(),
    )
    .await
    .expect("connect");

    // 1 KB of data.
    let payload: Vec<u8> = (0u8..255).cycle().take(1024).collect();
    conn.write_all(&payload).await.expect("write");

    let mut echoed = vec![0u8; 1024];
    conn.read_exact(&mut echoed).await.expect("read");

    assert_eq!(echoed, payload, "echo payload must match");
}

// ── TCP port is assigned from the configured range ────────────────────────────

#[tokio::test]
async fn tcp_tunnel_port_in_configured_range() {
    init_tracing();
    let server = TestServer::start().await;
    let [low, high] = server.config.limits.tcp_port_range;

    let mut client = TestClient::connect(&server).await.expect("auth");
    let (_, port) = client.register_tcp_tunnel().await.expect("register");

    assert!(
        port >= low && port <= high,
        "assigned port {port} outside range [{low}, {high}]"
    );
}

// ── second tunnel gets a different port ───────────────────────────────────────

#[tokio::test]
async fn two_tcp_tunnels_get_distinct_ports() {
    init_tracing();
    let server = TestServer::start().await;

    let mut client = TestClient::connect(&server).await.expect("auth");
    let (_, port1) = client.register_tcp_tunnel().await.expect("tunnel 1");
    let (_, port2) = client.register_tcp_tunnel().await.expect("tunnel 2");

    assert_ne!(port1, port2, "each TCP tunnel must get a unique port");
}

// ── TCP tunnel sends "ping" and receives exactly "ping" ────────────────────────
// (alias for the main test, easier to grep for)

#[tokio::test]
async fn ping_pong_through_tcp_tunnel() {
    init_tracing();

    let (local_addr, _echo_shutdown) = start_echo_server().await;
    let server = TestServer::start().await;

    let mut client = TestClient::connect(&server).await.expect("auth");
    let session_id = client.session_id.unwrap();
    let (_, port) = client.register_tcp_tunnel().await.expect("register");

    connect_data_bridge(&server, session_id, local_addr)
        .await
        .expect("data bridge ready");

    let mut conn =
        tokio::net::TcpStream::connect(format!("127.0.0.1:{port}").parse::<SocketAddr>().unwrap())
            .await
            .expect("connect to tunnel port");

    conn.write_all(b"ping").await.expect("write");
    let mut buf = [0u8; 4];
    conn.read_exact(&mut buf).await.expect("read");

    assert_eq!(&buf, b"ping");
}
