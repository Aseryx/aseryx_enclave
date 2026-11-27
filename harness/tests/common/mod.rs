//! Shared test helpers.
#![allow(
    dead_code,
    reason = "each test binary uses a different part of these helpers"
)]

use aseryx_enclave_harness::engine::{Limits, NativeEngine};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread::JoinHandle;
use std::time::Duration;

/// Serves one request with `status` and `body`, then returns the request it saw.
pub fn serve_once(status: &str, body: &str) -> (String, JoinHandle<String>) {
    let (status, body) = (status.to_owned(), body.to_owned());
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let url = format!("http://{}", listener.local_addr().expect("addr"));
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let mut seen = Vec::new();
        let mut buffer = [0u8; 4096];
        loop {
            let n = stream.read(&mut buffer).expect("read");
            seen.extend_from_slice(&buffer[..n]);
            let text = String::from_utf8_lossy(&seen).to_string();
            if let Some(split) = text.find("\r\n\r\n") {
                let length: usize = text[..split]
                    .lines()
                    .find_map(|l| {
                        l.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .map(|v| v.trim().parse().expect("length"))
                    })
                    .unwrap_or(0);
                if seen.len() >= split + 4 + length {
                    break;
                }
            }
            assert!(n > 0, "the client closed before sending a full request");
        }
        let reply = format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(reply.as_bytes()).expect("write");
        String::from_utf8(seen).expect("utf8")
    });
    (url, handle)
}

/// Serves `count` requests, one per connection, answering each with what `reply` returns for its body, and returns the
/// request bodies it saw.
pub fn serve_many<F>(count: usize, reply: F) -> (String, JoinHandle<Vec<String>>)
where
    F: Fn(&str) -> (u16, String) + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let url = format!("http://{}", listener.local_addr().expect("addr"));
    let handle = std::thread::spawn(move || {
        let mut bodies = Vec::new();
        for _ in 0..count {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut seen = Vec::new();
            let mut buffer = [0u8; 4096];
            let body = loop {
                let n = stream.read(&mut buffer).expect("read");
                seen.extend_from_slice(&buffer[..n]);
                let text = String::from_utf8_lossy(&seen).to_string();
                if let Some(split) = text.find("\r\n\r\n") {
                    let length: usize = text[..split]
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(|v| v.trim().parse().expect("length"))
                        })
                        .unwrap_or(0);
                    if seen.len() >= split + 4 + length {
                        break String::from_utf8_lossy(&seen[split + 4..split + 4 + length])
                            .to_string();
                    }
                }
                assert!(n > 0, "the client closed before sending a full request");
            };
            let (status, payload) = reply(&body);
            let head = format!(
                "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                payload.len()
            );
            stream.write_all(head.as_bytes()).expect("write");
            stream.write_all(payload.as_bytes()).expect("write");
            bodies.push(body);
        }
        bodies
    });
    (url, handle)
}

/// A new empty directory under the system's temporary directory, named for the test and unique within and across
/// processes (a counter, not the clock, whose resolution lets two tests collide).
pub fn unique_dir(name: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "enclave-{name}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

/// The limits the tests run the engine under.
pub fn engine_limits() -> Limits {
    Limits {
        deadline: Duration::from_secs(120),
        hard_grace: Duration::from_secs(60),
        pass_two_budget_bytes: 256 << 20,
    }
}

/// The engine linked into this build, started with the pin it was built with.
pub fn native_engine() -> NativeEngine {
    NativeEngine::new(NativeEngine::library_sha256(), engine_limits()).expect("the engine starts")
}
