//! Fetched bytes are bounded: evidence comes from signed URLs over HTTPS only, each chunk from its own URL, and every
//! fetch of a gateway, a URL or a chunk has a size limit.

mod common;

use aseryx_enclave_harness::manifest::Chunk;
use aseryx_enclave_harness::store::{
    CipherCache, Fetcher, HttpFetcher, IpfsGateway, StoreError, UrlChunks, UrlFetcher, chunk_limit,
};
use std::collections::HashMap;
use std::sync::Mutex;

struct Recording {
    bodies: HashMap<String, Vec<u8>>,
    asked: Mutex<Vec<(String, u64)>>,
}
impl UrlFetcher for Recording {
    fn get(&self, url: &str, max_bytes: u64) -> Result<Vec<u8>, StoreError> {
        self.asked
            .lock()
            .expect("lock")
            .push((url.to_owned(), max_bytes));
        self.bodies.get(url).cloned().ok_or(StoreError::Fetch)
    }
}

fn chunk(cid: &str) -> Chunk {
    Chunk {
        cid: cid.to_owned(),
        iv: [0; 12],
    }
}

fn urls(list: &[&str]) -> Vec<String> {
    list.iter().map(|u| (*u).to_owned()).collect()
}

/// Each chunk identifier is served by the URL at its position, with the size cap.
#[test]
fn each_chunk_is_fetched_from_its_own_url_with_the_cap() {
    let source = Recording {
        bodies: HashMap::from([
            ("https://x/0".to_owned(), vec![0]),
            ("https://x/1".to_owned(), vec![1]),
        ]),
        asked: Mutex::new(Vec::new()),
    };
    let chunks = UrlChunks::new(
        &[chunk("a"), chunk("b")],
        &urls(&["https://x/0", "https://x/1"]),
        &source,
    )
    .expect("chunks");
    assert_eq!(chunks.fetch("b", 99).expect("b"), vec![1]);
    assert_eq!(chunks.fetch("a", 99).expect("a"), vec![0]);
    assert!(matches!(chunks.fetch("c", 99), Err(StoreError::Fetch)));
    assert_eq!(
        *source.asked.lock().expect("lock"),
        [
            ("https://x/1".to_owned(), 99),
            ("https://x/0".to_owned(), 99)
        ]
    );
}

/// Lists of different lengths and a repeated identifier are refused, since a chunk could then be served by another's URL.
#[test]
fn mismatched_lists_and_repeated_identifiers_are_refused() {
    let source = Recording {
        bodies: HashMap::new(),
        asked: Mutex::new(Vec::new()),
    };
    assert!(matches!(
        UrlChunks::new(
            &[chunk("a")],
            &urls(&["https://x/0", "https://x/1"]),
            &source
        ),
        Err(StoreError::Fetch)
    ));
    assert!(matches!(
        UrlChunks::new(&[chunk("a"), chunk("b")], &urls(&["https://x/0"]), &source),
        Err(StoreError::Fetch)
    ));
    assert!(matches!(
        UrlChunks::new(
            &[chunk("a"), chunk("a")],
            &urls(&["https://x/0", "https://x/1"]),
            &source
        ),
        Err(StoreError::Fetch)
    ));
}

/// Only HTTPS URLs are fetched: a plain HTTP URL is refused before any connection, and so is anything else.
#[test]
fn only_https_urls_are_fetched() {
    let (url, server) = common::serve_once("200 OK", "evidence");
    let fetcher = HttpFetcher::default();
    assert!(
        matches!(fetcher.get(&url, 100), Err(StoreError::Fetch)),
        "{url}"
    );
    for refused in ["ftp://x/y", "file:///etc/passwd", "x", "", "HTTPS://x/y"] {
        assert!(
            matches!(fetcher.get(refused, 100), Err(StoreError::Fetch)),
            "{refused}"
        );
    }
    // The plain HTTP request never reached the server: connect to it to let its thread finish
    drop(std::net::TcpStream::connect(url.trim_start_matches("http://")).expect("connect"));
    drop(server);
}

/// An HTTPS address nothing listens on is a fetch failure.
#[test]
fn an_unreachable_https_address_is_a_fetch_failure() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let url = format!("https://{}/x", listener.local_addr().expect("addr"));
    drop(listener);
    assert!(matches!(
        HttpFetcher::new().get(&url, 100),
        Err(StoreError::Fetch)
    ));
}

/// A gateway answer longer than the limit is refused, and one of exactly the limit is taken.
#[test]
fn a_gateway_answer_longer_than_the_limit_is_refused() {
    let (url, server) = common::serve_once("200 OK", "0123456789");
    assert_eq!(
        IpfsGateway::new(&url)
            .fetch("QmX", 10)
            .expect("at the limit"),
        b"0123456789"
    );
    drop(server);
    let (url, server) = common::serve_once("200 OK", "0123456789");
    assert!(matches!(
        IpfsGateway::new(&url).fetch("QmX", 9),
        Err(StoreError::Fetch)
    ));
    drop(server);
}

struct Limits(Mutex<Vec<u64>>);
impl Fetcher for Limits {
    fn fetch(&self, _: &str, max_bytes: u64) -> Result<Vec<u8>, StoreError> {
        self.0.lock().expect("lock").push(max_bytes);
        Ok(vec![0; 32])
    }
}

/// The cache passes its limit to every fetch.
#[test]
fn the_cache_gives_every_fetch_its_limit() {
    let dir = common::unique_dir("limits");
    let cache = CipherCache::new(&dir).expect("cache");
    let fetcher = Limits(Mutex::new(Vec::new()));
    cache
        .fill(&[chunk("a"), chunk("b"), chunk("c")], &fetcher, 2, 4242)
        .expect("fill");
    assert_eq!(*fetcher.0.lock().expect("lock"), [4242, 4242, 4242]);
    std::fs::remove_dir_all(dir).expect("cleanup");
}

/// The limit leaves room for what a chunk becomes: gzip of data that does not compress, plus the GCM tag.
#[test]
fn the_chunk_limit_covers_incompressible_data_and_stops_a_runaway_source() {
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Nonce};
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;
    for size in [1u64 << 10, 1 << 20, 4 << 20] {
        let mut noise = vec![0u8; usize::try_from(size).expect("size")];
        getrandom::fill(&mut noise).expect("random");
        let mut gz = GzEncoder::new(Vec::new(), Compression::fast());
        gz.write_all(&noise).expect("gzip");
        let sealed = Aes256Gcm::new((&[7u8; 32]).into())
            .encrypt(
                &Nonce::from([1u8; 12]),
                gz.finish().expect("gzip").as_slice(),
            )
            .expect("encrypt");
        let stored = u64::try_from(sealed.len()).expect("length");
        assert!(
            stored <= chunk_limit(size),
            "{size}: {stored} > {}",
            chunk_limit(size)
        );
        assert!(
            chunk_limit(size) < size + size / 8 + 8192,
            "{size}: the limit is not tight"
        );
    }
}
