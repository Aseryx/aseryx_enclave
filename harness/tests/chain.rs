//! The registry record decodes exactly, and three endpoints are read under the two-answer rule.

mod common;

use aseryx_enclave_harness::chain::{
    ChainError, ChainReader, RpcChain, decode_dataset_record, encode_get_dataset,
};
use aseryx_enclave_harness::consent::{Address, Uint256};
use common::serve_many;
use serde_json::{Value, json};

const FIXTURE: &str = include_str!("fixtures/get-dataset-fuji.json");
const CONTRACT: &str = "0x5Db410D07931Efc7CF1d01545e773992Ab1988b2";
const DATASET: &str = "5daacae0e7a77a85253e78990e040197";

fn fixture() -> Value {
    serde_json::from_str(FIXTURE).expect("fixture")
}

fn raw() -> Vec<u8> {
    hex::decode(
        fixture()["raw"]
            .as_str()
            .expect("raw")
            .trim_start_matches("0x"),
    )
    .expect("hex")
}

fn word(value: u64) -> Vec<u8> {
    Uint256::from_u64(value).0.to_vec()
}

/// A record encoded the way the contract does: offset, hash, string offset, expiry, flag, string.
fn encode(hash: [u8; 32], cid: &str, expiry: u64, dropped: bool) -> Vec<u8> {
    let mut out = word(0x20);
    out.extend_from_slice(&hash);
    out.extend(word(0x80));
    out.extend(word(expiry));
    out.extend(word(u64::from(dropped)));
    out.extend(word(cid.len() as u64));
    out.extend_from_slice(cid.as_bytes());
    out.resize(out.len() + (32 - cid.len() % 32) % 32, 0);
    out
}

/// The call data equals what ethers encodes, and the answer decodes to the record the chain holds.
#[test]
fn the_call_and_the_answer_equal_what_ethers_made() {
    let f = fixture();
    let token = Uint256::from_u64(1);
    assert_eq!(
        format!("0x{}", hex::encode(encode_get_dataset(&token, DATASET))),
        f["call"].as_str().expect("call")
    );
    let record = decode_dataset_record(&raw()).expect("record");
    assert_eq!(
        record.plaintext_hash.to_string(),
        f["plaintextHash"].as_str().expect("hash")
    );
    assert_eq!(record.manifest_cid, f["manifestCid"].as_str().expect("cid"));
    assert_eq!(
        record.latest_expiry.to_string(),
        f["latestExpiry"].as_str().expect("expiry")
    );
    assert_eq!(encode([0x11; 32], "QmX", 5, false).len() % 32, 0);
    assert_eq!(decode_dataset_record(&raw()).expect("again"), record);
}

/// Names of other lengths encode with the right padding.
#[test]
fn the_call_pads_names_of_every_length() {
    for len in [0usize, 1, 31, 32, 33, 64] {
        let data = encode_get_dataset(&Uint256::from_u64(7), &"a".repeat(len));
        assert_eq!((data.len() - 4) % 32, 0, "{len}");
        assert_eq!(&data[4 + 64..4 + 96], &word(len as u64)[..]);
    }
}

/// An unregistered id is the all-zero record, and a dropped dataset is refused.
#[test]
fn an_unregistered_or_dropped_dataset_is_refused() {
    assert_eq!(
        decode_dataset_record(&encode([0; 32], "", 0, false)),
        Err(ChainError::NotRegistered)
    );
    assert_eq!(
        decode_dataset_record(&encode([7; 32], "QmDropped", 9, true)),
        Err(ChainError::Dropped)
    );
    assert!(decode_dataset_record(&encode([7; 32], "QmFine", 9, false)).is_ok());
}

/// Anything that is not exactly the encoding is malformed.
#[test]
fn malformed_answers_are_refused() {
    let good = raw();
    assert_eq!(decode_dataset_record(&[]), Err(ChainError::Malformed));
    for cut in [1usize, 31, 32, 96, 160, 192, 192 + 46 - 1] {
        assert_eq!(
            decode_dataset_record(&good[..cut]),
            Err(ChainError::Malformed),
            "cut at {cut}"
        );
    }
    let mut bad_flag = good.clone();
    bad_flag[0x20 + 96 + 31] = 2;
    assert_eq!(decode_dataset_record(&bad_flag), Err(ChainError::Malformed));
    let mut wide_expiry = good.clone();
    wide_expiry[0x20 + 64] = 1;
    assert_eq!(
        decode_dataset_record(&wide_expiry),
        Err(ChainError::Malformed)
    );
    let mut huge_offset = good.clone();
    huge_offset[0..32].copy_from_slice(&[0xff; 32]);
    assert_eq!(
        decode_dataset_record(&huge_offset),
        Err(ChainError::Malformed)
    );
    let mut huge_length = good.clone();
    huge_length[0x20 + 0x80 + 24..0x20 + 0x80 + 32].copy_from_slice(&u64::MAX.to_be_bytes());
    assert_eq!(
        decode_dataset_record(&huge_length),
        Err(ChainError::Malformed)
    );
    let mut not_utf8 = good.clone();
    let at = 0x20 + 0x80 + 32;
    not_utf8[at] = 0xff;
    assert_eq!(decode_dataset_record(&not_utf8), Err(ChainError::Malformed));
    let long = "Q".repeat(257);
    assert_eq!(
        decode_dataset_record(&encode([7; 32], &long, 9, false)),
        Err(ChainError::Malformed)
    );
}

fn rpc_reply(raw: &[u8]) -> impl Fn(&str) -> (u16, String) + Send + 'static {
    let result = format!("0x{}", hex::encode(raw));
    move |body| {
        let request: Value = serde_json::from_str(body).expect("json");
        match request["method"].as_str().expect("method") {
            "eth_chainId" => (
                200,
                json!({"jsonrpc": "2.0", "id": 1, "result": "0xa869"}).to_string(),
            ),
            _ => (
                200,
                json!({"jsonrpc": "2.0", "id": 1, "result": result}).to_string(),
            ),
        }
    }
}

fn reader(urls: &[&str]) -> RpcChain {
    RpcChain::new(Address::parse(CONTRACT).expect("address"), urls)
}

/// Three agreeing endpoints give the record, and the request names the contract and the encoded call.
#[test]
fn three_agreeing_endpoints_give_the_record() {
    let servers: Vec<_> = (0..3).map(|_| serve_many(2, rpc_reply(&raw()))).collect();
    let urls: Vec<&str> = servers.iter().map(|(u, _)| u.as_str()).collect();
    let record = reader(&urls)
        .get_dataset(&Uint256::from_u64(1), DATASET)
        .expect("record");
    assert_eq!(
        record.manifest_cid,
        "QmNnaigry3WZb1FV97KgUzQnwmwqFX9hZexYi5AXd1LpnN"
    );
    let seen = servers
        .into_iter()
        .next()
        .expect("first")
        .1
        .join()
        .expect("server");
    let call: Value = serde_json::from_str(&seen[1]).expect("json");
    assert_eq!(call["method"], "eth_call");
    assert_eq!(
        call["params"][0]["to"].as_str().expect("to").to_lowercase(),
        CONTRACT.to_lowercase()
    );
    assert_eq!(call["params"][0]["data"], fixture()["call"]);
    assert_eq!(call["params"][1], "latest");
}

type Behaviour = fn(&str) -> (u16, String);

fn fails_with_500(_: &str) -> (u16, String) {
    (500, String::new())
}
fn answers_garbage(_: &str) -> (u16, String) {
    (200, "not json".to_owned())
}
fn answers_with_an_error(_: &str) -> (u16, String) {
    (
        200,
        json!({"jsonrpc": "2.0", "id": 1, "error": {"code": -32005, "message": "limit"}})
            .to_string(),
    )
}
fn is_on_another_chain(_: &str) -> (u16, String) {
    (
        200,
        json!({"jsonrpc": "2.0", "id": 1, "result": "0x1"}).to_string(),
    )
}
fn answers_with_no_data(body: &str) -> (u16, String) {
    if body.contains("eth_chainId") {
        return (
            200,
            json!({"jsonrpc": "2.0", "id": 1, "result": "0xa869"}).to_string(),
        );
    }
    (
        200,
        json!({"jsonrpc": "2.0", "id": 1, "result": "0xzz"}).to_string(),
    )
}

/// An endpoint that fails, is on another chain or sends garbage does not deny while two others agree.
#[test]
fn one_failed_endpoint_is_ignored() {
    let behaviours: [Behaviour; 5] = [
        fails_with_500,
        answers_garbage,
        answers_with_an_error,
        is_on_another_chain,
        answers_with_no_data,
    ];
    for broken in behaviours {
        let bad = serve_many(2, broken);
        let (a, b) = (
            serve_many(2, rpc_reply(&raw())),
            serve_many(2, rpc_reply(&raw())),
        );
        let record = reader(&[bad.0.as_str(), a.0.as_str(), b.0.as_str()])
            .get_dataset(&Uint256::from_u64(1), DATASET);
        assert!(record.is_ok(), "{record:?}");
    }
}

/// Fewer than two answers is a refusal, whatever the one answer says.
#[test]
fn fewer_than_two_answers_is_a_refusal() {
    let only = serve_many(2, rpc_reply(&raw()));
    let (bad_a, bad_b) = (
        serve_many(2, fails_with_500),
        serve_many(2, is_on_another_chain),
    );
    let urls = [bad_a.0.as_str(), only.0.as_str(), bad_b.0.as_str()];
    assert_eq!(
        reader(&urls).get_dataset(&Uint256::from_u64(1), DATASET),
        Err(ChainError::TooFewAnswers)
    );
    assert_eq!(
        reader(&[]).get_dataset(&Uint256::from_u64(1), DATASET),
        Err(ChainError::TooFewAnswers)
    );
}

/// Two endpoints that answer differently deny, even with a third that agrees with one of them.
#[test]
fn endpoints_that_disagree_deny() {
    let other = encode([0x42; 32], "QmOther", 9, false);
    let (a, b, c) = (
        serve_many(2, rpc_reply(&raw())),
        serve_many(2, rpc_reply(&other)),
        serve_many(2, rpc_reply(&raw())),
    );
    let urls = [a.0.as_str(), b.0.as_str(), c.0.as_str()];
    assert_eq!(
        reader(&urls).get_dataset(&Uint256::from_u64(1), DATASET),
        Err(ChainError::Disagree)
    );
}

/// An unregistered dataset that all endpoints agree on is refused as not registered.
#[test]
fn an_unregistered_dataset_is_refused_through_the_endpoints() {
    let empty = encode([0; 32], "", 0, false);
    let servers: Vec<_> = (0..3).map(|_| serve_many(2, rpc_reply(&empty))).collect();
    let urls: Vec<&str> = servers.iter().map(|(u, _)| u.as_str()).collect();
    assert_eq!(
        reader(&urls).get_dataset(&Uint256::from_u64(9), "nothing"),
        Err(ChainError::NotRegistered)
    );
}

/// An error status is not an answer even when its body looks like one.
#[test]
fn an_error_status_with_a_plausible_body_is_not_an_answer() {
    let other = encode([0x42; 32], "QmOther", 9, false);
    let answer = rpc_reply(&other);
    let (a, b) = (
        serve_many(2, rpc_reply(&raw())),
        serve_many(2, rpc_reply(&raw())),
    );
    let unavailable = serve_many(2, move |body| (503, answer(body).1));
    let urls = [a.0.as_str(), unavailable.0.as_str(), b.0.as_str()];
    assert!(
        reader(&urls)
            .get_dataset(&Uint256::from_u64(1), DATASET)
            .is_ok()
    );
}
