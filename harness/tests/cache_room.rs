//! The ciphertext cache checks the disk before anything is fetched: every chunk at its largest and the workload's reserve
//! must fit.

mod common;

use aseryx_enclave_harness::store::{CipherCache, DISK_RESERVE_BYTES, StoreError};
use common::unique_dir;
use std::io;

/// Exactly enough room passes, one byte less does not, and the reserve counts even for a dataset with no chunks.
#[test]
fn the_disk_must_hold_every_chunk_at_its_largest_and_the_reserve() {
    let chunk = 1u64 << 20;
    let needed = 5 * chunk + DISK_RESERVE_BYTES;
    let enough =
        CipherCache::with_free_space(&unique_dir("room-ok"), move |_| Ok(needed)).expect("cache");
    assert!(enough.ensure_room(5, chunk).is_ok());
    let short = CipherCache::with_free_space(&unique_dir("room-short"), move |_| Ok(needed - 1))
        .expect("cache");
    assert!(matches!(
        short.ensure_room(5, chunk),
        Err(StoreError::NoRoom)
    ));
    assert!(matches!(short.ensure_room(0, chunk), Ok(())));
    let empty =
        CipherCache::with_free_space(&unique_dir("room-empty"), |_| Ok(DISK_RESERVE_BYTES - 1))
            .expect("cache");
    assert!(matches!(
        empty.ensure_room(0, chunk),
        Err(StoreError::NoRoom)
    ));
}

/// A count and a size whose product overflows is refused, not wrapped into a small number.
#[test]
fn an_overflowing_size_is_refused() {
    let cache = CipherCache::with_free_space(&unique_dir("room-overflow"), |_| Ok(u64::MAX - 1))
        .expect("cache");
    assert!(matches!(
        cache.ensure_room(usize::MAX, u64::MAX),
        Err(StoreError::NoRoom)
    ));
}

/// A disk that cannot be asked is an error, not room.
#[test]
fn an_unreadable_disk_is_an_error() {
    let cache = CipherCache::with_free_space(&unique_dir("room-error"), |_| {
        Err(io::Error::other("no disk"))
    })
    .expect("cache");
    assert!(matches!(cache.ensure_room(1, 1), Err(StoreError::Cache(_))));
}

/// The real disk answers through statvfs: no disk holds the largest possible dataset.
#[test]
fn the_real_disk_is_asked() {
    let cache = CipherCache::new(&unique_dir("room-real")).expect("cache");
    assert!(matches!(
        cache.ensure_room(usize::MAX, u64::MAX),
        Err(StoreError::NoRoom)
    ));
}
