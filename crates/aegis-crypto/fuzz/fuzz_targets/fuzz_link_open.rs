#![no_main]

use aegis_crypto::link::{LinkKey, LINK_FRAME_LEN};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let key = LinkKey::new([0xAB; 32]);

    let mut frame = [0u8; LINK_FRAME_LEN];
    let copy_len = data.len().min(LINK_FRAME_LEN);
    frame[..copy_len].copy_from_slice(&data[..copy_len]);
    let _ = key.open(&frame);

    // Variable-length frames must return Err, never panic.
    if !data.is_empty() {
        let short_len = data.len().min(LINK_FRAME_LEN.saturating_sub(1).max(1));
        let _ = key.open(&data[..short_len]);
    }
    if data.len() > LINK_FRAME_LEN {
        let _ = key.open(&data[..LINK_FRAME_LEN + 1]);
    }
});
