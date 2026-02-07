#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    use briefcase_core::util::sha256_hex_concat;
    use briefcase_core::ReceiptRecord;

    let s = String::from_utf8_lossy(data);

    if let Ok(r) = serde_json::from_str::<ReceiptRecord>(&s) {
        if let Ok(event_json) = serde_json::to_string(&r.event) {
            let _ = sha256_hex_concat(&r.prev_hash_hex, event_json.as_bytes());
        }
    }

    if let Ok(mut receipts) = serde_json::from_str::<Vec<ReceiptRecord>>(&s) {
        if receipts.len() > 1_000 {
            return;
        }
        receipts.sort_by_key(|r| r.id);

        let mut prev_hash_hex = "0".repeat(64);
        for r in receipts {
            let Ok(event_json) = serde_json::to_string(&r.event) else {
                continue;
            };
            let computed = sha256_hex_concat(&prev_hash_hex, event_json.as_bytes());
            let _ = computed == r.hash_hex;
            prev_hash_hex = r.hash_hex;
        }
    }
});

