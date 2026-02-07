#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(data);

    let _ = briefcase_payments::parse_www_authenticate(&s);
    let _ = briefcase_payments::x402::decode_payment_required_b64(&s);
    let _ = briefcase_payments::x402::decode_payment_payload_b64(&s);
    let _ = briefcase_payments::x402::decode_settlement_response_b64(&s);
});

