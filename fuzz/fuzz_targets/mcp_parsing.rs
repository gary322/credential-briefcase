#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(data);

    let _ = briefcase_mcp::decode_sse_events(&s);
    let _ = briefcase_mcp::parse_first_json_message_from_sse(&s);
    let _ = serde_json::from_str::<briefcase_mcp::JsonRpcMessage>(&s);
});

