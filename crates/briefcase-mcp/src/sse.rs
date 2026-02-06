use anyhow::Context as _;

/// Very small SSE decoder for MCP streamable HTTP.
///
/// We only care about `data:` lines and treat each blank-line-delimited SSE event
/// as a single JSON message payload.
pub fn decode_sse_events(buf: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut data_lines: Vec<&str> = Vec::new();

    for line in buf.split('\n') {
        let l = line.trim_end_matches('\r');

        if l.is_empty() {
            if !data_lines.is_empty() {
                out.push(data_lines.join("\n"));
                data_lines.clear();
            }
            continue;
        }

        // Ignore comments and unknown fields.
        if l.starts_with(':') {
            continue;
        }

        if let Some(rest) = l.strip_prefix("data:") {
            data_lines.push(rest.trim_start());
        }
    }

    if !data_lines.is_empty() {
        out.push(data_lines.join("\n"));
    }

    out
}

pub fn parse_first_json_message_from_sse(body: &str) -> anyhow::Result<serde_json::Value> {
    let events = decode_sse_events(body);
    let first = events.first().context("no sse events")?;
    serde_json::from_str(first).context("parse sse data as json")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_single_event() {
        let s = "event: message\ndata: {\"jsonrpc\":\"2.0\"}\n\n";
        let ev = decode_sse_events(s);
        assert_eq!(ev, vec!["{\"jsonrpc\":\"2.0\"}"]);
    }

    #[test]
    fn joins_multiline_data() {
        let s = "data: a\ndata: b\n\n";
        let ev = decode_sse_events(s);
        assert_eq!(ev, vec!["a\nb"]);
    }
}
