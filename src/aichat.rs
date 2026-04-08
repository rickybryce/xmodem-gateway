//! AI Chat via the Groq API.
//!
//! Sends user questions to the Groq API (OpenAI-compatible endpoint) and
//! returns the text response. Uses a blocking HTTP client (`ureq`) which
//! should be called from `tokio::task::spawn_blocking()`.

use std::io::Read;

const API_TIMEOUT_SECS: u64 = 30;
const GROQ_MODEL: &str = "llama-3.3-70b-versatile";

/// Send a question to the Groq API and return the response text.
pub(crate) fn ask(api_key: &str, question: &str) -> Result<String, String> {
    let url = "https://api.groq.com/openai/v1/chat/completions";

    let request_body = serde_json::json!({
        "model": GROQ_MODEL,
        "messages": [
            {"role": "user", "content": question}
        ]
    });

    let agent = ureq::Agent::new_with_config(
        ureq::config::Config::builder()
            .timeout_global(Some(std::time::Duration::from_secs(API_TIMEOUT_SECS)))
            .build(),
    );

    let response = agent
        .post(url)
        .header("Content-Type", "application/json")
        .header("Authorization", &format!("Bearer {}", api_key))
        .send(serde_json::to_string(&request_body).map_err(|e| format!("JSON serialize error: {}", e))?.as_bytes())
        .map_err(|e| format!("API error: {}", e))?;

    let mut body_bytes = Vec::new();
    response
        .into_body()
        .as_reader()
        .take(1024 * 1024)
        .read_to_end(&mut body_bytes)
        .map_err(|e| format!("Read error: {}", e))?;

    let json: serde_json::Value =
        serde_json::from_slice(&body_bytes).map_err(|e| format!("JSON parse error: {}", e))?;

    json.get("choices")
        .and_then(|c| c.get(0))
        .and_then(|c| c.get("message"))
        .and_then(|m| m.get("content"))
        .and_then(|t| t.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| {
            if let Some(err) = json
                .get("error")
                .and_then(|e| e.get("message"))
                .and_then(|m| m.as_str())
            {
                format!("Groq error: {}", err)
            } else {
                "No response from Groq".to_string()
            }
        })
}

/// Word-wrap a single line to fit within `width` columns, breaking at spaces.
pub(crate) fn wrap_line(line: &str, width: usize) -> Vec<String> {
    if line.is_empty() {
        return vec![String::new()];
    }
    if line.chars().count() <= width {
        return vec![line.to_string()];
    }
    let mut result = Vec::new();
    let mut remaining = line;
    while !remaining.is_empty() {
        if remaining.chars().count() <= width {
            result.push(remaining.to_string());
            break;
        }
        let boundary = remaining
            .char_indices()
            .nth(width)
            .map_or(remaining.len(), |(i, _)| i);
        let boundary = if boundary == 0 {
            remaining
                .char_indices()
                .nth(1)
                .map_or(remaining.len(), |(i, _)| i)
        } else {
            boundary
        };
        let break_at = remaining[..boundary].rfind(' ').unwrap_or(boundary);
        let break_at = if break_at == 0 { boundary } else { break_at };
        result.push(remaining[..break_at].to_string());
        remaining = remaining[break_at..].trim_start();
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_timeout_is_reasonable() {
        assert!(API_TIMEOUT_SECS >= 10, "too short for LLM response");
        assert!(API_TIMEOUT_SECS <= 120, "too long to wait");
    }

    #[test]
    fn test_wrap_line_short() {
        assert_eq!(wrap_line("hello", 40), vec!["hello"]);
    }

    #[test]
    fn test_wrap_line_empty() {
        assert_eq!(wrap_line("", 40), vec![""]);
    }

    #[test]
    fn test_wrap_line_long() {
        let lines = wrap_line("the quick brown fox jumps over the lazy dog", 20);
        assert!(lines.len() > 1);
        for line in &lines {
            assert!(line.len() <= 20, "line too long: '{}'", line);
        }
    }

    #[test]
    fn test_wrap_line_exact() {
        assert_eq!(wrap_line("1234567890", 10), vec!["1234567890"]);
    }

    #[test]
    fn test_wrap_line_no_spaces() {
        let lines = wrap_line("abcdefghijklmnopqrstuvwxyz", 10);
        assert!(lines.len() > 1);
    }

    #[test]
    fn test_wrap_line_preserves_words() {
        let lines = wrap_line("hello world foo bar", 12);
        assert_eq!(lines[0], "hello world");
        assert_eq!(lines[1], "foo bar");
    }

    #[test]
    fn test_wrap_line_petscii_width() {
        let text = "This is a test of the PETSCII word wrapping at 38 columns wide";
        let lines = wrap_line(text, 38);
        for line in &lines {
            assert!(line.len() <= 38, "line '{}' exceeds 38 chars", line);
        }
    }
}
