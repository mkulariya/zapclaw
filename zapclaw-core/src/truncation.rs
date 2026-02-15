//! Tool result truncation + history truncation utilities.
//!
//! Matches OpenClaw's tool-result-truncation.ts and limitHistoryTurns.

use crate::llm::ChatMessage;

// ── Constants (matching OpenClaw) ───────────────────────────────────────

/// Max share of context window a single tool result may consume.
pub const MAX_TOOL_RESULT_CONTEXT_SHARE: f64 = 0.3;

/// Absolute ceiling (chars) — even with huge context windows.
pub const HARD_MAX_TOOL_RESULT_CHARS: usize = 400_000;

/// Never truncate below this many chars.
pub const MIN_KEEP_CHARS: usize = 2_000;

/// Suffix appended after truncation.
pub const TRUNCATION_SUFFIX: &str = "\n\n[Content truncated — original was too large for the model's context window. The content above is a partial view. If you need more, request specific sections or use offset/limit parameters to read smaller chunks.]";

// ── Tool Result Truncation ──────────────────────────────────────────────

/// Calculate the maximum allowed characters for a single tool result.
pub fn calculate_max_tool_result_chars(context_window_tokens: usize) -> usize {
    let max_tokens = (context_window_tokens as f64 * MAX_TOOL_RESULT_CONTEXT_SHARE) as usize;
    let max_chars = max_tokens * 4; // ~4 chars per token heuristic
    max_chars.min(HARD_MAX_TOOL_RESULT_CHARS)
}

/// Truncate a tool result string to fit within max_chars.
/// Keeps the head, tries to break at a newline boundary.
pub fn truncate_tool_result(text: &str, max_chars: usize) -> String {
    if text.len() <= max_chars {
        return text.to_string();
    }

    let keep_chars = MIN_KEEP_CHARS
        .max(max_chars.saturating_sub(TRUNCATION_SUFFIX.len()))
        .min(text.len());

    // Try to break at last newline within 80% of keep_chars
    let cut_point = text[..keep_chars]
        .rfind('\n')
        .filter(|&pos| pos > (keep_chars * 4 / 5))
        .unwrap_or(keep_chars);

    format!("{}{}", &text[..cut_point], TRUNCATION_SUFFIX)
}

// ── History Truncation ──────────────────────────────────────────────────

/// Estimate tokens from a character count (~4 chars/token).
fn estimate_tokens_from_chars(chars: usize) -> usize {
    (chars + 3) / 4
}

/// Estimate total tokens in a messages array.
pub fn estimate_messages_tokens(messages: &[ChatMessage]) -> usize {
    messages
        .iter()
        .map(|m| {
            let mut chars = m.content.len();
            if let Some(ref tc) = m.tool_calls {
                for call in tc {
                    chars += call.function.name.len() + call.function.arguments.len();
                }
            }
            estimate_tokens_from_chars(chars)
        })
        .sum()
}

/// Truncate conversation history to fit within a token budget.
///
/// Strategy (matching OpenClaw's limitHistoryTurns + repair):
/// 1. Always preserve the system prompt (first message)
/// 2. Always preserve the last `min_keep_recent` user turns + responses
/// 3. Remove oldest messages (after system prompt) first
/// 4. After truncation, repair orphaned tool results
pub fn truncate_history(
    messages: &[ChatMessage],
    max_tokens: usize,
    min_keep_recent: usize,
) -> Vec<ChatMessage> {
    let total = estimate_messages_tokens(messages);
    if total <= max_tokens || messages.len() <= 2 {
        return messages.to_vec();
    }

    // Always keep system prompt (index 0)
    let system = &messages[0];
    let rest = &messages[1..];

    // Count user messages from the end to find the keep boundary
    let mut user_count = 0;
    let mut keep_from_idx = 0; // default: keep everything
    for (i, msg) in rest.iter().enumerate().rev() {
        if msg.role == "user" {
            user_count += 1;
            if user_count >= min_keep_recent {
                keep_from_idx = i;
                break;
            }
        }
    }

    // Build result: system + messages from keep_from_idx onward
    let mut result = vec![system.clone()];
    result.extend_from_slice(&rest[keep_from_idx..]);

    // If still over budget, progressively remove from the front (after system)
    while estimate_messages_tokens(&result) > max_tokens && result.len() > 2 {
        result.remove(1);
    }

    // Repair orphaned tool results
    repair_orphaned_tool_results(&mut result);

    result
}

/// Repair orphaned tool results after truncation.
///
/// If a "tool" message references a tool_call_id that doesn't exist in any
/// preceding "assistant" message's tool_calls, remove it.
pub fn repair_orphaned_tool_results(messages: &mut Vec<ChatMessage>) {
    use std::collections::HashSet;

    let known_ids: HashSet<String> = messages
        .iter()
        .filter(|m| m.role == "assistant")
        .flat_map(|m| {
            m.tool_calls
                .as_ref()
                .map(|tc| tc.iter().map(|t| t.id.clone()).collect::<Vec<_>>())
                .unwrap_or_default()
        })
        .collect();

    messages.retain(|m| {
        if m.role == "tool" {
            if let Some(ref id) = m.tool_call_id {
                return known_ids.contains(id);
            }
        }
        true
    });
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::llm::{FunctionCall, ToolCall};

    fn msg(role: &str, content: &str) -> ChatMessage {
        ChatMessage {
            role: role.to_string(),
            content: content.to_string(),
            tool_call_id: None,
            tool_calls: None,
        }
    }

    fn tool_msg(content: &str, call_id: &str) -> ChatMessage {
        ChatMessage {
            role: "tool".to_string(),
            content: content.to_string(),
            tool_call_id: Some(call_id.to_string()),
            tool_calls: None,
        }
    }

    fn assistant_with_tool_calls(call_ids: &[&str]) -> ChatMessage {
        ChatMessage {
            role: "assistant".to_string(),
            content: String::new(),
            tool_call_id: None,
            tool_calls: Some(
                call_ids
                    .iter()
                    .map(|id| ToolCall {
                        id: id.to_string(),
                        call_type: "function".to_string(),
                        function: FunctionCall {
                            name: "test".to_string(),
                            arguments: "{}".to_string(),
                        },
                    })
                    .collect(),
            ),
        }
    }

    #[test]
    fn test_no_truncation_small() {
        let result = truncate_tool_result("hello world", 10000);
        assert_eq!(result, "hello world");
    }

    #[test]
    fn test_truncation_large() {
        let big = "x".repeat(5000);
        let result = truncate_tool_result(&big, 3000);
        assert!(result.len() < big.len());
        assert!(result.contains("[Content truncated"));
    }

    #[test]
    fn test_truncation_newline_boundary() {
        let mut text = String::new();
        for i in 0..100 {
            text.push_str(&format!("Line {}\n", i));
        }
        let result = truncate_tool_result(&text, 200);
        // Should cut at a newline, not mid-line
        let before_suffix = result.split("[Content truncated").next().unwrap();
        assert!(before_suffix.ends_with('\n'));
    }

    #[test]
    fn test_calculate_max_chars() {
        // 128K context -> 0.3 * 128000 = 38400 tokens -> 38400 * 4 = 153600 chars
        let max = calculate_max_tool_result_chars(128_000);
        assert_eq!(max, 153_600);
    }

    #[test]
    fn test_hard_max() {
        // Very large context still capped at 400K
        let max = calculate_max_tool_result_chars(2_000_000);
        assert_eq!(max, HARD_MAX_TOOL_RESULT_CHARS);
    }

    #[test]
    fn test_min_keep() {
        // Even with tiny max, should keep at least MIN_KEEP_CHARS
        let big = "x".repeat(5000);
        let result = truncate_tool_result(&big, 100);
        let before_suffix = result.split("[Content truncated").next().unwrap();
        assert!(before_suffix.len() >= MIN_KEEP_CHARS);
    }

    #[test]
    fn test_truncate_history_under_budget() {
        let messages = vec![msg("system", "You are an AI"), msg("user", "Hello")];
        let result = truncate_history(&messages, 100_000, 1);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_truncate_history_over_budget() {
        let mut messages = vec![msg("system", "System prompt")];
        // Add 50 user/assistant pairs (~long conversation)
        for i in 0..50 {
            messages.push(msg("user", &format!("Question {} {}", i, "x".repeat(200))));
            messages.push(msg("assistant", &format!("Answer {} {}", i, "x".repeat(200))));
        }
        let result = truncate_history(&messages, 500, 2);
        // Should keep system + at least recent turns
        assert!(result.len() < messages.len());
        assert_eq!(result[0].role, "system");
    }

    #[test]
    fn test_repair_orphaned_tool_results() {
        let mut messages = vec![
            msg("system", "prompt"),
            msg("user", "test"),
            assistant_with_tool_calls(&["call_1"]),
            tool_msg("result 1", "call_1"),
            tool_msg("orphan result", "call_999"), // orphaned
        ];
        repair_orphaned_tool_results(&mut messages);
        assert_eq!(messages.len(), 4); // orphan removed
        assert!(messages.iter().all(|m| {
            if m.role == "tool" {
                m.tool_call_id.as_deref() == Some("call_1")
            } else {
                true
            }
        }));
    }

    #[test]
    fn test_estimate_messages_tokens() {
        let messages = vec![
            msg("system", "1234"), // 4 chars = ~1 token
            msg("user", "12345678"), // 8 chars = ~2 tokens
        ];
        let tokens = estimate_messages_tokens(&messages);
        assert!(tokens >= 2);
    }
}
