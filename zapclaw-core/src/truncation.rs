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

// ── Context Window Guard ────────────────────────────────────────────────

/// Hard block: refuse to start a run when fewer than this many tokens remain.
pub const CONTEXT_GUARD_BLOCK_REMAINING_TOKENS: usize = 16_000;

/// Soft warn: log a warning when fewer than this many tokens remain.
pub const CONTEXT_GUARD_WARN_REMAINING_TOKENS: usize = 32_000;

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

// ── Content-type detectors (private) ──────────────────────────────────

fn is_base64_like(sample: &str) -> bool {
    let s = sample.trim();
    s.len() > 50
        && s.chars().take(50).all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
        && !s.contains(' ')
        && !s.contains('\n')
}

fn is_json_like(sample: &str) -> bool {
    let s = sample.trim_start();
    (s.starts_with('{') || s.starts_with('[') || s.starts_with('"'))
        && (s.contains(':') || s.contains(','))
}

fn is_code_like(sample: &str) -> bool {
    sample.matches("=>").count()
        + sample.matches("fn ").count()
        + sample.matches("def ").count()
        + sample.matches("function ").count()
        + sample.matches("    ").count()   // 4-space indent
        + sample.matches("->").count()
        > 3
}

/// Content-aware token estimator.
/// Ratios: base64 ~1.33 ch/tok, JSON ~3 ch/tok, code ~3.5 ch/tok, prose ~4 ch/tok.
pub fn estimate_tokens(text: &str) -> usize {
    if text.is_empty() {
        return 0;
    }
    let byte_len   = text.len();
    let char_count = text.chars().count();
    let non_ascii  = byte_len.saturating_sub(char_count);
    let sample     = &text[..byte_len.min(256)];

    let base = if is_base64_like(sample) {
        (char_count * 3 + 3) / 4       // ~1.33 chars/token
    } else if is_json_like(sample) {
        (char_count + 2) / 3           // ~3 chars/token
    } else if is_code_like(sample) {
        (char_count * 2 + 6) / 7      // ~3.5 chars/token
    } else {
        (char_count + 3) / 4           // ~4 chars/token (prose default)
    };

    (base + non_ascii / 4).max(1)      // UTF-8 multi-byte overhead
}

/// Token estimate for one ChatMessage including role/structure overhead.
pub fn estimate_message_tokens(msg: &ChatMessage) -> usize {
    const ROLE_OVERHEAD: usize = 4;
    let content_tokens = estimate_tokens(&msg.content);
    let tool_tokens = msg.tool_calls.as_ref().map_or(0, |tcs| {
        tcs.iter()
            .map(|tc| {
                6 + estimate_tokens(&tc.function.name)
                    + estimate_tokens(&tc.function.arguments)
            })
            .sum::<usize>()
    });
    ROLE_OVERHEAD + content_tokens + tool_tokens
}

/// Estimate total tokens in a messages array.
pub fn estimate_messages_tokens(messages: &[ChatMessage]) -> usize {
    const REQUEST_OVERHEAD: usize = 3;
    REQUEST_OVERHEAD + messages.iter().map(estimate_message_tokens).sum::<usize>()
}

/// Result of evaluating the context window guard before a run begins.
pub struct ContextGuardResult {
    pub should_block:     bool,
    pub should_warn:      bool,
    pub estimated_tokens: usize,
    pub remaining_tokens: usize,
}

/// Evaluate context window headroom before a run begins.
pub fn evaluate_context_window_guard(
    messages: &[ChatMessage],
    context_window_tokens: usize,
) -> ContextGuardResult {
    let estimated = estimate_messages_tokens(messages);
    let remaining = context_window_tokens.saturating_sub(estimated);
    ContextGuardResult {
        should_block: remaining < CONTEXT_GUARD_BLOCK_REMAINING_TOKENS,
        should_warn:  remaining < CONTEXT_GUARD_WARN_REMAINING_TOKENS,
        estimated_tokens: estimated,
        remaining_tokens: remaining,
    }
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

    // Repair tool-call / tool-result pairing (both directions):
    // 1. Remove tool_calls entries in assistant messages with no matching tool result
    // 2. Remove tool result messages with no matching tool_call in any assistant message
    repair_orphaned_tool_uses(&mut result);
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

/// Repair orphaned tool_calls in assistant messages after truncation.
///
/// When truncation removes a `tool` result message, the corresponding
/// `tool_calls` entry in the preceding assistant message becomes orphaned —
/// the OpenAI API requires every `tool_calls` entry to have a matching
/// `tool` result, or it returns a validation error.
///
/// This function removes such orphaned entries. If an assistant message ends
/// up with an empty `tool_calls` list AND no text content, the whole message
/// is removed.
pub fn repair_orphaned_tool_uses(messages: &mut Vec<ChatMessage>) {
    use std::collections::HashSet;

    // Collect all tool_call_ids that have a matching tool result.
    let answered_ids: HashSet<String> = messages
        .iter()
        .filter(|m| m.role == "tool")
        .flat_map(|m| m.tool_call_id.iter().cloned())
        .collect();

    // For each assistant message, prune tool_calls that have no answer.
    for msg in messages.iter_mut() {
        if msg.role != "assistant" {
            continue;
        }
        if let Some(ref mut tool_calls) = msg.tool_calls {
            tool_calls.retain(|tc| answered_ids.contains(&tc.id));
            if tool_calls.is_empty() {
                msg.tool_calls = None;
            }
        }
    }

    // Remove assistant messages that are now empty (no text and no tool_calls).
    messages.retain(|m| {
        if m.role == "assistant" && m.tool_calls.is_none() && m.content.trim().is_empty() {
            return false;
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
            images: None,
        }
    }

    fn tool_msg(content: &str, call_id: &str) -> ChatMessage {
        ChatMessage {
            role: "tool".to_string(),
            content: content.to_string(),
            tool_call_id: Some(call_id.to_string()),
            tool_calls: None,
            images: None,
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
            images: None,
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
    fn test_repair_orphaned_tool_uses_removes_unmatched_call() {
        // Assistant calls [call_1, call_2] but only call_1's result is present
        let mut messages = vec![
            msg("system", "prompt"),
            msg("user", "test"),
            assistant_with_tool_calls(&["call_1", "call_2"]),
            tool_msg("result 1", "call_1"),
            // call_2 result was truncated away
        ];
        repair_orphaned_tool_uses(&mut messages);
        // call_2 should be removed from tool_calls
        let asst = messages.iter().find(|m| m.role == "assistant").unwrap();
        let tc = asst.tool_calls.as_ref().unwrap();
        assert_eq!(tc.len(), 1);
        assert_eq!(tc[0].id, "call_1");
    }

    #[test]
    fn test_repair_orphaned_tool_uses_removes_empty_assistant() {
        // Assistant has only tool_calls with no text content, and all results are gone
        let mut messages = vec![
            msg("system", "prompt"),
            msg("user", "test"),
            assistant_with_tool_calls(&["call_1"]),
            // tool result for call_1 was truncated away
        ];
        repair_orphaned_tool_uses(&mut messages);
        // Empty assistant message (no text, no remaining tool_calls) should be removed
        assert!(messages.iter().all(|m| m.role != "assistant"),
            "empty assistant message should be removed");
    }

    #[test]
    fn test_repair_orphaned_tool_uses_keeps_assistant_with_content() {
        // Assistant has text content AND tool_calls, only tool_calls removed
        let mut messages = vec![
            msg("system", "prompt"),
            msg("user", "test"),
            ChatMessage {
                role: "assistant".to_string(),
                content: "Let me think...".to_string(),
                tool_call_id: None,
                tool_calls: Some(vec![crate::llm::ToolCall {
                    id: "call_1".to_string(),
                    call_type: "function".to_string(),
                    function: crate::llm::FunctionCall {
                        name: "test".to_string(),
                        arguments: "{}".to_string(),
                    },
                }]),
                images: None,
            },
            // call_1 result is gone
        ];
        repair_orphaned_tool_uses(&mut messages);
        // Assistant message should remain (has text content), just with no tool_calls
        let asst = messages.iter().find(|m| m.role == "assistant").unwrap();
        assert!(asst.tool_calls.is_none());
        assert_eq!(asst.content, "Let me think...");
    }

    #[test]
    fn test_truncate_history_repairs_both_directions() {
        // After truncation both orphaned tool_uses and orphaned tool_results are cleaned up
        let mut messages = vec![msg("system", "System")];
        // Add many turns to force truncation
        for i in 0..20 {
            messages.push(msg("user", &format!("msg {} {}", i, "x".repeat(300))));
            messages.push(assistant_with_tool_calls(&[&format!("call_{}", i)]));
            messages.push(tool_msg(&format!("result {}", i), &format!("call_{}", i)));
        }
        let result = truncate_history(&messages, 200, 1);
        // Verify consistency: every tool msg has a matching assistant tool_call
        let answered: std::collections::HashSet<String> = result
            .iter()
            .filter(|m| m.role == "tool")
            .flat_map(|m| m.tool_call_id.iter().cloned())
            .collect();
        for m in &result {
            if let Some(ref tcs) = m.tool_calls {
                for tc in tcs {
                    assert!(answered.contains(&tc.id),
                        "tool_call {} in assistant message has no matching result", tc.id);
                }
            }
        }
    }

    #[test]
    fn test_estimate_messages_tokens() {
        let messages = vec![
            msg("system", "1234"),    // 4 chars prose
            msg("user", "12345678"), // 8 chars prose
        ];
        let tokens = estimate_messages_tokens(&messages);
        // With per-message overhead (4 each) + request overhead (3): at least 11
        assert!(tokens >= 11);
    }

    #[test]
    fn test_estimate_tokens_json_denser_than_prose() {
        let json = r#"{"key": "value", "number": 42, "arr": [1,2,3]}"#;
        // JSON ratio ~3 chars/token vs prose ~4 chars/token → more tokens for same length
        let prose_est = (json.len() + 3) / 4;
        assert!(estimate_tokens(json) >= prose_est);
    }

    #[test]
    fn test_estimate_tokens_base64_densest() {
        let b64 = "SGVsbG8gV29ybGQhIFRoaXMgaXMgYSBsb25nZXIgYmFzZTY0IHN0cmluZw==";
        // base64 ratio ~1.33 chars/token → more tokens than JSON (~3 chars/token)
        let json_est = (b64.len() + 2) / 3;
        assert!(estimate_tokens(b64) >= json_est);
    }

    #[test]
    fn test_context_guard_block() {
        let big = "x".repeat(64_000); // ~16K tokens prose
        let msgs = vec![ChatMessage {
            role: "user".to_string(),
            content: big,
            tool_call_id: None,
            tool_calls: None,
            images: None,
        }];
        let r = evaluate_context_window_guard(&msgs, 17_000);
        assert!(r.should_block);
    }

    #[test]
    fn test_context_guard_warn_not_block() {
        let medium = "x".repeat(28_000); // ~7K tokens prose
        let msgs = vec![ChatMessage {
            role: "user".to_string(),
            content: medium,
            tool_call_id: None,
            tool_calls: None,
            images: None,
        }];
        // 38K context − ~7K used = ~31K remaining → warn (< 32K), not block (> 16K)
        let r = evaluate_context_window_guard(&msgs, 38_000);
        assert!(r.should_warn);
        assert!(!r.should_block);
    }
}
