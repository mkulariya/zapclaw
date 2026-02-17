//! DLP-style egress guard for outbound web queries.
//!
//! Prevents sensitive data from being sent via web_search or browse_url payloads.
//! Implements payload safety checks without destination allowlists.

use anyhow::{Context, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

/// Risk level for outbound web request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum EgressRiskLevel {
    Low,
    Medium,
    High,
}

/// Egress assessment result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EgressAssessment {
    pub tool_name: String,
    pub risk_level: EgressRiskLevel,
    pub signals: Vec<String>,
    pub payload_len: usize,
    pub payload_sha256_prefix: String,
    pub preview: String,
}

/// Egress guard configuration with security thresholds.
#[derive(Debug, Clone)]
pub struct EgressGuardConfig {
    pub max_search_query_chars: usize,
    pub max_url_query_chars: usize,
    pub max_param_value_chars: usize,
    pub max_base64_like_chars: usize,
    pub entropy_min_token_len: usize,
    pub entropy_threshold: f64,
    pub taint_min_chunk_chars: usize,
    pub taint_recent_output_chars_per_item: usize,
    pub taint_max_recent_items: usize,
}

impl Default for EgressGuardConfig {
    fn default() -> Self {
        Self {
            max_search_query_chars: 512,
            max_url_query_chars: 512,
            max_param_value_chars: 256,
            max_base64_like_chars: 120,
            entropy_min_token_len: 32,
            entropy_threshold: 4.0,
            taint_min_chunk_chars: 24,
            taint_recent_output_chars_per_item: 2000,
            taint_max_recent_items: 5,
        }
    }
}

/// Egress guard for web_search and browse_url tools.
pub struct EgressGuard {
    config: EgressGuardConfig,
    // Precompiled regex patterns
    api_key_pattern: Regex,
    jwt_pattern: Regex,
    private_key_pattern: Regex,
    secret_param_pattern: Regex,
}

impl EgressGuard {
    pub fn new(config: EgressGuardConfig) -> Self {
        Self {
            config,
            // API key patterns (sk-, bearer, generic tokens)
            api_key_pattern: Regex::new(
                r"(?i)(\bsk-[a-zA-Z0-9]{20,}\b|bearer\s+[a-zA-Z0-9._~+/=]{20,}|api[_-]?key\s*[:=]\s*[a-zA-Z0-9._~+/=]{20,})"
            ).expect("Invalid API key regex"),

            // JWT shape: xxxx.yyyyy.zzzzz
            jwt_pattern: Regex::new(
                r"\b[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}\b"
            ).expect("Invalid JWT regex"),

            // PEM/private key markers
            private_key_pattern: Regex::new(
                r"(?i)-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----|-----BEGIN\s+EC\s+PRIVATE\s+KEY-----"
            ).expect("Invalid private key regex"),

            // Secret field names in URL params
            secret_param_pattern: Regex::new(
                r"(?i)[&?](token|api[_-]?key|secret|password|auth|access[_-]?token|refresh[_-]?token|id[_-]?token|api[_-]?secret)\s*=\s*[^&\s]{8,}"
            ).expect("Invalid secret param regex"),
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(EgressGuardConfig::default())
    }

    /// Assess web_search tool arguments for egress risk.
    pub fn assess_web_search(
        &self,
        arguments_json: &str,
        recent_outputs: &VecDeque<String>,
    ) -> Result<EgressAssessment> {
        let args: serde_json::Value = serde_json::from_str(arguments_json)
            .context("Invalid web_search arguments JSON")?;

        let query = args.get("query")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        self.assess_search_query("web_search", query, recent_outputs)
    }

    /// Assess browse_url tool arguments for egress risk.
    pub fn assess_browse_url(
        &self,
        arguments_json: &str,
        recent_outputs: &VecDeque<String>,
    ) -> Result<EgressAssessment> {
        let args: serde_json::Value = serde_json::from_str(arguments_json)
            .context("Invalid browse_url arguments JSON")?;

        let url = args.get("url")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        self.assess_url("browse_url", url, recent_outputs)
    }

    /// Internal assessment for search queries.
    fn assess_search_query(
        &self,
        tool_name: &str,
        query: &str,
        recent_outputs: &VecDeque<String>,
    ) -> Result<EgressAssessment> {
        let mut signals = Vec::new();
        let mut risk_level = EgressRiskLevel::Low;

        // Check 1: Query length limit
        if query.len() > self.config.max_search_query_chars {
            signals.push(format!(
                "Query length {} exceeds limit {}",
                query.len(),
                self.config.max_search_query_chars
            ));
            risk_level = EgressRiskLevel::High;
        }

        // Check 2: No multiline or code fences
        if query.contains('\n') || query.contains("```") {
            signals.push("Query contains multiline content or code fences".to_string());
            risk_level = EgressRiskLevel::High;
        }

        // Check 3: Secret pattern detection
        if self.api_key_pattern.is_match(query) {
            signals.push("Query contains API key pattern".to_string());
            risk_level = EgressRiskLevel::High;
        }

        if self.jwt_pattern.is_match(query) {
            signals.push("Query contains JWT-like token".to_string());
            risk_level = EgressRiskLevel::High;
        }

        if self.private_key_pattern.is_match(query) {
            signals.push("Query contains private key marker".to_string());
            risk_level = EgressRiskLevel::High;
        }

        // Check 4: High-entropy detection
        let entropy_signals = self.detect_high_entropy(query);
        if !entropy_signals.is_empty() {
            signals.extend(entropy_signals.clone());
            if risk_level == EgressRiskLevel::Low {
                risk_level = EgressRiskLevel::Medium;
            }
        }

        // Check 5: Taint detection against recent outputs
        let taint_signals = self.detect_taint(query, recent_outputs);
        if !taint_signals.is_empty() {
            signals.extend(taint_signals);
            if risk_level == EgressRiskLevel::Low {
                risk_level = EgressRiskLevel::Medium;
            }
        }

        let payload_len = query.len();
        let payload_sha256_prefix = self.sha256_prefix(query);
        let preview = self.preview_payload(query);

        Ok(EgressAssessment {
            tool_name: tool_name.to_string(),
            risk_level,
            signals,
            payload_len,
            payload_sha256_prefix,
            preview,
        })
    }

    /// Internal assessment for URLs.
    fn assess_url(
        &self,
        tool_name: &str,
        url: &str,
        recent_outputs: &VecDeque<String>,
    ) -> Result<EgressAssessment> {
        let mut signals = Vec::new();
        let mut risk_level = EgressRiskLevel::Low;

        // Check 1: URL length limit (entire URL)
        if url.len() > self.config.max_url_query_chars {
            signals.push(format!(
                "URL length {} exceeds limit {}",
                url.len(),
                self.config.max_url_query_chars
            ));
            risk_level = EgressRiskLevel::High;
        }

        // Check 2: Secret patterns in URL
        if self.secret_param_pattern.is_match(url) {
            signals.push("URL contains secret-bearing param (token/api_key/secret/password/auth)".to_string());
            risk_level = EgressRiskLevel::High;
        }

        if self.api_key_pattern.is_match(url) {
            signals.push("URL contains API key pattern".to_string());
            risk_level = EgressRiskLevel::High;
        }

        if self.jwt_pattern.is_match(url) {
            signals.push("URL contains JWT-like token".to_string());
            risk_level = EgressRiskLevel::High;
        }

        if self.private_key_pattern.is_match(url) {
            signals.push("URL contains private key marker".to_string());
            risk_level = EgressRiskLevel::High;
        }

        // Check 3: Base64-like blobs in query params
        // Check 3: Base64-like blobs in query params
        let blob_pattern = Regex::new(
            &format!(r"[&=][a-zA-Z0-9+/]{{{},}}={{0,2}}(&|\s|$)", self.config.max_base64_like_chars)
        ).expect("Invalid base64 blob regex");
        if blob_pattern.is_match(url) {
            signals.push(format!(
                "URL contains base64-like blob exceeding {} chars in param",
                self.config.max_base64_like_chars
            ));
            risk_level = EgressRiskLevel::High;
        }

        // Check 4: Param value length limits
        if let Err(e) = self.validate_param_lengths(url) {
            signals.push(e.to_string());
            if risk_level == EgressRiskLevel::Low {
                risk_level = EgressRiskLevel::Medium;
            }
        }

        // Check 5: High entropy in param values
        let entropy_signals = self.detect_high_entropy(url);
        if !entropy_signals.is_empty() {
            signals.extend(entropy_signals);
            if risk_level == EgressRiskLevel::Low {
                risk_level = EgressRiskLevel::Medium;
            }
        }

        // Check 6: Taint detection
        let taint_signals = self.detect_taint(url, recent_outputs);
        if !taint_signals.is_empty() {
            signals.extend(taint_signals);
            if risk_level == EgressRiskLevel::Low {
                risk_level = EgressRiskLevel::Medium;
            }
        }

        let payload_len = url.len();
        let payload_sha256_prefix = self.sha256_prefix(url);
        let preview = self.preview_payload(url);

        Ok(EgressAssessment {
            tool_name: tool_name.to_string(),
            risk_level,
            signals,
            payload_len,
            payload_sha256_prefix,
            preview,
        })
    }

    /// Detect high-entropy tokens in text.
    fn detect_high_entropy(&self, text: &str) -> Vec<String> {
        let mut signals = Vec::new();

        // Tokenize by non-alphanumeric separators
        let tokens: Vec<&str> = text.split(|c: char| !c.is_alphanumeric())
            .filter(|t| t.len() >= self.config.entropy_min_token_len)
            .collect();

        for token in tokens {
            let entropy = shannon_entropy(token);
            if entropy >= self.config.entropy_threshold {
                signals.push(format!(
                    "High-entropy token detected (entropy={:.2}, len={})",
                    entropy,
                    token.len()
                ));
            }
        }

        signals
    }

    /// Detect taint overlap with recent tool outputs.
    fn detect_taint(&self, payload: &str, recent_outputs: &VecDeque<String>) -> Vec<String> {
        let mut signals = Vec::new();

        let normalized_payload = payload.to_lowercase();

        // Check recent outputs (truncated)
        for (idx, output) in recent_outputs.iter().enumerate().take(self.config.taint_max_recent_items) {
            let truncated = if output.len() > self.config.taint_recent_output_chars_per_item {
                &output[..self.config.taint_recent_output_chars_per_item]
            } else {
                output
            };

            // Skip if output is too small to meet taint_min_chunk_chars threshold
            if truncated.len() < self.config.taint_min_chunk_chars {
                continue;
            }

            let normalized_output = truncated.to_lowercase();

            // Check for exact substring overlap (must meet minimum chunk size)
            if normalized_payload.contains(normalized_output.as_str())
                || normalized_output.contains(normalized_payload.as_str())
            {
                // Verify the overlap is at least taint_min_chunk_chars
                let overlap = if normalized_payload.contains(normalized_output.as_str()) {
                    normalized_output.len()
                } else {
                    normalized_payload.len()
                };

                if overlap >= self.config.taint_min_chunk_chars {
                    signals.push(format!(
                        "Taint overlap with recent tool output #{} ({} chars)",
                        idx + 1,
                        truncated.len()
                    ));
                    continue;
                }
            }

            // Check for multi-token overlap (long tokens only)
            let payload_tokens: Vec<&str> = normalized_payload
                .split(|c: char| !c.is_alphanumeric())
                .filter(|t| t.len() >= 12)
                .collect();

            let output_tokens: Vec<&str> = normalized_output
                .split(|c: char| !c.is_alphanumeric())
                .filter(|t| t.len() >= 12)
                .collect();

            let overlap_count = payload_tokens
                .iter()
                .filter(|t| output_tokens.contains(t))
                .count();

            if overlap_count >= 2 {
                signals.push(format!(
                    "Multi-token overlap with recent tool output #{} ({} shared tokens)",
                    idx + 1,
                    overlap_count
                ));
            }
        }

        signals
    }

    /// Validate URL param value lengths.
    fn validate_param_lengths(&self, url: &str) -> Result<()> {
        if let Ok(parsed) = url::Url::parse(url) {
            for (key, value) in parsed.query_pairs() {
                if value.len() > self.config.max_param_value_chars {
                    anyhow::bail!(
                        "URL param '{}' value length {} exceeds limit {}",
                        key,
                        value.len(),
                        self.config.max_param_value_chars
                    );
                }
            }
        }
        Ok(())
    }

    /// Generate SHA256 hash prefix for audit logging.
    fn sha256_prefix(&self, data: &str) -> String {
        use sha2::Digest;
        let hash = sha2::Sha256::digest(data.as_bytes());
        format!("{:x}", hash)[..16].to_string()
    }

    /// Generate safe preview for display.
    fn preview_payload(&self, payload: &str) -> String {
        if payload.len() <= 200 {
            payload.to_string()
        } else {
            format!("{}...{}", &payload[..100], &payload[payload.len()-100..])
        }
    }

    /// Convert assessment to audit JSON (metadata only, no secrets).
    pub fn assessment_to_audit_json(&self, assessment: &EgressAssessment) -> String {
        serde_json::json!({
            "tool": assessment.tool_name,
            "risk_level": format!("{:?}", assessment.risk_level),
            "signals": assessment.signals,
            "payload_len": assessment.payload_len,
            "payload_sha256": assessment.payload_sha256_prefix,
        }).to_string()
    }
}

/// Calculate Shannon entropy of a string.
fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }

    let mut freq = [0usize; 256];
    for byte in s.bytes() {
        freq[byte as usize] += 1;
    }

    let len = s.len() as f64;
    let mut entropy = 0.0;

    for &count in freq.iter() {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_guard() -> EgressGuard {
        EgressGuard::with_defaults()
    }

    #[test]
    fn test_shannon_entropy() {
        // Low entropy (repeated chars)
        assert!(shannon_entropy("aaaa") < 2.0);
        // High entropy (random-like)
        assert!(shannon_entropy("sk-1234567890abcdefghijklmnop") > 4.0);
    }

    #[test]
    fn test_web_search_low_risk() {
        let guard = create_guard();
        let assessment = guard
            .assess_web_search(r#"{"query": "rust programming language"}"#, &VecDeque::new())
            .unwrap();

        assert_eq!(assessment.risk_level, EgressRiskLevel::Low);
        assert!(assessment.signals.is_empty());
    }

    #[test]
    fn test_web_search_secret_detected() {
        let guard = create_guard();
        let assessment = guard
            .assess_web_search(
                r#"{"query": "my api key is sk-1234567890abcdefghijklmnopqrstuvwxyz"}"#,
                &VecDeque::new(),
            )
            .unwrap();

        assert_eq!(assessment.risk_level, EgressRiskLevel::High);
        assert!(assessment
            .signals
            .iter()
            .any(|s| s.contains("API key pattern")));
    }

    #[test]
    fn test_web_search_jwt_detected() {
        let guard = create_guard();
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        let assessment = guard
            .assess_web_search(&format!(r#"{{"query": "token {}"}}"#, jwt), &VecDeque::new())
            .unwrap();

        assert_eq!(assessment.risk_level, EgressRiskLevel::High);
        assert!(assessment.signals.iter().any(|s| s.contains("JWT")));
    }

    #[test]
    fn test_web_search_multiline_blocked() {
        let guard = create_guard();
        let assessment = guard
            .assess_web_search(
                r#"{"query": "line1\nline2\nline3"}"#,
                &VecDeque::new(),
            )
            .unwrap();

        assert_eq!(assessment.risk_level, EgressRiskLevel::High);
        assert!(assessment
            .signals
            .iter()
            .any(|s| s.contains("multiline")));
    }

    #[test]
    fn test_web_search_length_exceeded() {
        let guard = create_guard();
        let long_query = "a".repeat(600);
        let assessment = guard
            .assess_web_search(&format!(r#"{{"query": "{}"}}"#, long_query), &VecDeque::new())
            .unwrap();

        assert_eq!(assessment.risk_level, EgressRiskLevel::High);
        assert!(assessment.signals.iter().any(|s| s.contains("exceeds limit")));
    }

    #[test]
    fn test_browse_url_secret_param() {
        let guard = create_guard();
        let assessment = guard
            .assess_browse_url(
                r#"{"url": "https://example.com?token=abc123def456"}"#,
                &VecDeque::new(),
            )
            .unwrap();

        assert_eq!(assessment.risk_level, EgressRiskLevel::High);
        assert!(assessment
            .signals
            .iter()
            .any(|s| s.contains("secret-bearing")));
    }

    #[test]
    fn test_browse_url_base64_blob() {
        let guard = create_guard();
        let blob = "a".repeat(120);
        let assessment = guard
            .assess_browse_url(
                &format!(r#"{{"url": "https://example.com?data={}&other=1"}}"#, blob),
                &VecDeque::new(),
            )
            .unwrap();

        assert_eq!(assessment.risk_level, EgressRiskLevel::High);
        assert!(assessment.signals.iter().any(|s| s.contains("base64-like")));
    }

    #[test]
    fn test_browse_url_param_length_exceeded() {
        let guard = create_guard();
        let long_value = "x".repeat(300);
        let assessment = guard
            .assess_browse_url(
                &format!(r#"{{"url": "https://example.com?key={}"}}"#, long_value),
                &VecDeque::new(),
            )
            .unwrap();

        assert!(assessment.risk_level >= EgressRiskLevel::Medium);
        assert!(assessment.signals.iter().any(|s| s.contains("exceeds limit")));
    }

    #[test]
    fn test_taint_detection() {
        let guard = create_guard();
        let mut recent_outputs = VecDeque::new();
        recent_outputs.push_back("my_secret_api_key_abc123xyz789".to_string()); // 32 chars, exceeds taint_min_chunk_chars=24

        let assessment = guard
            .assess_web_search(
                r#"{"query": "search for my_secret_api_key_abc123xyz789"}"#,
                &recent_outputs,
            )
            .unwrap();

        assert!(assessment.risk_level >= EgressRiskLevel::Medium);
        assert!(assessment.signals.iter().any(|s| s.contains("Taint overlap")));
    }

    #[test]
    fn test_high_entropy_detection() {
        let guard = create_guard();
        let high_entropy_token = "sk-7K8mN9pQ2rS3tU4vW5xY6zA7bC8dE9fG0hH1iI2jJ3k";

        let assessment = guard
            .assess_web_search(
                &format!(r#"{{"query": "{}"}}"#, high_entropy_token),
                &VecDeque::new(),
            )
            .unwrap();

        assert!(assessment.risk_level >= EgressRiskLevel::Medium);
        assert!(assessment
            .signals
            .iter()
            .any(|s| s.contains("High-entropy")));
    }

    #[test]
    fn test_assessment_to_audit_json() {
        let guard = create_guard();
        let assessment = guard
            .assess_web_search(r#"{"query": "test"}"#, &VecDeque::new())
            .unwrap();

        let json = guard.assessment_to_audit_json(&assessment);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["tool"], "web_search");
        assert_eq!(parsed["risk_level"], "Low");
        assert!(parsed["payload_len"].is_number());
        assert!(parsed["payload_sha256"].is_string());
        // preview should NOT be in audit JSON (metadata only)
        assert!(parsed.get("preview").is_none());
    }
}
