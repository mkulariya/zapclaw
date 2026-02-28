//! Telegram bot integration for ZapClaw.
//!
//! Provides whitelist-based Telegram bot control with silent drop
//! for unauthorized users. Modeled after OpenClaw's approach.

use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Mutex;
use zapclaw_core::agent::Agent;
use anyhow::{Result, Context};

const TELEGRAM_API_BASE: &str = "https://api.telegram.org";
const MAX_MESSAGE_LEN: usize = 4096;
const MAX_CONCURRENT_PER_CHAT: usize = 1;

/// Telegram API response wrapper
#[derive(Debug, Deserialize)]
struct TelegramResponse<T> {
    ok: bool,
    result: T,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct Update {
    update_id: i32,
    message: Option<Message>,
    edited_message: Option<Message>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct Message {
    message_id: i32,
    from: User,
    chat: Chat,
    #[serde(default)]
    text: Option<String>,
}

#[derive(Debug, Deserialize)]
struct User {
    id: i64,
    #[serde(default)]
    username: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct Chat {
    id: i64,
    #[serde(rename = "type")]
    chat_type: String,
}

#[derive(Debug, Serialize)]
struct SendMessageParams<'a> {
    chat_id: i64,
    text: &'a str,
}

/// Persistent state for replay prevention
#[derive(Debug, Serialize, Deserialize)]
struct TelegramState {
    last_update_id: i32,
}

impl Default for TelegramState {
    fn default() -> Self {
        Self { last_update_id: 0 }
    }
}

/// Telegram bot listener with whitelist enforcement
pub struct TelegramListener {
    token: String,
    allowed_ids: Vec<i64>,
    agent: Arc<Agent>,
    client: Client,
    state_path: PathBuf,
    state: Arc<Mutex<TelegramState>>,
    active_tasks: Arc<Mutex<HashMap<i64, usize>>>,
}

impl TelegramListener {
    pub fn new(
        token: String,
        allowed_ids: Vec<i64>,
        agent: Arc<Agent>,
        workspace: &Path,
    ) -> Result<Self> {
        let state_path = workspace.join(".telegram_state.json");
        
        // Load or create default state
        let state = if state_path.exists() {
            let content = std::fs::read_to_string(&state_path)
                .context("Failed to read Telegram state file")?;
            serde_json::from_str::<TelegramState>(&content)
                .unwrap_or_default()
        } else {
            TelegramState::default()
        };
        
        // Validate configuration
        if allowed_ids.is_empty() {
            anyhow::bail!("Telegram allowed_ids cannot be empty");
        }
        
        Ok(Self {
            token,
            allowed_ids,
            agent,
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(45))
                .build()
                .context("Failed to create HTTP client")?,
            state_path,
            state: Arc::new(Mutex::new(state)),
            active_tasks: Arc::new(Mutex::new(HashMap::new())),
        })
    }
    
    /// Main polling loop - runs forever
    pub async fn run(&self) -> Result<()> {
        log::info!("Telegram listener started ({} whitelisted users)", self.allowed_ids.len());
        
        loop {
            if let Err(e) = self.poll_once().await {
                log::error!("Telegram poll error: {}", e);
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            }
        }
    }
    
    async fn poll_once(&self) -> Result<()> {
        let offset = {
            let state = self.state.lock().await;
            state.last_update_id
        };
        
        let url = format!(
            "{}/bot{}/getUpdates?offset={}&timeout=30",
            TELEGRAM_API_BASE, self.token, offset + 1
        );
        
        let response = self.client.get(&url).send().await?;
        
        // Proper deserialization with wrapper
        let wrapper: TelegramResponse<Vec<Update>> = response.json().await
            .context("Failed to parse Telegram API response")?;
        
        if !wrapper.ok {
            anyhow::bail!("Telegram API returned error: {:?}", wrapper);
        }
        
        let updates = wrapper.result;
        
        for update in updates {
            // Issue 4: Only handle new messages, ignore edits
            let msg = update.message.as_ref();
            // edited_message is intentionally ignored to prevent re-runs
            
            if let Some(message) = msg {
                // SECURITY: Whitelist enforcement with silent drop
                if !self.allowed_ids.contains(&message.from.id) {
                    log::warn!(
                        "Blocked unauthorized Telegram user {} (@{:?})",
                        message.from.id,
                        message.from.username
                    );
                    // Silent drop - no response
                    self.save_state(update.update_id).await?;
                    continue;
                }
                
                // Check rate limit WITHOUT holding lock across await
                let is_busy = {
                    let mut active = self.active_tasks.lock().await;
                    let count = active.entry(message.chat.id).or_insert(0);
                    if *count >= MAX_CONCURRENT_PER_CHAT {
                        true
                    } else {
                        *count += 1;
                        false
                    }
                };
                
                let chat_id = message.chat.id;
                
                if is_busy {
                    // Lock already released after is_busy block
                    self.send_message(
                        chat_id,
                        "⏳ Previous task still running. Please wait."
                    ).await.ok();
                    
                    self.save_state(update.update_id).await?;
                    continue;
                }
                
                // Clone text to own the data
                let text = message.text.clone().unwrap_or_default();
                
                let agent = self.agent.clone();
                let active_tasks = self.active_tasks.clone();
                let client = self.client.clone();
                let token = self.token.clone();
                
                // Send response back to user
                tokio::spawn(async move {
                    let result = agent.run(&chat_id.to_string(), &text).await;
                    
                    // Decrement active task count
                    {
                        let mut active = active_tasks.lock().await;
                        if let Some(count) = active.get_mut(&chat_id) {
                            if *count > 0 {
                                *count -= 1;
                            }
                        }
                    }
                    
                    match result {
                        Ok(response) => {
                            // Send response back to Telegram
                            if let Err(e) = send_chunked(&client, &token, chat_id, &response).await {
                                log::error!("Failed to send Telegram response: {}", e);
                            }
                        }
                        Err(e) => {
                            let error_msg = format!("❌ Error: {}", e);
                            if let Err(e) = send_single(&client, &token, chat_id, &error_msg).await {
                                log::error!("Failed to send error message: {}", e);
                            }
                        }
                    }
                });
            }
            
            self.save_state(update.update_id).await?;
        }
        
        Ok(())
    }
    
    async fn send_message(&self, chat_id: i64, text: &str) -> Result<()> {
        send_chunked(&self.client, &self.token, chat_id, text).await
    }
    
    async fn save_state(&self, update_id: i32) -> Result<()> {
        let mut state = self.state.lock().await;
        if update_id > state.last_update_id {
            state.last_update_id = update_id;
            
            let json = serde_json::to_string_pretty(&*state)
                .context("Failed to serialize Telegram state")?;
            std::fs::write(&self.state_path, json)
                .context("Failed to save Telegram state file")?;
        }
        Ok(())
    }
}

/// Helper function to send chunked messages (outside struct for tokio::spawn)
async fn send_chunked(
    client: &Client,
    token: &str,
    chat_id: i64,
    text: &str,
) -> Result<()> {
    if text.len() <= MAX_MESSAGE_LEN {
        send_single(client, token, chat_id, text).await
    } else {
        for chunk in split_message(text, MAX_MESSAGE_LEN) {
            send_single(client, token, chat_id, &chunk).await?;
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }
        Ok(())
    }
}

/// Helper function to send a single message
async fn send_single(
    client: &Client,
    token: &str,
    chat_id: i64,
    text: &str,
) -> Result<()> {
    let url = format!("{}/bot{}/sendMessage", TELEGRAM_API_BASE, token);
    
    // Send plain text (no parse_mode to avoid HTML escaping issues)
    let params = SendMessageParams {
        chat_id,
        text,
    };
    
    let response = client
        .post(&url)
        .json(&params)
        .send()
        .await?;
    
    if !response.status().is_success() {
        let error_text = response.text().await.unwrap_or_default();
        anyhow::bail!("Telegram API error: {}", error_text);
    }
    
    Ok(())
}

/// Split text into chunks respecting word boundaries
fn split_message(text: &str, max_len: usize) -> Vec<String> {
    let mut chunks = Vec::new();
    let mut current = String::new();
    
    for line in text.lines() {
        if !current.is_empty() && current.len() + line.len() + 1 > max_len {
            chunks.push(current.clone());
            current = String::new();
        }
        
        // Handle single line longer than max_len
        if line.len() > max_len {
            if !current.is_empty() {
                chunks.push(current.clone());
                current = String::new();
            }
            
            for chunk in line.as_bytes().chunks(max_len) {
                chunks.push(String::from_utf8_lossy(chunk).to_string());
            }
            continue;
        }
        
        if !current.is_empty() {
            current.push('\n');
        }
        current.push_str(line);
    }
    
    if !current.is_empty() {
        chunks.push(current);
    }
    
    chunks
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_split_message_short() {
        let text = "Hello, world!";
        let chunks = split_message(text, 4096);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0], text);
    }
    
    #[test]
    fn test_split_message_over_limit() {
        let text = "a".repeat(5000);
        let chunks = split_message(&text, 4096);
        assert!(chunks.len() >= 2);
        assert!(chunks.iter().all(|c| c.len() <= 4096));
        let reconstructed = chunks.concat();
        assert_eq!(reconstructed.len(), 5000);
    }
    
    #[test]
    fn test_telegram_response_deserialization() {
        let json = r#"{"ok":true,"result":[{"update_id":1,"message":{"message_id":1,"from":{"id":123456},"chat":{"id":123456,"type":"private"},"text":"hello"}}]}"#;
        let response: TelegramResponse<Vec<Update>> = serde_json::from_str(json).unwrap();
        assert!(response.ok);
        assert_eq!(response.result.len(), 1);
        assert_eq!(response.result[0].update_id, 1);
    }
    
    #[test]
    fn test_state_default() {
        let state = TelegramState::default();
        assert_eq!(state.last_update_id, 0);
    }
}
