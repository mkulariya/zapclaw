use std::io::{self, Write};

/// Human-in-the-loop confirmation for sensitive actions.
///
/// Displays the proposed action and waits for user approval.
/// This is a critical security layer preventing automated execution
/// of potentially dangerous operations.
pub fn confirm_action(tool_name: &str, description: &str) -> bool {
    println!("\n🔒 ─── Confirmation Required ───────────────────────");
    println!("  Tool: {}", tool_name);
    println!("  Action: {}", description);
    println!("────────────────────────────────────────────────────");
    print!("  Proceed? [y/N]: ");
    io::stdout().flush().unwrap();

    let mut input = String::new();
    if io::stdin().read_line(&mut input).is_err() {
        return false;
    }

    let answer = input.trim().to_lowercase();
    matches!(answer.as_str(), "y" | "yes")
}

/// Auto-approve all actions (for testing or non-interactive mode).
pub fn always_approve(_tool_name: &str, _description: &str) -> bool {
    true
}
