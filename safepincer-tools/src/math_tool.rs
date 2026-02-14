use anyhow::{Context, Result};
use async_trait::async_trait;
use safepincer_core::agent::Tool;
use serde::Deserialize;

/// Secure math evaluation tool.
///
/// Evaluates mathematical expressions safely using a restricted parser.
/// Unlike OpenClaw's approach of shelling out to Python, this uses a
/// built-in Rust expression evaluator with no code execution capability.
///
/// Supports:
/// - Basic arithmetic: +, -, *, /, %, ^
/// - Parentheses
/// - Common functions: sqrt, sin, cos, tan, log, ln, abs, ceil, floor
/// - Constants: pi, e
pub struct MathTool;

#[derive(Deserialize)]
struct MathArgs {
    expression: String,
}

impl MathTool {
    pub fn new() -> Self {
        Self
    }

    /// Evaluate a mathematical expression safely.
    fn evaluate(&self, expr: &str) -> Result<f64> {
        let expr = expr.trim();

        if expr.is_empty() {
            anyhow::bail!("Empty expression");
        }

        // Security: reject anything that looks like code injection
        if expr.contains(';') || expr.contains('`') || expr.contains('$')
            || expr.contains("import") || expr.contains("exec")
            || expr.contains("eval") || expr.contains("__")
        {
            anyhow::bail!("Expression contains disallowed characters or keywords");
        }

        // Tokenize and parse
        let tokens = tokenize(expr)?;
        let mut parser = Parser::new(&tokens);
        parser.parse_expression()
    }
}

impl Default for MathTool {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Tool for MathTool {
    fn name(&self) -> &str {
        "math_eval"
    }

    fn description(&self) -> &str {
        "Evaluate a mathematical expression. Supports arithmetic (+, -, *, /, %, ^), \
         functions (sqrt, sin, cos, tan, log, ln, abs, ceil, floor), \
         and constants (pi, e). Example: 'sqrt(144) + 3^2'"
    }

    fn requires_confirmation(&self) -> bool {
        false // Math is always safe
    }

    fn parameters_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "expression": {
                    "type": "string",
                    "description": "The mathematical expression to evaluate"
                }
            },
            "required": ["expression"]
        })
    }

    async fn execute(&self, arguments: &str) -> Result<String> {
        let args: MathArgs = serde_json::from_str(arguments)
            .context("Invalid math tool arguments")?;

        let result = self.evaluate(&args.expression)?;

        // Format nicely: remove trailing zeros for integers
        if result == result.floor() && result.abs() < 1e15 {
            Ok(format!("{}", result as i64))
        } else {
            Ok(format!("{:.10}", result).trim_end_matches('0').trim_end_matches('.').to_string())
        }
    }
}

// --- Expression Parser ---

#[derive(Debug, Clone)]
enum Token {
    Number(f64),
    Plus,
    Minus,
    Multiply,
    Divide,
    Modulo,
    Power,
    LParen,
    RParen,
    Comma,
    Function(String),
}

fn tokenize(input: &str) -> Result<Vec<Token>> {
    let mut tokens = Vec::new();
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        match chars[i] {
            ' ' | '\t' | '\n' => i += 1,
            '+' => { tokens.push(Token::Plus); i += 1; }
            '-' => {
                // Handle negative numbers
                if tokens.is_empty() || matches!(tokens.last(), Some(Token::LParen) | Some(Token::Comma) | Some(Token::Plus) | Some(Token::Minus) | Some(Token::Multiply) | Some(Token::Divide) | Some(Token::Power)) {
                    // Unary minus — read the number
                    i += 1;
                    if i < chars.len() && (chars[i].is_ascii_digit() || chars[i] == '.') {
                        let start = i - 1;
                        while i < chars.len() && (chars[i].is_ascii_digit() || chars[i] == '.') {
                            i += 1;
                        }
                        let num_str: String = chars[start..i].iter().collect();
                        let num: f64 = num_str.parse().context("Invalid number")?;
                        tokens.push(Token::Number(num));
                    } else {
                        // Unary minus before a paren or function
                        tokens.push(Token::Number(-1.0));
                        tokens.push(Token::Multiply);
                    }
                } else {
                    tokens.push(Token::Minus);
                    i += 1;
                }
            }
            '*' => { tokens.push(Token::Multiply); i += 1; }
            '/' => { tokens.push(Token::Divide); i += 1; }
            '%' => { tokens.push(Token::Modulo); i += 1; }
            '^' => { tokens.push(Token::Power); i += 1; }
            '(' => { tokens.push(Token::LParen); i += 1; }
            ')' => { tokens.push(Token::RParen); i += 1; }
            ',' => { tokens.push(Token::Comma); i += 1; }
            c if c.is_ascii_digit() || c == '.' => {
                let start = i;
                while i < chars.len() && (chars[i].is_ascii_digit() || chars[i] == '.') {
                    i += 1;
                }
                let num_str: String = chars[start..i].iter().collect();
                let num: f64 = num_str.parse().context("Invalid number")?;
                tokens.push(Token::Number(num));
            }
            c if c.is_ascii_alphabetic() => {
                let start = i;
                while i < chars.len() && chars[i].is_ascii_alphanumeric() {
                    i += 1;
                }
                let name: String = chars[start..i].iter().collect();
                match name.to_lowercase().as_str() {
                    "pi" => tokens.push(Token::Number(std::f64::consts::PI)),
                    "e" => tokens.push(Token::Number(std::f64::consts::E)),
                    _ => tokens.push(Token::Function(name.to_lowercase())),
                }
            }
            c => anyhow::bail!("Unexpected character: '{}'", c),
        }
    }

    Ok(tokens)
}

struct Parser<'a> {
    tokens: &'a [Token],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(tokens: &'a [Token]) -> Self {
        Self { tokens, pos: 0 }
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn next(&mut self) -> Option<&Token> {
        let token = self.tokens.get(self.pos);
        self.pos += 1;
        token
    }

    fn parse_expression(&mut self) -> Result<f64> {
        self.parse_additive()
    }

    fn parse_additive(&mut self) -> Result<f64> {
        let mut left = self.parse_multiplicative()?;
        while let Some(token) = self.peek() {
            match token {
                Token::Plus => { self.next(); left += self.parse_multiplicative()?; }
                Token::Minus => { self.next(); left -= self.parse_multiplicative()?; }
                _ => break,
            }
        }
        Ok(left)
    }

    fn parse_multiplicative(&mut self) -> Result<f64> {
        let mut left = self.parse_power()?;
        while let Some(token) = self.peek() {
            match token {
                Token::Multiply => { self.next(); left *= self.parse_power()?; }
                Token::Divide => {
                    self.next();
                    let right = self.parse_power()?;
                    if right == 0.0 {
                        anyhow::bail!("Division by zero");
                    }
                    left /= right;
                }
                Token::Modulo => {
                    self.next();
                    let right = self.parse_power()?;
                    if right == 0.0 {
                        anyhow::bail!("Modulo by zero");
                    }
                    left %= right;
                }
                _ => break,
            }
        }
        Ok(left)
    }

    fn parse_power(&mut self) -> Result<f64> {
        let base = self.parse_unary()?;
        if let Some(Token::Power) = self.peek() {
            self.next();
            let exp = self.parse_power()?; // Right-associative
            Ok(base.powf(exp))
        } else {
            Ok(base)
        }
    }

    fn parse_unary(&mut self) -> Result<f64> {
        if let Some(Token::Minus) = self.peek() {
            self.next();
            Ok(-self.parse_primary()?)
        } else {
            self.parse_primary()
        }
    }

    fn parse_primary(&mut self) -> Result<f64> {
        match self.next().cloned() {
            Some(Token::Number(n)) => Ok(n),
            Some(Token::LParen) => {
                let val = self.parse_expression()?;
                match self.next() {
                    Some(Token::RParen) => Ok(val),
                    _ => anyhow::bail!("Expected closing parenthesis"),
                }
            }
            Some(Token::Function(name)) => {
                // Expect opening paren
                match self.next() {
                    Some(Token::LParen) => {}
                    _ => anyhow::bail!("Expected '(' after function name"),
                }
                let arg = self.parse_expression()?;
                // Check for second argument (for log base)
                let result = match name.as_str() {
                    "sqrt" => {
                        if arg < 0.0 { anyhow::bail!("sqrt of negative number"); }
                        arg.sqrt()
                    }
                    "sin" => arg.sin(),
                    "cos" => arg.cos(),
                    "tan" => arg.tan(),
                    "log" | "log10" => {
                        if arg <= 0.0 { anyhow::bail!("log of non-positive number"); }
                        arg.log10()
                    }
                    "ln" => {
                        if arg <= 0.0 { anyhow::bail!("ln of non-positive number"); }
                        arg.ln()
                    }
                    "abs" => arg.abs(),
                    "ceil" => arg.ceil(),
                    "floor" => arg.floor(),
                    "round" => arg.round(),
                    "exp" => arg.exp(),
                    _ => anyhow::bail!("Unknown function: {}", name),
                };
                match self.next() {
                    Some(Token::RParen) => Ok(result),
                    _ => anyhow::bail!("Expected closing parenthesis after function"),
                }
            }
            Some(other) => anyhow::bail!("Unexpected token: {:?}", other),
            None => anyhow::bail!("Unexpected end of expression"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eval(expr: &str) -> f64 {
        let tool = MathTool::new();
        tool.evaluate(expr).unwrap()
    }

    #[test]
    fn test_basic_arithmetic() {
        assert_eq!(eval("2 + 3"), 5.0);
        assert_eq!(eval("10 - 4"), 6.0);
        assert_eq!(eval("3 * 7"), 21.0);
        assert_eq!(eval("15 / 3"), 5.0);
        assert_eq!(eval("17 % 5"), 2.0);
    }

    #[test]
    fn test_order_of_operations() {
        assert_eq!(eval("2 + 3 * 4"), 14.0);
        assert_eq!(eval("(2 + 3) * 4"), 20.0);
    }

    #[test]
    fn test_power() {
        assert_eq!(eval("2 ^ 10"), 1024.0);
        assert_eq!(eval("3 ^ 2"), 9.0);
    }

    #[test]
    fn test_functions() {
        assert!((eval("sqrt(144)") - 12.0).abs() < 1e-10);
        assert!((eval("abs(-5)") - 5.0).abs() < 1e-10);
        assert!((eval("ceil(3.2)") - 4.0).abs() < 1e-10);
        assert!((eval("floor(3.8)") - 3.0).abs() < 1e-10);
    }

    #[test]
    fn test_constants() {
        assert!((eval("pi") - std::f64::consts::PI).abs() < 1e-10);
        assert!((eval("e") - std::f64::consts::E).abs() < 1e-10);
    }

    #[test]
    fn test_complex_expression() {
        assert!((eval("sqrt(144) + 3^2") - 21.0).abs() < 1e-10);
    }

    #[test]
    fn test_negative_numbers() {
        assert_eq!(eval("-5 + 3"), -2.0);
        assert_eq!(eval("(-3) * 2"), -6.0);
    }

    #[test]
    fn test_division_by_zero() {
        let tool = MathTool::new();
        assert!(tool.evaluate("1 / 0").is_err());
    }

    #[test]
    fn test_injection_blocked() {
        let tool = MathTool::new();
        assert!(tool.evaluate("import os; os.system('ls')").is_err());
        assert!(tool.evaluate("eval('print(1)')").is_err());
        assert!(tool.evaluate("__import__('os')").is_err());
    }

    #[tokio::test]
    async fn test_tool_execute() {
        let tool = MathTool::new();
        let args = serde_json::json!({"expression": "2 + 2"});
        let result = tool.execute(&args.to_string()).await.unwrap();
        assert_eq!(result, "4");
    }

    #[tokio::test]
    async fn test_tool_formatting() {
        let tool = MathTool::new();
        let args = serde_json::json!({"expression": "10 / 3"});
        let result = tool.execute(&args.to_string()).await.unwrap();
        assert!(result.starts_with("3.333"));
    }
}
