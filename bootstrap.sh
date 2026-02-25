#!/usr/bin/env bash
set -euo pipefail

# ZapClaw Bootstrap Script
# Usage: ./bootstrap.sh
# This script installs all dependencies and builds ZapClaw from source.

ZAPCLAW_VERSION="0.1.0"
OLLAMA_EMBEDDING_MODEL="nomic-embed-text:v1.5"

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

# Detect OS
detect_os() {
    case "$(uname -s)" in
        Linux)  echo "linux" ;;
        Darwin) echo "macos" ;;
        *)      echo "unknown" ;;
    esac
}

# Check if running in Termux
is_termux() {
    [ -n "${TERMUX_VERSION:-}" ]
}

# Detect architecture
detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64)  echo "x86_64" ;;
        aarch64|arm64) echo "aarch64" ;;
        *)             echo "unknown" ;;
    esac
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Install Rust toolchain
install_rust() {
    if command_exists rustc && command_exists cargo; then
        log_success "Rust toolchain already installed ($(rustc --version))"
        return 0
    fi

    log_info "Installing Rust toolchain..."
    if curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y; then
        log_success "Rust toolchain installed"
        # Source cargo environment
        source "$HOME/.cargo/env"
    else
        log_error "Failed to install Rust toolchain"
        return 1
    fi
}

# Install system dependencies
install_system_deps() {
    # Termux special case
    if is_termux; then
        log_info "Termux detected: Installing dependencies via pkg..."
        pkg install -y rust git curl build-essential
        return 0
    fi

    local os="$(detect_os)"
    
    case "$os" in
        linux)
            if command_exists apt-get; then
                log_info "Installing system dependencies via apt..."
                sudo apt-get update -qq
                sudo apt-get install -y build-essential pkg-config curl
            elif command_exists dnf; then
                log_info "Installing system dependencies via dnf..."
                sudo dnf install -y gcc gcc-c++ make pkg-config curl
            elif command_exists pacman; then
                log_info "Installing system dependencies via pacman..."
                sudo pacman -Sy --noconfirm --needed base-devel pkg-config curl
            else
                log_warn "No known package manager found. Please install build-essential, pkg-config, and curl manually."
            fi
            ;;
        macos)
            if ! command_exists xcode-select || ! xcode-select -p >/dev/null 2>&1; then
                log_info "Installing Xcode Command Line Tools..."
                xcode-select --install
            fi
            ;;
        *)
            log_warn "Unknown OS: $os. Skipping system dependencies installation."
            ;;
    esac
}

# Install Bubblewrap (required for sandbox on Linux)
install_bubblewrap() {
    local os="$(detect_os)"
    
    # Termux doesn't support Bubblewrap (kernel limitations)
    if is_termux; then
        log_warn "Bubblewrap is not available in Termux."
        log_warn "ZapClaw will use --no-sandbox mode on Android."
        return 0
    fi

    # macOS uses built-in sandbox-exec (no installation needed)
    if [ "$os" = "macos" ]; then
        log_info "macOS detected: Using built-in sandbox-exec for sandboxing."
        if [ ! -f /usr/bin/sandbox-exec ]; then
            log_warn "sandbox-exec not found. Run 'xcode-select --install' to fix."
        fi
        return 0
    fi

    # Linux: check for existing bubblewrap
    if command_exists bwrap; then
        log_success "Bubblewrap already installed ($(bwrap --version | head -1))"
        return 0
    fi

    log_info "Installing Bubblewrap (required for sandbox on Linux)..."

    case "$os" in
        linux)
            if command_exists apt-get; then
                sudo apt-get install -y bubblewrap
            elif command_exists dnf; then
                sudo dnf install -y bubblewrap
            elif command_exists pacman; then
                sudo pacman -S --noconfirm bubblewrap
            else
                log_warn "No known package manager found. Please install bubblewrap manually."
            fi
            ;;
        *)
            log_warn "Bubblewrap installation skipped for unknown OS: $os"
            ;;
    esac
}

# Install Ollama (required for indexing)
install_ollama() {
    if command_exists ollama; then
        log_success "Ollama already installed ($(ollama --version 2>&1 | head -1 || echo "version unknown"))"
        return 0
    fi

    # Termux special case - build from source
    if is_termux; then
        log_info "Termux detected: Building Ollama from source..."
        
        # Install dependencies for building Ollama
        log_info "Installing build dependencies (golang, cmake, git)..."
        pkg install -y golang cmake git curl || {
            log_error "Failed to install Termux dependencies"
            return 1
        }

        # Clone and build Ollama
        local ollama_build_dir="$(mktemp -d -t ollama-build-XXXXXX)"
        log_info "Cloning Ollama repository..."
        git clone --depth 1 https://github.com/ollama/ollama.git "$ollama_build_dir" || {
            log_error "Failed to clone Ollama repository"
            return 1
        }

        log_info "Building Ollama (this may take a while)..."
        cd "$ollama_build_dir"
        
        # Generate Go files and build
        go generate ./... || {
            log_error "Failed to generate Go files"
            return 1
        }
        
        go build . || {
            log_error "Failed to build Ollama"
            return 1
        }

        # Install to Termux bin directory
        log_info "Installing Ollama to ~/../usr/bin..."
        cp ollama ~/../usr/bin/ || {
            log_error "Failed to copy Ollama binary"
            return 1
        }

        # Cleanup
        cd - >/dev/null
        rm -rf "$ollama_build_dir"

        log_success "Ollama built and installed successfully"
        return 0
    fi

    # Standard Linux/macOS installation
    log_info "Installing Ollama (required for embeddings)..."
    if curl -fsSL https://ollama.com/install.sh | sh; then
        log_success "Ollama installed successfully"
    else
        log_error "Failed to install Ollama"
        return 1
    fi
}

# Pull Ollama embedding model (required for indexing)
pull_ollama_embedding_model() {
    if ! command_exists ollama; then
        log_warn "Ollama not found. Skipping embedding model pull."
        log_warn "You can configure a remote embedding service in zapclaw.json:"
        log_warn "  Set memory_embedding_base_url to a remote provider"
        return 0
    fi

    # Start Ollama service in background for Termux
    if is_termux; then
        log_info "Starting Ollama service in background..."
        ollama serve >/dev/null 2>&1 &
        # Wait a bit for Ollama to start
        sleep 3
    fi

    log_info "Pulling embedding model: ${OLLAMA_EMBEDDING_MODEL}..."
    if ollama pull "${OLLAMA_EMBEDDING_MODEL}"; then
        log_success "Embedding model ${OLLAMA_EMBEDDING_MODEL} pulled successfully"
    else
        log_warn "Failed to pull embedding model ${OLLAMA_EMBEDDING_MODEL}"
        log_warn "You can configure a remote embedding service later"
        return 0
    fi
}

# Build and install ZapClaw
install_zapclaw() {
    local script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    
    log_info "Building ZapClaw ${ZAPCLAW_VERSION}..."
    cd "$script_dir"

    if cargo build --release; then
        log_success "ZapClaw built successfully"
    else
        log_error "Failed to build ZapClaw"
        return 1
    fi

    log_info "Installing ZapClaw to ~/.cargo/bin..."
    if cargo install --path zapclaw-cli --force; then
        log_success "ZapClaw installed successfully"
    else
        log_error "Failed to install ZapClaw"
        return 1
    fi
}

# Verify installation
verify_installation() {
    if ! command_exists zapclaw; then
        log_error "zapclaw command not found in PATH"
        log_warn "Make sure ~/.cargo/bin is in your PATH"
        return 1
    fi

    local version
    version="$(zapclaw --version 2>&1 || echo "unknown")"
    log_success "ZapClaw ${version} installed successfully!"
}

# Print next steps
print_next_steps() {
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║          ZapClaw Installation Complete! 🦞                    ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "ZapClaw is now installed and ready to use!"
    echo ""
    echo "📝 Configuration:"
    echo "  - Config file: ~/.zapclaw/zapclaw.json (auto-created on first run)"
    echo "  - Workspace:   ./zapclaw_workspace (default)"
    echo ""
    echo "🚀 Quick Start:"
    echo ""
    echo "  1. Interactive mode (REPL):"
    echo "     ${YELLOW}zapclaw${NC}"
    echo ""
    echo "  2. Single task (requires LLM configuration):"
    echo "     ${YELLOW}ZAPCLAW_API_BASE_URL=http://localhost:11434/v1 \\${NC}"
    echo "     ${YELLOW}ZAPCLAW_MODEL=your-model \\${NC}"
    echo "     ${YELLOW}zapclaw --task \"Your task here\"${NC}"
    echo ""
    echo "  3. Using cloud LLM (e.g., OpenAI):"
    echo "     ${YELLOW}ZAPCLAW_API_BASE_URL=https://api.openai.com/v1 \\${NC}"
    echo "     ${YELLOW}ZAPCLAW_API_KEY=sk-your-key \\${NC}"
    echo "     ${YELLOW}ZAPCLAW_MODEL=gpt-4o \\${NC}"
    echo "     ${YELLOW}zapclaw --task \"Explain quantum computing\"${NC}"
    echo ""
    echo "📚 Memory & Embeddings:"
    echo "  - Embedding model: ${OLLAMA_EMBEDDING_MODEL}"
    echo "  - Hybrid search: BM25 keyword + vector embeddings"
    echo ""
    echo "🔒 Security:"
    if is_termux; then
        echo "  - Sandbox: Not available on Android (use --no-sandbox flag)"
    elif [ "$(detect_os)" = "macos" ]; then
        echo "  - Sandbox: sandbox-exec (macOS built-in, enabled by default)"
    else
        echo "  - Sandbox: Bubblewrap (Linux namespace isolation, enabled by default)"
    fi
    echo "  - Workspace confinement: All operations in ./zapclaw_workspace"
    echo "  - No delete operations: File tool supports read/write/append only"
    echo ""
    echo "📖 Documentation:"
    echo "  - README.md: Project overview and features"
    echo "  - CLAUDE.md: Developer guide"
    echo "  - Run 'zapclaw --help' for all options"
    echo ""
    echo "✨ Enjoy using ZapClaw!"
    echo ""
}

# Main installation flow
main() {
    echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}           ZapClaw Bootstrap Installer v${ZAPCLAW_VERSION}          🦞${NC}"
    echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
    echo ""

    local os="$(detect_os)"
    local arch="$(detect_arch)"
    
    log_info "Detected OS: ${os} ${arch}"
    echo ""

    # Step 1: Install Rust
    log_info "[Step 1/5] Installing Rust toolchain..."
    install_rust || exit 1
    echo ""

    # Step 2: Install system dependencies
    log_info "[Step 2/5] Installing system dependencies..."
    install_system_deps
    echo ""

    # Step 3: Install sandbox tool (Bubblewrap on Linux; sandbox-exec is built-in on macOS)
    log_info "[Step 3/5] Setting up sandbox tool..."
    install_bubblewrap
    echo ""

    # Step 4: Install Ollama and pull embedding model
    log_info "[Step 4/5] Installing Ollama and pulling embedding model..."
    install_ollama || exit 1
    pull_ollama_embedding_model || exit 1
    echo ""

    # Step 5: Build and install ZapClaw
    log_info "[Step 5/5] Building and installing ZapClaw..."
    install_zapclaw || exit 1
    echo ""

    # Verify and print next steps
    verify_installation
    print_next_steps
}

main "$@"
