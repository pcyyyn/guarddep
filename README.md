First, I'm sorry!

# GuardDep
A lightweight supply chain security scanner written in Rust. Detects known vulnerabilities in project dependencies via OSV (Open Source Vulnerabilities) database.

## Features
- **Lightweight**: Single binary, no external dependencies
- **Fast**: Concurrent scanning with connection reuse  
- **Memory Safe**: Zero unsafe Rust code
- **CI/CD Ready**: Exit code 1 on critical vulnerabilities

## Supported Ecosystems
- [x] NPM (Node.js)
- [ ] Python (Planned)
- [ ] Rust/Cargo (Planned)

## Installation

```bash
git clone https://github.com/pcyyyn/guarddep.git
cd guarddep
cargo build --release

Usage
# Scan current directory
./target/release/guarddep

# Scan specific path
./target/release/guarddep /path/to/project

# Show only high/critical severity
./target/release/guarddep --severity High
