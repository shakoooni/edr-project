# ultra_edr

Ultra-lightweight, secure, local-only, memory-focused endpoint detection and response (EDR) system in pure Rust.

## Features
- Modular async architecture
- Memory-first detection (Linux/Windows)
- No UI, no telemetry, no web
- Works offline, low-end system support
- Secure-by-default, nation-state quality

## Crate Structure
- `agent`: Async scan orchestrator
- `process`: Cross-platform memory scanner (FFI, safe wrappers)
- `carving`: Dumps/encrypts high-risk memory
- `triage`: Risk scoring/classification
- `scheduler`: Async job queue
- `utils`: Shared errors, encryption, logging

## Usage
- Configure via `configs/config.toml`
- Run with your own integration (no binaries provided)


## Security & Hardening
- No `unwrap()`, no `panic!`, explicit error handling
- AES-GCM encryption for dumps
- Binary, redacted logs
- **Stack allocation** for hot-path buffers (no heap for small/medium regions)
- **Self-integrity/anti-tamper**: agent validates its own binary hash at startup
- **Stealth**: process renaming (Linux), randomized scan intervals
- **Anti-debugging**: exits if debugger detected (Linux TracerPid)
- **Anti-VM**: exits if VM detected (DMI/cpuinfo heuristics)

## Development
- `cargo test` for unit tests
- `cargo miri test`, `cargo fuzz`, `cargo flamegraph`, `valgrind` for advanced checks


## Threat Model
- **Adversary**: Nation-state, APT, or advanced malware with root/low-level access
- **Goals**: Prevent EDR evasion, tampering, or detection by malware
- **Assumptions**: Kernel is trusted, EDR runs as root, no remote C2
- **Non-goals**: Defend against kernel-level rootkits, physical attacks, or supply chain compromise

## Operational Stealth
- EDR agent mimics kernel worker process name
- Scan intervals are randomized to avoid timing-based detection
- No network, no telemetry, no persistent temp files

## Extensibility
- Modular crates for memory scanning, triage, carving, scheduling, and logging
- Async job queue for future expansion (e.g., file, registry, or network triage)

---
For more details, see crate-level documentation and code comments.
