<!-- Use this file to provide workspace-specific custom instructions to Copilot. For more details, visit https://code.visualstudio.com/docs/copilot/copilot-customization#_use-a-githubcopilotinstructionsmd-file -->

# Copilot Instructions for EDR Project

- All code must be modular, minimal, and secure by design.
- No unsafe Rust code unless formally verified and justified.
- All error handling must be explicit and defensive; no panics or unwraps in core logic.
- Only use dependencies with a strong security track record and minimal footprint.
- All cryptography and memory operations must be constant-time and side-channel resistant.
- All interfaces must be trait-based for testability and cross-platform support.
- All logging, config, and disk I/O must be binary, redacted, and integrity-checked.
- No telemetry, no network by default, no external calls.
- All FFI and syscalls must be validated, with strict bounds and type checks.
- All code must be fully documented and covered by tests.
