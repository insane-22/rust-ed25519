
# Ed25519 sign/verify — Rust example

This repository demonstrates how to generate Ed25519 keypairs, sign messages and verify signatures using `ed25519-dalek` in Rust.

## Usage

```bash
# generate a keypair
cargo run -- gen-keypair

# sign a message (inline)
cargo run -- sign <hex-private-key> --message "hello world"

# verify a signature
cargo run -- verify <hex-public-key> <hex-signature> --message "hello world"
````

You can pass file paths instead of hex strings — the CLI treats a path to an existing file as a file to read (containing hex).

## Tests

```
cargo test
```

