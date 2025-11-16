# Secure Client-Server Communication Example

This project demonstrates a secure communication protocol between a client and server using symmetric cryptography (AES-GCM) and HMAC-based authentication. All code is pure Dart and uses the [pointycastle](https://pub.dev/packages/pointycastle) cryptography library.

## Protocol Overview

1. **Handshake**
   - The client sends its username and a random 16-byte nonce.
   - The server replies with a random 8-byte session nonce.
   - Both sides derive a pre-shared key (PSK) using PBKDF2 (with device salt, username, and password).
   - Both sides derive a session key using HMAC-SHA256 over the concatenated nonces.
   - The client sends an HMAC for authentication; the server verifies it and replies with its own HMAC.
   - If authentication fails, the connection is closed.

2. **Message Exchange**
   - All messages are encrypted using AES-GCM with the session key.
   - Each message uses a unique 12-byte nonce (8 bytes from the session, 4 bytes as a counter).
   - The client sends encrypted messages to the server.
   - The server replies to each message with its own encrypted response, using a new random 12-byte nonce for each.
   - Each encrypted server response is prefixed with a 2-byte big-endian length for robust parsing.

## Security Details

- **Key Derivation:**
  - PBKDF2 with 600,000 iterations, SHA-256, and a salt of deviceSalt + username.
  - Session key is derived using HMAC-SHA256 over the concatenated client and server nonces.

- **Authentication:**
  - Both client and server authenticate each other using HMACs over the handshake data.

- **Encryption:**
  - AES-GCM (Galois/Counter Mode) is used for authenticated encryption.
  - Each message uses a unique nonce to ensure security.

- **Replay Protection:**
  - Each message includes a counter in the nonce; the server tracks the last seen counter to prevent replay attacks.

- **Message Framing:**
  - Server responses are length-prefixed to allow the client to parse multiple responses in a single TCP packet.

For more details on the security considerations and best practices, refer to the [Security Documentation](SECURITY.md).

---

## ✅ Highlights & Security Features

- **PSK derived with PBKDF2-HMAC-SHA256, 600k iterations.**
- **Mutual authentication via HMAC during handshake.**
- **AES‑GCM encryption with 12-byte nonce (8-byte session + 4-byte counter).**
- **Replay protection using per-session counter.**

---

## AI Contribution

This project was entirely created with the assistance of AI models, guided solely by human-provided prompts. The code, documentation, and design were generated collaboratively between the user and AI tools.

---

## Running the Example

1. Start the server:
   ```sh
   dart run cserver.dart
   ```
2. In another terminal, run the client:
   ```sh
   dart run cclient.dart
   ```

You will see debug output showing the handshake, encrypted message exchange, and decrypted responses.

## Files
- `cclient.dart`: Secure client implementation
- `cserver.dart`: Secure server implementation
- `crypto_utils.dart`: Cryptographic utility functions

## Dependencies
- Dart SDK >=2.12.0 <4.0.0
- pointycastle: ^3.7.3

---
**Note:** This example is for educational purposes. In production, always use established libraries and protocols for secure communication.
