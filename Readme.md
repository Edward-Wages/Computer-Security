# Computer Security Final Project

## Secure Instant Point-to-Point (P2P) Messaging

## Project Layout

### SharedPassword/
```text
SharedPassword/
├── server.py             # TCP relay server for exactly two clients
├── client.py             # Original version that uses a shared password/key
└── client_custom_enc.py  # Original Bonus 1 custom-encryption version
```

### Bonus2-KeyEnc/
```text
Bonus2-KeyEnc/
├── server.py                 # TCP relay server for exactly two clients
├── client.py                 # Bonus 2 client with authenticated key exchange
├── client_custom_enc.py      # Bonus 1 custom-encryption client with Bonus 2 key exchange
├── trusted_identities.json   # Local trust store created after first contact
└── *_ed25519.pem             # Local identity keys created per username
```

## How the Two Versions Differ

- `SharedPassword` is the original version that uses a shared key/password-based setup.
- `Bonus2-KeyEnc` is the updated version that uses authenticated key establishment with long-term Ed25519 identity keys and ephemeral X25519 exchange.
- Do not mix files from the two folders in the same run.

## Setup: Python Environment and Dependencies

1. Create a virtual environment (if not already created):

   ```bash
   python -m venv .venv
   ```

2. Activate the virtual environment:

   **Windows (PowerShell):**
   ```bash
   .\.venv\Scripts\Activate.ps1
   ```

   **Windows (Command Prompt):**
   ```bash
   .venv\Scripts\activate.bat
   ```

   **macOS/Linux:**
   ```bash
   source .venv/bin/activate
   ```

3. Install required dependencies:

   ```bash
   pip install cryptography
   ```

## Run Instructions for SharedPassword

1. Open three terminals in the `SharedPassword` folder.
2. Start the server:

   ```bash
   python server.py
   ```

3. Start two clients:

   ```bash
   python client.py Alice
   python client.py Bob
   ```

4. Type a message in one window and click Send. The other window will display the received ciphertext and decrypted plaintext.

## Run Instructions for Bonus2-KeyEnc

1. Open three terminals in the `Bonus2-KeyEnc` folder.
2. Start the server:

   ```bash
   python server.py
   ```

3. Start two clients using the same client type:

   ```bash
   python client.py Alice
   python client.py Bob
   ```

   or

   ```bash
   python client_custom_enc.py Alice
   python client_custom_enc.py Bob
   ```

4. Type a message in one window and click Send. The other window will display the received ciphertext and decrypted plaintext.

## Notes

- On first contact, each bonus-2 client pins the peer identity key in `trusted_identities.json`.
- If identity files need to be reset for testing, remove `trusted_identities.json` and the generated `*_ed25519.pem` files, then reconnect.

## Report Notes

- Requirement 1: AES-256 is used, so the key length is at least 56 bits.
- Requirement 2: Keys are derived from a negotiated shared secret, not from a password.
- Requirement 3: CBC padding uses PKCS7.
- Requirement 4: The GUI shows sent ciphertext, received ciphertext, and plaintext.
- Requirement 5: TCP sockets are used for initial connection and message relay.
- Requirement 6: Random IVs/nonces ensure the same plaintext produces different ciphertext.
- Requirement 7: Periodic rekeying happens after a fixed number of messages.
- Bonus 1: `client_custom_enc.py` keeps the two-layer custom encryption design.
- Bonus 2: The Ed25519 identity keys plus X25519 exchange provide authenticated key establishment without a shared password.