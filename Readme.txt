Computer Security Final Project

Secure Instant Point-to-Point (P2P) Messaging

Project layout used for the final implementation:

project_cs_bonus2/
├── server.py                # TCP relay server for exactly two clients
├── client.py                # Standard secure chat client
├── client_custom_enc.py      # Bonus 1 custom-encryption client
├── trusted_identities.json   # Local trust store created after first contact
└── *_ed25519.pem             # Local identity keys created per username

How the system works:
- Alice and Bob start the relay server first.
- Each client connects with a username.
- The clients perform an authenticated X25519 key exchange using long-term Ed25519 identity keys.
- The shared session key is derived with HKDF and is refreshed periodically after a fixed number of messages.
- Messages are encrypted before transmission and the GUI shows both sent and received ciphertext.

Run instructions:
1. Open three terminals in the `P2P Messaging` folder.
2. Start the server:
   `python server.py`
3. Start two clients using the same client type:
   `python client.py` Alice
   `python client.py` Bob
   or
   `python client_custom_enc.py` Alice
   `python client_custom_enc.py` Bob
4. Type a message in one window and click Send. The other window will display the received ciphertext and decrypted plaintext.

Notes:
- Do not mix `client.py` with `client_custom_enc.py` in the same chat session.
- On first contact, each client pins the peer identity key in `trusted_identities.json`.
- If identity files need to be reset for testing, remove `trusted_identities.json` and the generated `*_ed25519.pem` files, then reconnect.

Report notes:
- Requirement 1: AES-256 is used, so the key length is at least 56 bits.
- Requirement 2: Keys are derived from a negotiated shared secret, not from a password.
- Requirement 3: CBC padding uses PKCS7.
- Requirement 4: The GUI shows sent ciphertext, received ciphertext, and plaintext.
- Requirement 5: TCP sockets are used for initial connection and message relay.
- Requirement 6: Random IVs/nonces ensure the same plaintext produces different ciphertext.
- Requirement 7: Periodic rekeying happens after a fixed number of messages.
- Bonus 1: `client_custom_enc.py` keeps the two-layer custom encryption design.
- Bonus 2: The Ed25519 identity keys plus X25519 exchange provide authenticated key establishment without a shared password.

Group members:
- Add all member names here before submission.
 