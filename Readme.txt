Project_Folder/
│
├── main.py                 # The entry point that initializes the GUI and ties everything together
├── README.md               # Quick instructions on how to run (useful for the grader)
│
├── network/                # [Socket Lead's Workspace]
│   ├── __init__.py         # Makes this a Python package
│   └── connection.py       # TCP socket setup, listener, and sender logic [cite: 49, 50]
│
├── crypto/                 # [Crypto Lead's Workspace]
│   ├── __init__.py
│   ├── manager.py          # Key management and periodic update logic [cite: 53]
│   └── engine.py           # Encryption, decryption, padding, and key derivation [cite: 44, 45, 46]
│
├── gui/                    # [GUI Lead's Workspace]
│   ├── __init__.py
│   └── interface.py        # Tkinter/PyQt layout with ciphertext display fields [cite: 47, 48]
│
└── Report_GroupMembers.pdf  # Final 5-page report (11pt Times New Roman) [cite: 9, 10, 18, 19]