Computer Security Final Project


Project_Folder/
│
├── main.py                 # The entry point that initializes the GUI and ties everything together
├── README.md               # Quick instructions on how to run (useful for the grader)
│
├── network/                # [Socket Lead's Workspace]
│   ├── __init__.py         # Makes this a Python package
│   └── connection.py       # TCP socket setup, listener, and sender logic 
│
├── crypto/                 # [Crypto Lead's Workspace]
│   ├── __init__.py
│   ├── manager.py          # Key management and periodic update logic 
│   └── engine.py           # Encryption, decryption, padding, and key derivation 
│
├── gui/                    # [GUI Lead's Workspace]
│   ├── __init__.py
│   └── interface.py        # Tkinter/PyQt layout with ciphertext display fields 
│
└── Report_GroupMembers.pdf  # Final 5-page report (11pt Times New Roman) 

The core components of the messaging service are broken up into modules which can be independantly worked on. The general flow of the 
process is defined here:

The main script will instantiate the GUI. The initial setup where users input the shared password will happen in the GUi,
then passing it to the crypto module to generate the 56 bit key.
The user will then click a "connect" button, which will call functions in connection.py to establish a TCP socket. 

When a message is sent, the GUI sends the string to the crypto module, returning the ciphertext bytes which are then handed to
connection.py to be sent over the internet. 