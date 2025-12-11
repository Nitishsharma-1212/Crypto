# FileCrypti Pro — Full Edition

**FileCrypti Pro** is a secure file encryption and decryption tool with a modern GUI built in Python. It supports AES-GCM encryption, optional keyfiles, secure shredding, drag-and-drop, and history tracking. Designed for both files and folders, it is easy to use yet highly secure.

---

## Features

- **AES-GCM Encryption** with PBKDF2-HMAC-SHA256 key derivation
- **Optional Keyfile** for an additional layer of security
- **Folder Support** (folders are zipped before encryption)
- **Secure Shredding** to permanently delete sensitive files
- **Progress Tracking** with real-time progress bars
- **Activity Log & History** of encrypt/decrypt actions
- **Drag & Drop Support** for files
- **Auto-Lock** for inactivity (configurable timeout)
- **Light/Dark Theme** for better usability

---

## Installation

1. Clone the repository:

```bash
git clone https://github.com/yourusername/FileCryptiPro.git
cd FileCryptiPro
Install dependencies (Python 3.10+ recommended):

bash
Copy code
pip install -r requirements.txt
Dependencies:

cryptography

tkinter (built-in in Python)

tkinterdnd2 (optional, for drag-and-drop)

Usage
Run the application:

bash
Copy code
python filecrypti_pro.py
Encrypt a File/Folder:

Select a file or folder

Optionally create or browse a keyfile

Enter a password

Click Start Encrypt

Optionally Shred Source after encryption

Decrypt a File:

Select the encrypted .fcp file

Enter the same password and keyfile (if used)

Click Start Decrypt

Verify SHA256 hash for file integrity

History & Settings:

View recent encrypt/decrypt operations

Adjust PBKDF2 iterations, chunk size, auto-lock timeout, and theme

Clear history when needed

Security Notes
Encryption uses AES-GCM for authenticated encryption

Passwords are processed via PBKDF2-HMAC-SHA256 with high iteration count

Keyfiles provide an additional layer of security

Shredding overwrites files multiple times for secure deletion

Always keep backups — irreversible operations like shredding cannot be undone

Screenshots
(Add screenshots of your app here for clarity)

Contributing
Contributions, issues, and feature requests are welcome!

Fork the project

Create a new branch (git checkout -b feature-name)

Make your changes

Submit a pull request

License
MIT License © Nitish

