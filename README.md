# FileCrypti Pro — Full Edition

**FileCrypti Pro** is a secure file encryption and decryption tool with a modern GUI built in Python. It uses AES-GCM encryption with PBKDF2-HMAC-SHA256 key derivation and supports optional keyfiles, secure shredding, folder encryption, drag-and-drop, activity logging, and auto-lock for enhanced security.

---

## Features

* **AES-GCM Encryption** with authenticated encryption
* **PBKDF2-HMAC-SHA256** key derivation with configurable iterations
* **Optional Keyfile** for additional security
* **Folder Support** (folders are zipped before encryption)
* **Secure Shredding** of files and folders
* **Progress Bars** for encrypt/decrypt operations
* **Activity Log & History** of actions
* **Drag & Drop** support for files
* **Auto-Lock** on inactivity (configurable timeout)
* **Light/Dark Theme** for better usability

---

## Installation

1. Clone the repository:

```bash
git clone https://github.com/yourusername/FileCryptiPro.git
cd FileCryptiPro
```

2. Install dependencies (Python 3.10+ recommended):

```bash
pip install -r requirements.txt
```

**Dependencies:**

* `cryptography`
* `tkinter` (built-in with Python)
* `tkinterdnd2` (optional, for drag-and-drop)

---

## Usage

Run the application:

```bash
python filecrypti_pro.py
```

### Encrypt a File or Folder

1. Select a file or folder to encrypt
2. Optionally create or browse a keyfile
3. Enter a password
4. Click **Start Encrypt**
5. Optionally **Shred Source** to securely delete original files

### Decrypt a File

1. Select the encrypted `.fcp` file
2. Enter the same password and keyfile (if used)
3. Click **Start Decrypt**
4. SHA256 hash is displayed for verification

### History & Settings

* View recent encrypt/decrypt operations in **History**
* Adjust PBKDF2 iterations, chunk size, auto-lock timeout, and theme in **Settings**
* Clear history if needed

---

## Security Notes

* Encryption is **authenticated** using AES-GCM
* Passwords are processed with high-iteration PBKDF2-HMAC-SHA256
* Optional keyfiles enhance security
* Secure shredding overwrites files multiple times before deletion
* Always keep backups — shredded files cannot be recovered

---

## Contributing

Contributions, issues, and feature requests are welcome!

1. Fork the project
2. Create a new branch (`git checkout -b feature-name`)
3. Make your changes
4. Submit a pull request

---

## License

MIT License © Nitish
