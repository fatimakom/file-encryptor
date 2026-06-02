# 🛡️ File Encryptor — AES-256

> Encrypt and decrypt any file using **AES-256 military-grade encryption** — the same standard used by banks, governments, and the military.

---

## ✨ Features

- 🔒 Encrypt **any file type** (photos, PDFs, videos, documents, code...)
- 🔓 Decrypt files back to their original form
- 🔑 AES-256-CBC (Python) / AES-256-GCM (Web) encryption
- 🧂 PBKDF2 key derivation with 100,000 iterations
- 🎲 Random Salt + IV — every encryption is unique
- 🌐 Web version runs 100% in your browser — files never leave your device
- 🖥️ Python CLI version for terminal users

---

## 🚀 Getting Started

### Web Version (easiest)
Just open `index.html` in your browser. No installation needed!

### Python CLI Version

```bash
# 1. Clone the repo
git clone https://github.com/YOUR_USERNAME/file-encryptor.git
cd file-encryptor

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run
python file_encryptor.py
```

---

## 🗂️ Project Structure

```
file-encryptor/
├── file_encryptor.py   # Python CLI — full encryption/decryption
├── index.html          # Web app — drag & drop interface
├── requirements.txt    # Python dependencies
├── .gitignore
└── README.md
```

---

## 🔐 How the Encryption Works

### Step by step:

```
Your Password
      │
      ▼
 PBKDF2 (100,000 iterations + random Salt)
      │
      ▼
 256-bit AES Key
      │
      ▼
 AES-256 Encryption (with random IV)
      │
      ▼
 [Salt][IV][Encrypted Data] → .encrypted file
```

### To decrypt:
```
.encrypted file → read Salt + IV
Password + Salt → PBKDF2 → same 256-bit Key
Key + IV + Encrypted Data → AES Decrypt → Original File
```

---

## 🧮 Security Details

| Feature | Value | Why |
|---|---|---|
| Encryption | AES-256 | Industry standard, used by NSA/banks |
| Mode | CBC (Python) / GCM (Web) | Secure block chaining |
| Key Derivation | PBKDF2-SHA256 | Stretches password to 256 bits |
| Iterations | 100,000 | Makes brute-force 100k× harder |
| Salt size | 32 bytes | Prevents rainbow table attacks |
| IV size | 16 bytes (CBC) / 12 bytes (GCM) | Makes each encryption unique |

---

## ⚠️ Important Warning

> If you forget your password, **the file cannot be recovered**. There is no reset, no backdoor, no master key. This is by design — it means nobody else can recover it either.

**Always store your password safely** (use a password manager like Bitwarden).

---

## 💡 What is AES-256?

AES (Advanced Encryption Standard) with a 256-bit key is the strongest encryption standard publicly available. To brute-force a 256-bit key at 1 trillion attempts per second, it would take longer than the age of the universe.

It is used by:
- The US Government and NSA
- Banks and financial institutions
- WhatsApp, Signal, iMessage
- BitLocker, FileVault disk encryption

---

## 🛠️ Tech Stack

- **Python 3.10+** — CLI version
- **`cryptography` library** — AES-256-CBC encryption
- **Web Crypto API** — built-in browser encryption (no libraries!)
- **Vanilla HTML/CSS/JS** — web interface

---
---
## 🔗 Demo link

https://file-encryptionlb.netlify.app

## 🙋 Author

Built by **Fatima Koumayha** — junior developer learning cybersecurity.

- GitHub: [@fatimakom](https://github.com/fatimakom/file-encryptor.git)
- LinkedIn: [linkedin.com/in/fatima-koumayha-a09675323/](https://www.linkedin.com/in/fatima-koumayha-a09675323)

---

## 📄 License

MIT — free to use and modify.