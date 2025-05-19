# 🔐 Hybrid Encryption System (DH + RSA + AES)

This project demonstrates a secure hybrid encryption architecture combining:

- **Diffie-Hellman (DH)** via ECC for secure key exchange
- **AES** for fast symmetric encryption
- **RSA** for asymmetric encryption of AES ciphertext

---

## ✅ Final Architecture

| Step | Description |
|------|-------------|
| 1 | Sender & Receiver perform DH key exchange (generate A, B) |
| 2 | Both compute `shared_secret = g^(ab) mod p` (via ECC) |
| 3 | `shared_secret` is used as AES key for encryption/decryption |
| 4 | Receiver generates RSA key pair |
| 5 | Receiver shares only RSA public key with sender |
| 6 | Sender encrypts the message using AES (CT1) |
| 7 | Sender encrypts CT1 using RSA public key → CT2 |
| 8 | Receiver decrypts CT2 using RSA private key → gets CT1 |
| 9 | Receiver decrypts CT1 using shared_secret AES key → Plain Text |

---

## 📦 Project Files

- `app.py`: Flask app with routes for encryption and decryption
- `crypto_logic.py`: Core crypto logic using PyCryptodome
- `templates/index.html`: Frontend UI
- `static/style.css`: Basic styling
- `requirements.txt`: Dependencies

---

## 🚀 How to Run

1. Install dependencies:

```bash
pip install -r requirements.txt
```

2. Run the Flask app:

```bash
python app.py
```

3. Open in browser: [http://localhost:5003](http://localhost:5003)

---

## 🔐 Libraries Used

- `pycryptodome` for AES, RSA, ECC, HKDF
- `Flask` for serving the web interface

---

## 🛡️ Security Highlights

- AES key never transmitted — derived via ECDH
- AES-GCM ensures confidentiality and integrity
- RSA wraps AES ciphertext for public-key security
- Session state and keys are managed securely

---

© 2025 Secure Crypto Example
