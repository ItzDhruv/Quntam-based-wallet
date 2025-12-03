

#  Hybrid Quantum-Safe Wallet (Dilithium + Ed25519 + Kyber)

This project implements a **Post-Quantum + Classical Hybrid Cryptographic Wallet** in **Rust**.
It combines 3 cryptographic systems:

| Cryptosystem              | Category     | Purpose                                             |
| ------------------------- | ------------ | --------------------------------------------------- |
| **Dilithium2 (PQCrypto)** | Post-Quantum | Digital signatures secure against quantum computers |
| **Ed25519 (Dalek)**       | Classical    | Fast + lightweight digital signatures               |
| **Kyber (QRC)**           | Post-Quantum | Key exchange / encryption                           |

The project generates **three independent keypairs**, performs **signature + verification**, and demonstrates a **hybrid signature scheme** where a message must be valid in both Dilithium and Ed25519 — offering **Double Security**.

---

## 📌 Why Hybrid Cryptography?

Quantum computers will break classical cryptography like RSA, ECDSA & Ed25519 in the future.
Post-Quantum cryptography (PQC) protects against future attacks, but classical cryptography is still faster and widely supported today.

✔ Combining PQC + Classical = security now + security after quantum era
✔ Even if PQC or classical is broken alone — the wallet remains secure
✔ Compressed hybrid key makes the wallet address **only 32 bytes**

---

## 🧬 Project Structure

```
src/
 ├─ kyber.rs        → Kyber KEM (encryption + shared secret)
 ├─ dilithium.rs    → Dilithium signatures
 ├─ ed25519.rs      → Ed25519 signatures
 ├─ hybrid.rs       → Hybrid wallet + hybrid signature
 └─ main.rs         → Demo runner
```

---

## 🚀 Features

| Module         | Features                                                       |
| -------------- | -------------------------------------------------------------- |
| `dilithium.rs` | Generate keypair, sign message, verify                         |
| `ed25519.rs`   | Generate keypair, sign message, verify                         |
| `kyber.rs`     | Generate seed, derive keypair, encrypt & decrypt shared secret |
| `hybrid.rs`    | Generate hybrid keypair, hybrid signature, hybrid verification |
| `main.rs`      | Runs all demonstrations in sequence                            |

---

## 🔑 Hybrid Key Format

The hybrid wallet produces:

```
Dilithium Public Key    → Large (1312 bytes)
Ed25519 Public Key      → 32 bytes
Hybrid Compressed Key   → 32 bytes  (BLAKE2b hash of both keys)
```

Compressed Hybrid Key (wallet address):

```
compressed = blake2b( dil_pk || ed_pk )[0..32]
```

This provides a **short 32-byte address** while internally using two independent cryptographic systems.

---

## 🔄 Signing Workflow

### 🔹 Hybrid Sign

Both signatures are generated:

```
DilithiumSignedMessage = Dilithium.sign(message)
Ed25519Signature       = Ed25519.sign(message)
```

The final HybridSignature object contains:

```
{
  dilithium_sm,
  ed25519_sig
}
```

### 🔹 Hybrid Verify

Verification succeeds only if:

1️⃣ Dilithium signed message is valid **AND**
2️⃣ Ed25519 signature is valid **AND**
3️⃣ Recovered message matches original

This prevents:

* Dilithium-only forged signature
* Ed25519-only forged signature
* Message tampering

---

## 📌 Kyber Encryption (KEM Use Case)

Kyber is used for secure key exchange:

```
Encrypt → produces shared_secret, ciphertext
Decrypt → restores shared_secret
```

Useful for:

* Secure peer-to-peer communication
* Session key generation
* Quantum-safe layer for blockchain wallets

---

## ▶ Running the Project

Install Rust nightly if not installed:

```bash
rustup update
```

Run:

```bash
cargo run
```

You will see printed output for:

* Dilithium keypair + signing demo
* Kyber encryption demo
* Hybrid keypair
* Hybrid signing & verification
* Ed25519 keypair + signing demo

---

## 📌 Security Notes

| Cryptosystem | Strength                                           |
| ------------ | -------------------------------------------------- |
| Dilithium2   | NIST PQC standard — secure against quantum attacks |
| Kyber        | NIST PQC standard — secure against quantum attacks |
| Ed25519      | Very fast — secure against classical attacks       |

🔐 **Hybrid cryptography guarantees safety even if one system is broken.**

---

## 🧠 Use Cases

| Target System                    | Result |
| -------------------------------- | ------ |
| Post-Quantum Blockchain Wallet   | ✔      |
| Decentralized Identity           | ✔      |
| Secure Messaging                 | ✔      |
| PQC Support for Smart Contracts  | ✔      |
| Multi-Signature Security Wallets | ✔      |

---

## 📄 Summary

| Component                | Bytes  | Role             |
| ------------------------ | ------ | ---------------- |
| Dilithium Public Key     | ~1312  | PQ security      |
| Dilithium Secret Key     | ~2528  | PQ security      |
| Ed25519 Public Key       | 32     | Classical crypto |
| Ed25519 Secret Key       | 32     | Classical crypto |
| Dilithium Signed Message | ~2400  | PQ Signature     |
| Ed25519 Signature        | 64     | Signature        |
| Hybrid Compressed Key    | **32** | Wallet Address   |

---

## ✨ Future Improvements

* Wallet import/export structure
* BIP-39 mnemonic support
* Hardware wallet support
* Transaction format using hybrid signature
* Blockchain integration example

---

## 📜 License

MIT — Free to modify and use.