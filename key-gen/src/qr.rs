use rand::random;
use blake2b_simd::Params;
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};

use pqcrypto_dilithium::dilithium2::{
    keypair as dilithium_keypair,
    sign as dilithium_sign,
    open as dilithium_open,
    PublicKey as DilithiumPublicKey,
    SecretKey as DilithiumSecretKey,
    SignedMessage as DilithiumSignedMessage,
};


use pqcrypto_traits::sign::PublicKey as _;
use pqcrypto_traits::sign::SecretKey as _;
use pqcrypto_traits::sign::SignedMessage as TraitSignedMessage;


pub struct HybridPublicKey {
    pub dilithium_pk: DilithiumPublicKey,
    pub ed25519_pk: VerifyingKey,
    pub compressed_key: [u8; 32], 
}

/// Hybrid secret key (kept in wallet storage)
pub struct HybridSecretKey {
    pub dilithium_sk: DilithiumSecretKey,
    pub ed25519_sk: SigningKey,
}

/// Hybrid signature (sent with transaction)
pub struct HybridSignature {
    pub dilithium_sm: DilithiumSignedMessage,
    pub ed25519_sig: Signature,
}

/// Create 32-byte compressed hybrid public key
pub fn minimize_key(dil_pk: &DilithiumPublicKey, ed_pk: &VerifyingKey) -> [u8; 32] {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(dil_pk.as_bytes());
    encoded.extend_from_slice(&ed_pk.to_bytes());
    let hash = Params::new().hash(&encoded);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hash.as_bytes()[..32]);
    out
}

/// Generate Hybrid Keypair (Dilithium + Ed25519)
pub fn generate_hybrid_keypair() -> (HybridPublicKey, HybridSecretKey) {
    println!();
    println!("----> HYBRID KEYPAIR (Dilithium + Ed25519)");
    println!();

    // Dilithium
    let (dil_pk, dil_sk) = dilithium_keypair();

    // Ed25519
    let seed: [u8; 32] = random();
    let ed_sk = SigningKey::from_bytes(&seed);
    let ed_pk = ed_sk.verifying_key();

    // Compressed wallet public key
    let compressed = minimize_key(&dil_pk, &ed_pk);

    // Print only compressed key
    print!("Hybrid COMPRESSED Public Key: 0x");
    for b in compressed {
        print!("{:02x}", b);
    }
    println!("\n");

    let hybrid_pk = HybridPublicKey {
        dilithium_pk: dil_pk,
        ed25519_pk: ed_pk,
        compressed_key: compressed,
    };

    let hybrid_sk = HybridSecretKey {
        dilithium_sk: dil_sk,
        ed25519_sk: ed_sk,
    };

    (hybrid_pk, hybrid_sk)
}

/// Sign a message using BOTH Dilithium + Ed25519
pub fn hybrid_sign(message: &[u8], sk: &HybridSecretKey) -> HybridSignature {
    let dil_sm: DilithiumSignedMessage = dilithium_sign(message, &sk.dilithium_sk);
    let ed_sig: Signature = sk.ed25519_sk.sign(message);

    HybridSignature {
        dilithium_sm: dil_sm,
        ed25519_sig: ed_sig,
    }
}

/// Verify both signatures (Dilithium + Ed25519)
pub fn hybrid_verify(message: &[u8], sig: &HybridSignature, pk: &HybridPublicKey) -> bool {
    // Dilithium (recover message)
    let recovered = match dilithium_open(&sig.dilithium_sm, &pk.dilithium_pk) {
        Ok(msg) => msg,
        Err(_) => return false,
    };

    print!("Recovered Dilithium Message: ");
    println!("{}", String::from_utf8_lossy(&recovered));

    if recovered.as_slice() != message {
        return false;
    }

    // Ed25519
    pk.ed25519_pk.verify(message, &sig.ed25519_sig).is_ok()
}

/// Demo function to show whole process
pub fn demo_hybrid() {
    println!();
    println!();
    println!("==================== HYBRID SIGNING & VERIFICATION DEMO ====================");
    println!();

    let (hybrid_pk, hybrid_sk) = generate_hybrid_keypair();

    // ---- Print ALL RAW KEYS ----
    println!("\n==================== RAW KEY DETAILS ====================");

    println!("Dilithium Public Key ({} bytes) print Only First 32 bytes :", hybrid_pk.dilithium_pk.as_bytes().len());
    print!("0x");
    for b in hybrid_pk.dilithium_pk.as_bytes().iter().take(32) {
        print!("{:02x}", b);
    }
    println!("\n");

    println!("Dilithium Secret Key ({} bytes) print Only First 32 bytes :", hybrid_sk.dilithium_sk.as_bytes().len());
    print!("0x");
    for b in hybrid_sk.dilithium_sk.as_bytes().iter().take(32) {
        print!("{:02x}", b);
    }
    println!("\n");

    println!("Ed25519 Public Key ({} bytes):", hybrid_pk.ed25519_pk.to_bytes().len());
    print!("0x");
    for b in hybrid_pk.ed25519_pk.to_bytes() {
        print!("{:02x}", b);
    }
    println!("\n");

    println!("Ed25519 Secret Key ({} bytes):", hybrid_sk.ed25519_sk.to_bytes().len());
    print!("0x");
    for b in hybrid_sk.ed25519_sk.to_bytes() {
        print!("{:02x}", b);
    }
    println!("\n");

    // ---- Print compressed Hybrid public key ----
    println!("Hybrid COMPRESSED Public Key (32 bytes): 0x");
    for b in hybrid_pk.compressed_key {
        print!("{:02x}", b);
    }
    println!("\n");

    // ---- Sign message ----
    let message = b"Post-Quantum Blockchain Ready (Hybrid Wallet)";
    let sig = hybrid_sign(message, &hybrid_sk);

    println!("==================== SIGNATURE DETAILS ====================\n");

    println!("Dilithium SignedMessage ({} bytes):", sig.dilithium_sm.as_bytes().len());
    print!("0x");
    for b in sig.dilithium_sm.as_bytes().iter().take(80) { // not printing full because 2KB+
        print!("{:02x}", b);
    }
    println!(" ... (truncated)\n");

    println!("Ed25519 Signature ({} bytes):", sig.ed25519_sig.to_bytes().len());
    print!("0x");
    for b in sig.ed25519_sig.to_bytes() {
        print!("{:02x}", b);
    }
    println!("\n");

    // ---- Verify ----
    println!("==================== VERIFICATION ====================\n");
    if hybrid_verify(message, &sig, &hybrid_pk) {
        println!("✔ HYBRID verification successful (Dilithium + Ed25519 both valid)");
    } else {
        println!("✘ HYBRID verification FAILED");
    }


    println!("\n==================== SUMMARY ====================");
    println!("Dilithium PK: {} bytes", hybrid_pk.dilithium_pk.as_bytes().len());
    println!("Dilithium SK: {} bytes", hybrid_sk.dilithium_sk.as_bytes().len());
    println!("Ed25519 PK: {} bytes", hybrid_pk.ed25519_pk.to_bytes().len());
    println!("Ed25519 SK: {} bytes", hybrid_sk.ed25519_sk.to_bytes().len());
    println!("Dilithium SignedMessage: {} bytes", sig.dilithium_sm.as_bytes().len());
    println!("Ed25519 Signature: {} bytes", sig.ed25519_sig.to_bytes().len());
    println!("Hybrid Compressed Address: 32 bytes");
}