use ed25519_dalek::{
    SigningKey, Signer, Verifier, Signature
};
use rand::rngs::OsRng;
use rand::RngCore; // needed for fill_bytes()

pub fn generate_ed25519() {
    println!();
    println!("---------------------------- Ed25519 Keypair -------------------------------");
    println!();

    // Step 1: create 32-byte random seed
    let mut seed = [0u8; 32];
    let mut rng = OsRng;
    rng.fill_bytes(&mut seed);

    // Step 2: build SigningKey from seed
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();

    let sk_bytes = signing_key.to_bytes(); // 32 bytes
    let pk_bytes = verifying_key.to_bytes(); // 32 bytes

    println!("Public key length: {} bytes", pk_bytes.len());
    println!("Secret key length: {} bytes", sk_bytes.len());

    print!("Public key (first 32 bytes): ");
    for byte in pk_bytes.iter().take(32) {
        print!("{:02x}", byte);
    }
    println!();

    print!("Secret key (first 32 bytes): ");
    for byte in sk_bytes.iter().take(32) {
        print!("{:02x}", byte);
    }
    println!();
}


pub fn demo_signed_message() {
    println!();
    println!("------------------------ Ed25519 Signing & Verification ------------------------");
    println!();

    // new keypair
    let mut seed = [0u8; 32];
    let mut rng = OsRng;
    rng.fill_bytes(&mut seed);
                  
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();

    let message = b"Post-Quantum Blockchain Ready";

    // sign message
    let signature: Signature = signing_key.sign(message);

    print!("Public key (first 32 bytes): ");
    for byte in verifying_key.to_bytes().iter().take(32) {
        print!("{:02x}", byte);
    }
    println!();

    println!("Signature length: {} bytes", signature.to_bytes().len());

    print!("Signature (first 32 bytes): ");
    for byte in signature.to_bytes().iter().take(32) {
        print!("{:02x}", byte);
    }
    println!();

    // verify signature
    match verifying_key.verify(message, &signature) {
        Ok(()) => println!("✔ Verification successful"),
        Err(_) => println!("✘ Verification failed"),
    }
}

pub fn ed25519_main(){
    generate_ed25519();
    demo_signed_message();
}