use pqcrypto_dilithium::dilithium2::{keypair, public_key_bytes, secret_key_bytes, sign, open};
use pqcrypto_traits::sign::{PublicKey, SecretKey};
use pqcrypto_traits::sign::SignedMessage as TraitSignedMessage;

pub fn generate_dilithium() {
    println!();
    println!();
    println!("---------------------------- Dilithium Keypair -------------------------------");
    println!();
    let (pk, sk) = keypair();

    println!("Public key length: {} bytes", public_key_bytes());
    println!("Secret key length: {} bytes", secret_key_bytes());

    print!("Public key (first 34 bytes): ");
    for byte in pk.as_bytes().iter().take(34) {
        print!("{:02x}", byte);
    }
    println!();

    print!("Secret key (first 34 bytes): ");
    for byte in sk.as_bytes().iter().take(34) {
        print!("{:02x}", byte);
    }
    println!();
}


pub fn demo_signed_message() {
    
    println!("--------------------------- Dilithium Verification of Signed message -----------------------");
    println!();

    let (pk, sk) = keypair();
    // let (pk2, sk2) = keypair();

    let message = b"Post-Quantum Blockchain Ready";


    let signed_msg = sign(message, &sk);



    
    for byte in pk.as_bytes().iter().take(34) {
        print!("{:02x}", byte);
    }
    // let pk2 = "c5f57259d887c75474d9f47f2c2872c0d9e893329db6003f38ff9081f67519bd304f";
    // println!("Public key as array: {:?}", pk.as_bytes());

    println!("SignedMessage total length: {} bytes", signed_msg.as_bytes().len());

    print!("SignedMessage (first 33 bytes): ");
    for byte in signed_msg.as_bytes().iter().take(32) {
        print!("{:02x}", byte);
    }
    println!();

    
    let verified = open(&signed_msg, &pk).expect("verification failed");

    println!("Recovered message: {}", String::from_utf8_lossy(&verified));
}

pub fn dilithium_main(){
    generate_dilithium();
    demo_signed_message();
}