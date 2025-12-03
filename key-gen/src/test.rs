use pqcrypto_dilithium::dilithium2::*;
use pqcrypto_traits::sign::PublicKey as _;
use pqcrypto_traits::sign::SecretKey as _;
use pqcrypto_traits::sign::SignedMessage as _;

pub fn dill_gen(){
    let message = String::from("Post-Quantum Blockchain Ready");
    let (pk, sk) = keypair();
    let signed_msg = sign(message.as_bytes(), &sk);
    println!();
    print!("--------------------Public Key mine testing ----------------");
    println!();
    println!();
    println!("Signed msg : ");
    for b in signed_msg.as_bytes().iter().take(34)   {
        print!("{:02x}", b);
    }
    println!();
    println!("Public key : ");
    for b in pk.as_bytes().iter().take(34)   {
        print!("{:02x}", b);
    }
    println!();
    println!("Private key : ");
     for b in sk.as_bytes().iter().take(34)   {
        print!("{:02x}", b);
    }
    println!();
    let verified = open(&signed_msg, &pk).expect("verification failed");
    println!("Verified msg : {}", String::from_utf8_lossy(&verified));
    println!();
}   