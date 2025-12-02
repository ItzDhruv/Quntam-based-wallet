use qrc_opensource_rs::{
    asymmetric::cipher::kyber::{
        qrc_kyber_generate_keypair, qrc_kyber_encrypt, qrc_kyber_decrypt,
        QRC_KYBER_SEED_SIZE, QRC_KYBER_PUBLICKEY_SIZE, QRC_KYBER_PRIVATEKEY_SIZE,
        QRC_KYBER_SHAREDSECRET_SIZE, QRC_KYBER_CIPHERTEXT_SIZE,
    },
    provider::rcrng::qrc_rcrng_generate,
};





pub fn generate_kyber() {
    println!();
    println!("------------------------------------- Kyber Keypair --------------------------------------");
    println!();
    let mut seed = [0u8; QRC_KYBER_SEED_SIZE];
    qrc_rcrng_generate(&mut seed, QRC_KYBER_SEED_SIZE);

    let publickey = &mut [0u8; QRC_KYBER_PUBLICKEY_SIZE];
    let privatekey = &mut [0u8; QRC_KYBER_PRIVATEKEY_SIZE];

    let secret1 = &mut [0u8; QRC_KYBER_SHAREDSECRET_SIZE];
    let secret2 = &mut [0u8; QRC_KYBER_SHAREDSECRET_SIZE];

    let ciphertext = &mut [0u8; QRC_KYBER_CIPHERTEXT_SIZE];

    
    qrc_kyber_generate_keypair(publickey, privatekey, seed);
    qrc_kyber_encrypt(secret1, ciphertext, publickey, seed);
    qrc_kyber_decrypt(secret2, ciphertext, privatekey);
    
    println!("Public key length: {} bytes",publickey.len()); 
    println!("Private key length: {} bytes",privatekey.len()); 
    print!("Public key (first 32 bytes): ");
    for byte in publickey.iter().take(32) {
        print!("{:02x}", byte);
    }
    
    println!();

    print!("Private key (first 32 bytes): ");
    for byte in privatekey.iter().take(32) {
        print!("{:02x}", byte);
    }
    
    println!();

}



