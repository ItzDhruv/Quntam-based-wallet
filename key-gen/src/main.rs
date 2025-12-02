mod kyber;
mod dilithium;
mod hybrid;
mod ed25519;

fn main() {
    dilithium::generate_dilithium();
    
    dilithium::demo_signed_message();
    kyber::generate_kyber();
    hybrid::demo_hybrid();
    
    ed25519::generate_ed25519();
    ed25519::demo_signed_message();
   
     
}
