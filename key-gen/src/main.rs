mod kyber;
mod dilithium;
mod hybrid;
mod ed25519;
mod test;
fn main() {
    dilithium::dilithium_main();
    
    kyber::generate_kyber();
    hybrid::demo_hybrid();
    
    ed25519::ed25519_main();
       
    test::dill_gen();
     
     
}
