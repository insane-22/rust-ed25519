use rust_ed25519::{generate_keypair, sign_message, verify_signature};

#[test]
fn test_sign_and_verify() {
    let (sk, pk) = generate_keypair().unwrap();
    let msg = b"hello ed25519";
    let sig = sign_message(&sk, msg).unwrap();
    assert!(verify_signature(&pk, msg, &sig).unwrap());
}
