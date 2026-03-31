use sibna_core::*;
use sibna_core::handshake::PreKeyBundle;
use ed25519_dalek::{SigningKey, Signer};

#[test]
fn test_multi_device_identity_linking() {
    let config = Config::default();
    
    // 1. Create Root Identity
    let root_ctx = SecureContext::new(config.clone(), None).unwrap();
    let root_kp = root_ctx.generate_identity().unwrap();
    let root_signing_key = SigningKey::from_bytes(&root_kp.ed25519_secret.unwrap());
    
    // 2. Create Device Identity
    let device_ctx = SecureContext::new(config.clone(), None).unwrap();
    let device_kp = device_ctx.generate_identity().unwrap();
    device_ctx.keystore().write().generate_signed_prekey().unwrap();
    
    // 3. Link Device to Root
    // Proof = sign(device_pub_key || device_id)
    let device_id = 1u32;
    let mut proof_data = [0u8; 36];
    proof_data[0..32].copy_from_slice(&device_kp.ed25519_public);
    proof_data[32..36].copy_from_slice(&device_id.to_le_bytes());
    
    let signature = root_signing_key.sign(&proof_data);
    
    // 4. Set link in device context
    device_ctx.set_device_link(device_id, &root_kp.ed25519_public, &signature.to_bytes()).unwrap();
    
    // 5. Generate PreKeyBundle and verify it contains the link
    let bundle_bytes = device_ctx.keystore().read().generate_prekey_bundle_bytes().unwrap();
    let bundle = PreKeyBundle::from_bytes(&bundle_bytes).unwrap();
    
    assert_eq!(bundle.device_id, device_id);
    assert_eq!(bundle.root_identity_key, root_kp.ed25519_public);
    // Signature should not be all zeros
    assert!(!bundle.device_signature.iter().all(|&b| b == 0));
    
    // 6. Validate the bundle (this checks the root signature internally)
    assert!(bundle.validate().is_ok(), "Bundle validation failed: {:?}", bundle.validate().err());
}

#[test]
fn test_self_signed_root_device() {
    let config = Config::default();
    let ctx = SecureContext::new(config, None).unwrap();
    let _ = ctx.generate_identity().unwrap();
    ctx.keystore().write().generate_signed_prekey().unwrap();
    
    // Device 0 is the root itself, it should be self-signed by default or allowed
    let bundle_bytes = ctx.keystore().read().generate_prekey_bundle_bytes().unwrap();
    let bundle = PreKeyBundle::from_bytes(&bundle_bytes).unwrap();
    
    assert_eq!(bundle.device_id, 0);
    // Root should be able to validate its own device 0 bundle
    assert!(bundle.validate().is_ok());
}

#[test]
fn test_invalid_device_signature_rejected() {
    let config = Config::default();
    let root_ctx = SecureContext::new(config.clone(), None).unwrap();
    let root_kp = root_ctx.generate_identity().unwrap();
    
    let device_ctx = SecureContext::new(config, None).unwrap();
    let _ = device_ctx.generate_identity().unwrap();
    device_ctx.keystore().write().generate_signed_prekey().unwrap();
    
    // Provide a fake signature
    let fake_sig = [0u8; 64];
    device_ctx.set_device_link(1, &root_kp.ed25519_public, &fake_sig).unwrap();
    
    let bundle_bytes = device_ctx.keystore().read().generate_prekey_bundle_bytes().unwrap();
    let bundle = PreKeyBundle::from_bytes(&bundle_bytes).unwrap();
    
    // Validation MUST fail
    assert!(bundle.validate().is_err());
}
