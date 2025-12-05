#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use cachekit_core::encryption::key_derivation::derive_tenant_keys;

#[derive(Arbitrary, Debug)]
struct KeyDerivationInput {
    master_key: Vec<u8>,
    tenant_id: String,
}

fuzz_target!(|input: KeyDerivationInput| {
    // Attack: Fuzz HKDF tenant key derivation with arbitrary master keys and tenant IDs
    // Validates: No panics, memory safety, deterministic output, key separation

    let KeyDerivationInput { master_key, tenant_id } = input;

    // Attempt key derivation with arbitrary inputs
    match derive_tenant_keys(&master_key, &tenant_id) {
        Ok(keys) => {
            // Fuzz property 1: All derived keys are 32 bytes
            assert_eq!(keys.encryption_key.len(), 32, "Encryption key must be 32 bytes");
            assert_eq!(keys.authentication_key.len(), 32, "Authentication key must be 32 bytes");
            assert_eq!(keys.cache_key_salt.len(), 32, "Cache key salt must be 32 bytes");

            // Fuzz property 2: Tenant ID is preserved
            assert_eq!(keys.tenant_id, tenant_id, "Tenant ID must be preserved");

            // Fuzz property 3: Determinism - same inputs produce same outputs
            let keys2 = derive_tenant_keys(&master_key, &tenant_id)
                .expect("Deterministic derivation should succeed again");

            assert_eq!(
                keys.encryption_key, keys2.encryption_key,
                "Encryption key derivation must be deterministic"
            );
            assert_eq!(
                keys.authentication_key, keys2.authentication_key,
                "Authentication key derivation must be deterministic"
            );
            assert_eq!(
                keys.cache_key_salt, keys2.cache_key_salt,
                "Cache key salt derivation must be deterministic"
            );

            // Fuzz property 4: Key separation - all three keys are different
            assert_ne!(
                keys.encryption_key, keys.authentication_key,
                "Encryption and authentication keys must differ"
            );
            assert_ne!(
                keys.encryption_key, keys.cache_key_salt,
                "Encryption key and cache salt must differ"
            );
            assert_ne!(
                keys.authentication_key, keys.cache_key_salt,
                "Authentication key and cache salt must differ"
            );

            // Fuzz property 5: Fingerprints are deterministic
            let fp1 = keys.encryption_fingerprint();
            let fp2 = keys.encryption_fingerprint();
            assert_eq!(fp1, fp2, "Fingerprints must be deterministic");
            assert_eq!(fp1.len(), 16, "Fingerprints must be 16 bytes");

            let auth_fp1 = keys.authentication_fingerprint();
            let auth_fp2 = keys.authentication_fingerprint();
            assert_eq!(auth_fp1, auth_fp2, "Auth fingerprints must be deterministic");
            assert_eq!(auth_fp1.len(), 16, "Auth fingerprints must be 16 bytes");

            // Fuzz property 6: Different tenant IDs produce different keys
            if !tenant_id.is_empty() {
                let different_tenant = format!("{}_different", tenant_id);
                if let Ok(different_keys) = derive_tenant_keys(&master_key, &different_tenant) {
                    assert_ne!(
                        keys.encryption_key, different_keys.encryption_key,
                        "Different tenant IDs must produce different encryption keys"
                    );
                    assert_ne!(
                        keys.authentication_key, different_keys.authentication_key,
                        "Different tenant IDs must produce different authentication keys"
                    );
                    assert_ne!(
                        keys.cache_key_salt, different_keys.cache_key_salt,
                        "Different tenant IDs must produce different cache salts"
                    );
                }
            }
        }
        Err(_) => {
            // Key derivation failed - acceptable for invalid inputs
            // Fuzz property: No panics, just clean error handling

            // Test that invalid inputs are consistently rejected
            let result2 = derive_tenant_keys(&master_key, &tenant_id);
            assert!(
                result2.is_err(),
                "Same invalid inputs should consistently fail"
            );
        }
    }

    // Test specific edge cases to maximize coverage
    test_edge_cases(&master_key, &tenant_id);
});

fn test_edge_cases(master_key: &[u8], tenant_id: &str) {
    // Edge case: Empty tenant ID (should fail)
    if master_key.len() >= 16 {
        let result = derive_tenant_keys(master_key, "");
        // Empty tenant ID should be rejected
        assert!(result.is_err(), "Empty tenant ID should fail");
    }

    // Edge case: Very long tenant ID
    let long_tenant = "x".repeat(10000);
    if master_key.len() >= 16 {
        match derive_tenant_keys(master_key, &long_tenant) {
            Ok(keys) => {
                assert_eq!(keys.tenant_id, long_tenant);
                assert_eq!(keys.encryption_key.len(), 32);
            }
            Err(_) => {
                // Acceptable failure
            }
        }
    }

    // Edge case: Unicode tenant IDs
    let unicode_tenants = [
        "tenant_αβγ",           // Greek letters
        "tenant_中文",          // Chinese characters
        "tenant_🔐🔑",         // Emojis
        "tenant\u{200B}zero",   // Zero-width space
    ];

    for unicode_tenant in &unicode_tenants {
        if master_key.len() >= 16 {
            match derive_tenant_keys(master_key, unicode_tenant) {
                Ok(keys) => {
                    assert_eq!(keys.tenant_id, *unicode_tenant);
                    assert_eq!(keys.encryption_key.len(), 32);
                }
                Err(_) => {
                    // Acceptable failure
                }
            }
        }
    }

    // Edge case: Tenant IDs with special characters
    let special_tenants = [
        "tenant/../admin",      // Path traversal
        "tenant\x00null",        // Null byte
        "tenant\nCRLF\r",       // Control characters
        "tenant\tTAB",          // Tab characters
    ];

    for special_tenant in &special_tenants {
        if master_key.len() >= 16 {
            let _ = derive_tenant_keys(master_key, special_tenant);
            // Just verify no panic - any result is acceptable
        }
    }

    // Edge case: Master key exactly 16 bytes (minimum valid)
    if master_key.len() >= 16 && !tenant_id.is_empty() {
        let min_key = &master_key[..16];
        match derive_tenant_keys(min_key, tenant_id) {
            Ok(keys) => {
                assert_eq!(keys.encryption_key.len(), 32);
            }
            Err(_) => {
                // Acceptable failure
            }
        }
    }

    // Edge case: Master key less than 16 bytes (should fail)
    if master_key.len() < 16 && !tenant_id.is_empty() {
        let result = derive_tenant_keys(master_key, tenant_id);
        assert!(result.is_err(), "Short master key should fail");
    }
}
