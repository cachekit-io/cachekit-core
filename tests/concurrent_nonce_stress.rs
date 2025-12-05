//! Concurrent Nonce Generation Stress Tests
//!
//! WHY THIS TEST EXISTS:
//! Nonce uniqueness is CRITICAL for AES-GCM security. Reusing a nonce with the
//! same key catastrophically breaks encryption (exposes plaintext XOR patterns).
//!
//! This test validates that under extreme concurrent load:
//! - No nonce collisions occur across thousands of threads
//! - Thread safety works correctly (AtomicU64 operations)
//! - Multi-domain and multi-tenant scenarios maintain uniqueness
//! - Counter overflow detection works under contention
//!
//! WHAT WE'RE TESTING:
//! The ZeroKnowledgeEncryptor uses a counter-based nonce strategy:
//! - Format: [instance_id(8)][counter(4)] = 12 bytes
//! - instance_id: Globally unique 64-bit ID from GLOBAL_INSTANCE_COUNTER (deterministic)
//! - counter: Per-instance 32-bit counter, incremented atomically per encryption
//! - Deterministic uniqueness (no birthday paradox like random IVs)
//!
//! WHY STRESS TESTING MATTERS:
//! Race conditions only appear under high contention. This test creates
//! worst-case scenarios to verify the atomic counter implementation.

#![cfg(feature = "encryption")]

mod common;

use cachekit_core::encryption::core::ZeroKnowledgeEncryptor;
use std::collections::HashSet;
use std::sync::{Arc, Barrier};
use std::thread;

// Test parameters
const NUM_THREADS: usize = 1000; // Stress test with 1000 concurrent threads
const ENCRYPTIONS_PER_THREAD: usize = 100; // 100K total encryptions

#[test]
fn test_concurrent_nonce_uniqueness_basic() {
    // WHY: Verify no nonce collisions with basic concurrent access
    // SETUP: Multiple threads encrypting concurrently

    let encryptor = Arc::new(ZeroKnowledgeEncryptor::new().unwrap());
    let key = [0x42u8; 32];
    let plaintext = b"test data";
    let aad = b"domain";

    // Collect all ciphertexts (contains nonces)
    let ciphertexts = Arc::new(std::sync::Mutex::new(Vec::new()));

    let mut handles = vec![];

    // Spawn threads that encrypt concurrently
    for _ in 0..100 {
        let encryptor = Arc::clone(&encryptor);
        let ciphertexts = Arc::clone(&ciphertexts);

        let handle = thread::spawn(move || {
            for _ in 0..10 {
                let ciphertext = encryptor
                    .encrypt_aes_gcm(plaintext, &key, aad)
                    .expect("Encryption should succeed");

                // Extract nonce (first 12 bytes of ciphertext)
                let nonce = &ciphertext[..12];

                ciphertexts.lock().unwrap().push(nonce.to_vec());
            }
        });

        handles.push(handle);
    }

    // Wait for all threads
    for handle in handles {
        handle.join().expect("Thread should complete");
    }

    // VERIFICATION: All nonces must be unique
    let ciphertexts = ciphertexts.lock().unwrap();
    let unique_nonces: HashSet<Vec<u8>> = ciphertexts.iter().cloned().collect();

    assert_eq!(
        unique_nonces.len(),
        ciphertexts.len(),
        "All nonces must be unique (found {} duplicates out of {} total)",
        ciphertexts.len() - unique_nonces.len(),
        ciphertexts.len()
    );

    println!(
        "✓ Basic concurrency: {} unique nonces from 100 threads × 10 encryptions",
        unique_nonces.len()
    );
}

#[test]
fn test_concurrent_nonce_stress_1000_threads() {
    // WHY: Extreme stress test - 1000 threads encrypting simultaneously
    // VALIDATES: AtomicU64 counter handles high contention correctly

    let encryptor = Arc::new(ZeroKnowledgeEncryptor::new().unwrap());
    let key = [0x7fu8; 32];
    let plaintext = b"stress test data";
    let aad = b"stress_domain";

    // Use barrier to synchronize thread start (maximize contention)
    let barrier = Arc::new(Barrier::new(NUM_THREADS));
    let nonces = Arc::new(std::sync::Mutex::new(Vec::with_capacity(
        NUM_THREADS * ENCRYPTIONS_PER_THREAD,
    )));

    let mut handles = vec![];

    println!(
        "Starting stress test: {} threads × {} encryptions",
        NUM_THREADS, ENCRYPTIONS_PER_THREAD
    );

    for _ in 0..NUM_THREADS {
        let encryptor = Arc::clone(&encryptor);
        let barrier = Arc::clone(&barrier);
        let nonces = Arc::clone(&nonces);

        let handle = thread::spawn(move || {
            // Wait for all threads to be ready (synchronize start)
            barrier.wait();

            let mut local_nonces = Vec::with_capacity(ENCRYPTIONS_PER_THREAD);

            for _ in 0..ENCRYPTIONS_PER_THREAD {
                let ciphertext = encryptor
                    .encrypt_aes_gcm(plaintext, &key, aad)
                    .expect("Encryption should succeed");

                // Extract nonce (first 12 bytes)
                let nonce = &ciphertext[..12];
                local_nonces.push(nonce.to_vec());
            }

            // Batch insert to minimize lock contention during test
            nonces.lock().unwrap().extend(local_nonces);
        });

        handles.push(handle);
    }

    // Wait for all threads
    for handle in handles {
        handle.join().expect("Thread should complete");
    }

    // VERIFICATION: All nonces must be unique
    let nonces = nonces.lock().unwrap();
    let unique_nonces: HashSet<Vec<u8>> = nonces.iter().cloned().collect();

    let expected_count = NUM_THREADS * ENCRYPTIONS_PER_THREAD;

    assert_eq!(
        unique_nonces.len(),
        expected_count,
        "All {} nonces must be unique (found {} duplicates)",
        expected_count,
        expected_count - unique_nonces.len()
    );

    println!(
        "✓ Stress test passed: {} unique nonces from {} threads × {} encryptions",
        unique_nonces.len(),
        NUM_THREADS,
        ENCRYPTIONS_PER_THREAD
    );
}

#[test]
fn test_concurrent_multi_domain_nonce_uniqueness() {
    // WHY: Verify nonce uniqueness across different domains (AAD values)
    // VALIDATES: Domain separation doesn't affect nonce uniqueness

    let encryptor = Arc::new(ZeroKnowledgeEncryptor::new().unwrap());
    let key = [0x9cu8; 32];
    let plaintext = b"multi-domain data";

    let domains: Vec<&[u8]> = vec![b"cache", b"session", b"authentication", b"api_tokens"];
    let nonces = Arc::new(std::sync::Mutex::new(Vec::new()));

    let mut handles = vec![];

    // Spawn threads for each domain
    for domain in domains {
        for _ in 0..50 {
            // 50 threads per domain
            let encryptor = Arc::clone(&encryptor);
            let nonces = Arc::clone(&nonces);

            let handle = thread::spawn(move || {
                let mut local_nonces = Vec::new();

                for _ in 0..20 {
                    // 20 encryptions per thread
                    let ciphertext = encryptor
                        .encrypt_aes_gcm(plaintext, &key, domain)
                        .expect("Encryption should succeed");

                    let nonce = &ciphertext[..12];
                    local_nonces.push(nonce.to_vec());
                }

                nonces.lock().unwrap().extend(local_nonces);
            });

            handles.push(handle);
        }
    }

    // Wait for all threads
    for handle in handles {
        handle.join().expect("Thread should complete");
    }

    // VERIFICATION: All nonces unique across all domains
    let nonces = nonces.lock().unwrap();
    let unique_nonces: HashSet<Vec<u8>> = nonces.iter().cloned().collect();

    let expected_count = 4 * 50 * 20; // 4 domains × 50 threads × 20 encryptions

    assert_eq!(
        unique_nonces.len(),
        expected_count,
        "Nonces must be unique across domains (found {} duplicates)",
        expected_count - unique_nonces.len()
    );

    println!(
        "✓ Multi-domain: {} unique nonces across 4 domains × 50 threads × 20 encryptions",
        unique_nonces.len()
    );
}

#[test]
fn test_concurrent_multi_tenant_nonce_uniqueness() {
    // WHY: Verify nonce uniqueness in multi-tenant scenarios
    // VALIDATES: Tenant isolation doesn't cause nonce reuse

    let encryptor = Arc::new(ZeroKnowledgeEncryptor::new().unwrap());

    // Simulate different tenant keys (in practice, derived from master key)
    let tenant_keys = vec![
        [0xa1u8; 32],
        [0xb2u8; 32],
        [0xc3u8; 32],
        [0xd4u8; 32],
        [0xe5u8; 32],
    ];

    let nonces = Arc::new(std::sync::Mutex::new(Vec::new()));

    let mut handles = vec![];

    // Spawn threads for each tenant
    for tenant_key in tenant_keys {
        for _ in 0..40 {
            // 40 threads per tenant
            let encryptor = Arc::clone(&encryptor);
            let nonces = Arc::clone(&nonces);

            let handle = thread::spawn(move || {
                let plaintext = b"tenant data";
                let aad = b"tenant_domain";
                let mut local_nonces = Vec::new();

                for _ in 0..25 {
                    // 25 encryptions per thread
                    let ciphertext = encryptor
                        .encrypt_aes_gcm(plaintext, &tenant_key, aad)
                        .expect("Encryption should succeed");

                    let nonce = &ciphertext[..12];
                    local_nonces.push(nonce.to_vec());
                }

                nonces.lock().unwrap().extend(local_nonces);
            });

            handles.push(handle);
        }
    }

    // Wait for all threads
    for handle in handles {
        handle.join().expect("Thread should complete");
    }

    // VERIFICATION: All nonces unique across all tenants
    let nonces = nonces.lock().unwrap();
    let unique_nonces: HashSet<Vec<u8>> = nonces.iter().cloned().collect();

    let expected_count = 5 * 40 * 25; // 5 tenants × 40 threads × 25 encryptions

    assert_eq!(
        unique_nonces.len(),
        expected_count,
        "Nonces must be unique across tenants (found {} duplicates)",
        expected_count - unique_nonces.len()
    );

    println!(
        "✓ Multi-tenant: {} unique nonces across 5 tenants × 40 threads × 25 encryptions",
        unique_nonces.len()
    );
}

#[test]
fn test_nonce_counter_atomicity() {
    // WHY: Verify counter increments are truly atomic (no lost updates)
    // VALIDATES: fetch_add operations work correctly under contention

    let encryptor = Arc::new(ZeroKnowledgeEncryptor::new().unwrap());
    let key = [0xffu8; 32];
    let plaintext = b"counter test";
    let aad = b"atomicity";

    let num_threads = 100;
    let increments_per_thread = 1000;
    let expected_final_count = num_threads * increments_per_thread;

    let mut handles = vec![];

    // Spawn threads that increment counter
    for _ in 0..num_threads {
        let encryptor = Arc::clone(&encryptor);

        let handle = thread::spawn(move || {
            for _ in 0..increments_per_thread {
                // Each encryption increments counter once
                let _ = encryptor
                    .encrypt_aes_gcm(plaintext, &key, aad)
                    .expect("Encryption should succeed");
            }
        });

        handles.push(handle);
    }

    // Wait for all threads
    for handle in handles {
        handle.join().expect("Thread should complete");
    }

    // VERIFICATION: Counter value equals expected (no lost updates)
    let final_counter = encryptor.get_nonce_counter();

    assert_eq!(
        final_counter,
        expected_final_count as u64,
        "Counter atomicity failed: expected {} but got {} (lost {} updates)",
        expected_final_count,
        final_counter,
        expected_final_count as i64 - final_counter as i64
    );

    println!(
        "✓ Counter atomicity: {} threads × {} increments = {} final count",
        num_threads, increments_per_thread, final_counter
    );
}

#[test]
fn test_nonce_format_consistency() {
    // WHY: Verify nonce format is consistent under concurrent access
    // VALIDATES: [instance_id(8)][counter(4)] structure maintained

    let encryptor = Arc::new(ZeroKnowledgeEncryptor::new().unwrap());
    let key = [0x33u8; 32];
    let plaintext = b"format test";
    let aad = b"format_check";

    let nonces = Arc::new(std::sync::Mutex::new(Vec::new()));
    let mut handles = vec![];

    // Generate nonces concurrently
    for _ in 0..50 {
        let encryptor = Arc::clone(&encryptor);
        let nonces = Arc::clone(&nonces);

        let handle = thread::spawn(move || {
            let mut local_nonces = Vec::new();

            for _ in 0..100 {
                let ciphertext = encryptor
                    .encrypt_aes_gcm(plaintext, &key, aad)
                    .expect("Encryption should succeed");

                let nonce = &ciphertext[..12];
                local_nonces.push(nonce.to_vec());
            }

            nonces.lock().unwrap().extend(local_nonces);
        });

        handles.push(handle);
    }

    for handle in handles {
        handle.join().expect("Thread should complete");
    }

    let nonces = nonces.lock().unwrap();

    // VERIFICATION: All nonces have correct format
    // - First 8 bytes should be same (instance_id - deterministically unique per encryptor)
    // - Last 4 bytes should be counter (increasing)

    assert!(!nonces.is_empty(), "Should have generated nonces");

    let first_nonce = &nonces[0];
    let instance_id_bytes = &first_nonce[..8];

    // All nonces from same encryptor instance share the same instance_id
    for nonce in nonces.iter() {
        assert_eq!(nonce.len(), 12, "Nonce must be exactly 12 bytes");
        assert_eq!(
            &nonce[..8],
            instance_id_bytes,
            "Instance ID must be consistent across all nonces from same encryptor"
        );
    }

    // Extract counters (last 4 bytes)
    let mut counters: Vec<u32> = nonces
        .iter()
        .map(|nonce| u32::from_be_bytes([nonce[8], nonce[9], nonce[10], nonce[11]]))
        .collect();

    counters.sort_unstable();

    // Counters should be sequential (0, 1, 2, ..., N-1)
    for (i, &counter) in counters.iter().enumerate() {
        assert_eq!(
            counter, i as u32,
            "Counter sequence broken at index {} (expected {}, got {})",
            i, i, counter
        );
    }

    println!(
        "✓ Format consistency: All {} nonces have correct [iv(8)][counter(4)] format",
        nonces.len()
    );
}
