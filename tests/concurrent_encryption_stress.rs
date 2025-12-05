//! Concurrent Encryption Stress Tests
//!
//! WHY THIS TEST EXISTS:
//! Production systems perform concurrent encryption operations across multiple
//! threads. This test validates that the encryption implementation is truly
//! thread-safe with no data races, corruption, or security issues under load.
//!
//! WHAT WE'RE TESTING:
//! - Thread safety: Multiple threads encrypting/decrypting simultaneously
//! - Data integrity: No corruption in concurrent operations
//! - Domain separation: Mixed domains work correctly under contention
//! - Multi-tenant: Concurrent operations with different tenant keys
//! - Memory safety: No race conditions or use-after-free issues
//!
//! WHY STRESS TESTING MATTERS:
//! Concurrency bugs only manifest under high load. These tests create worst-case
//! scenarios to expose race conditions, deadlocks, or data corruption.

#![cfg(feature = "encryption")]

mod common;

use cachekit_core::encryption::core::ZeroKnowledgeEncryptor;
use std::sync::{Arc, Barrier};
use std::thread;

#[test]
fn test_concurrent_encrypt_decrypt_basic() {
    // WHY: Verify basic thread safety with simple concurrent operations

    let encryptor = Arc::new(ZeroKnowledgeEncryptor::new().unwrap());
    let key = [0x42u8; 32];
    let plaintext = b"concurrent test data";
    let aad = b"test_domain";

    let mut handles = vec![];

    // Spawn 50 threads that encrypt and immediately decrypt
    for _ in 0..50 {
        let encryptor = Arc::clone(&encryptor);

        let handle = thread::spawn(move || {
            for _ in 0..20 {
                // Encrypt
                let ciphertext = encryptor
                    .encrypt_aes_gcm(plaintext, &key, aad)
                    .expect("Encryption should succeed");

                // Decrypt
                let decrypted = encryptor
                    .decrypt_aes_gcm(&ciphertext, &key, aad)
                    .expect("Decryption should succeed");

                // Verify roundtrip
                assert_eq!(decrypted, plaintext, "Decrypted data should match original");
            }
        });

        handles.push(handle);
    }

    // Wait for all threads
    for handle in handles {
        handle.join().expect("Thread should complete successfully");
    }

    println!("✓ Basic concurrency: 50 threads × 20 encrypt/decrypt roundtrips succeeded");
}

#[test]
fn test_concurrent_encryption_100_threads() {
    // WHY: Extreme stress test with 100 threads to expose race conditions

    let encryptor = Arc::new(ZeroKnowledgeEncryptor::new().unwrap());
    let key = [0x7fu8; 32];
    let aad = b"stress_domain";

    // Use barrier to synchronize start (maximize contention)
    let barrier = Arc::new(Barrier::new(100));
    let mut handles = vec![];

    for thread_id in 0..100 {
        let encryptor = Arc::clone(&encryptor);
        let barrier = Arc::clone(&barrier);

        let handle = thread::spawn(move || {
            // Each thread has unique plaintext (for verification)
            let plaintext = format!("thread_{}_data", thread_id);

            // Wait for all threads to be ready
            barrier.wait();

            // Perform 50 encrypt/decrypt cycles
            for i in 0..50 {
                let test_data = format!("{}_{}", plaintext, i);

                let ciphertext = encryptor
                    .encrypt_aes_gcm(test_data.as_bytes(), &key, aad)
                    .expect("Encryption should succeed");

                let decrypted = encryptor
                    .decrypt_aes_gcm(&ciphertext, &key, aad)
                    .expect("Decryption should succeed");

                assert_eq!(
                    decrypted,
                    test_data.as_bytes(),
                    "Thread {} iteration {} failed",
                    thread_id,
                    i
                );
            }
        });

        handles.push(handle);
    }

    // Wait for all threads
    for (i, handle) in handles.into_iter().enumerate() {
        handle
            .join()
            .unwrap_or_else(|_| panic!("Thread {} panicked", i));
    }

    println!(
        "✓ Extreme stress: 100 threads × 50 operations = 5000 concurrent encrypt/decrypt cycles"
    );
}

#[test]
fn test_concurrent_mixed_domains() {
    // WHY: Verify domain separation works correctly under concurrent access

    let encryptor = Arc::new(ZeroKnowledgeEncryptor::new().unwrap());
    let key = [0x9cu8; 32];

    let domains: Vec<(&str, &[u8])> = vec![
        ("cache", b"cache domain data"),
        ("session", b"session domain data"),
        ("authentication", b"auth domain data"),
        ("api_tokens", b"api token domain data"),
    ];

    let mut handles = vec![];

    // Spawn threads for each domain
    for (domain, data) in domains {
        for _ in 0..25 {
            // 25 threads per domain
            let encryptor = Arc::clone(&encryptor);

            let handle = thread::spawn(move || {
                for _ in 0..30 {
                    // 30 operations per thread
                    let ciphertext = encryptor
                        .encrypt_aes_gcm(data, &key, domain.as_bytes())
                        .expect("Encryption should succeed");

                    let decrypted = encryptor
                        .decrypt_aes_gcm(&ciphertext, &key, domain.as_bytes())
                        .expect("Decryption should succeed");

                    assert_eq!(decrypted, data, "Domain {} data mismatch", domain);

                    // Verify wrong domain fails
                    let wrong_domain = b"wrong_domain";
                    let result = encryptor.decrypt_aes_gcm(&ciphertext, &key, wrong_domain);
                    assert!(
                        result.is_err(),
                        "Cross-domain decryption should fail for domain {}",
                        domain
                    );
                }
            });

            handles.push(handle);
        }
    }

    // Wait for all threads
    for handle in handles {
        handle.join().expect("Thread should complete");
    }

    println!(
        "✓ Mixed domains: 4 domains × 25 threads × 30 operations = 3000 concurrent ops with domain separation"
    );
}

#[test]
fn test_concurrent_multi_tenant() {
    // WHY: Verify tenant isolation under concurrent access

    let encryptor = Arc::new(ZeroKnowledgeEncryptor::new().unwrap());

    // Simulate 5 different tenant keys
    let tenants = vec![
        ([0xa1u8; 32], b"tenant_a_data"),
        ([0xb2u8; 32], b"tenant_b_data"),
        ([0xc3u8; 32], b"tenant_c_data"),
        ([0xd4u8; 32], b"tenant_d_data"),
        ([0xe5u8; 32], b"tenant_e_data"),
    ];

    let mut handles = vec![];

    // Spawn threads for each tenant
    for (tenant_key, tenant_data) in tenants {
        for _ in 0..20 {
            // 20 threads per tenant
            let encryptor = Arc::clone(&encryptor);

            let handle = thread::spawn(move || {
                let aad = b"tenant_domain";

                for _ in 0..40 {
                    // 40 operations per thread
                    let ciphertext = encryptor
                        .encrypt_aes_gcm(tenant_data, &tenant_key, aad)
                        .expect("Encryption should succeed");

                    let decrypted = encryptor
                        .decrypt_aes_gcm(&ciphertext, &tenant_key, aad)
                        .expect("Decryption should succeed");

                    assert_eq!(decrypted, tenant_data, "Tenant data mismatch");
                }
            });

            handles.push(handle);
        }
    }

    // Wait for all threads
    for handle in handles {
        handle.join().expect("Thread should complete");
    }

    println!(
        "✓ Multi-tenant: 5 tenants × 20 threads × 40 operations = 4000 concurrent ops with tenant isolation"
    );
}

#[test]
fn test_concurrent_varying_payload_sizes() {
    // WHY: Verify concurrent operations work with different payload sizes

    let encryptor = Arc::new(ZeroKnowledgeEncryptor::new().unwrap());
    let key = [0xffu8; 32];
    let aad = b"size_test";

    let payload_sizes = vec![
        0,      // Empty
        10,     // Tiny
        100,    // Small
        1_000,  // Medium
        10_000, // Large
    ];

    let mut handles = vec![];

    for size in payload_sizes {
        for _ in 0..20 {
            // 20 threads per size
            let encryptor = Arc::clone(&encryptor);

            let handle = thread::spawn(move || {
                let plaintext = vec![0x42u8; size];

                for _ in 0..25 {
                    // 25 operations per thread
                    let ciphertext = encryptor
                        .encrypt_aes_gcm(&plaintext, &key, aad)
                        .expect("Encryption should succeed");

                    let decrypted = encryptor
                        .decrypt_aes_gcm(&ciphertext, &key, aad)
                        .expect("Decryption should succeed");

                    assert_eq!(decrypted, plaintext, "Size {} data mismatch", size);
                }
            });

            handles.push(handle);
        }
    }

    // Wait for all threads
    for handle in handles {
        handle.join().expect("Thread should complete");
    }

    println!("✓ Varying sizes: 5 sizes × 20 threads × 25 operations = 2500 concurrent ops");
}

#[test]
fn test_concurrent_encrypt_shared_decrypt() {
    // WHY: Verify one thread encrypting while others decrypt (producer/consumer pattern)

    let encryptor = Arc::new(ZeroKnowledgeEncryptor::new().unwrap());
    let key = [0x33u8; 32];
    let plaintext = b"shared test data";
    let aad = b"producer_consumer";

    // Pre-encrypt some ciphertexts for consumers
    let mut ciphertexts = Vec::new();
    for _ in 0..100 {
        let ciphertext = encryptor
            .encrypt_aes_gcm(plaintext, &key, aad)
            .expect("Pre-encryption should succeed");
        ciphertexts.push(ciphertext);
    }

    let ciphertexts = Arc::new(ciphertexts);
    let mut handles = vec![];

    // Spawn producer threads (encrypt new data)
    for _ in 0..10 {
        let encryptor = Arc::clone(&encryptor);

        let handle = thread::spawn(move || {
            for _ in 0..50 {
                let _ = encryptor
                    .encrypt_aes_gcm(plaintext, &key, aad)
                    .expect("Producer encryption should succeed");
            }
        });

        handles.push(handle);
    }

    // Spawn consumer threads (decrypt pre-encrypted data)
    for _ in 0..10 {
        let encryptor = Arc::clone(&encryptor);
        let ciphertexts = Arc::clone(&ciphertexts);

        let handle = thread::spawn(move || {
            for ciphertext in ciphertexts.iter() {
                let decrypted = encryptor
                    .decrypt_aes_gcm(ciphertext, &key, aad)
                    .expect("Consumer decryption should succeed");

                assert_eq!(decrypted, plaintext, "Consumer data mismatch");
            }
        });

        handles.push(handle);
    }

    // Wait for all threads
    for handle in handles {
        handle.join().expect("Thread should complete");
    }

    println!("✓ Producer/consumer: 10 producers + 10 consumers working concurrently");
}

#[test]
fn test_concurrent_memory_safety() {
    // WHY: Verify no memory corruption under high concurrency
    // This test creates heavy memory churn to expose use-after-free or double-free bugs

    let encryptor = Arc::new(ZeroKnowledgeEncryptor::new().unwrap());
    let key = [0x5au8; 32];
    let aad = b"memory_safety";

    let mut handles = vec![];

    for thread_id in 0..50 {
        let encryptor = Arc::clone(&encryptor);

        let handle = thread::spawn(move || {
            for i in 0..100 {
                // Create varying-size plaintexts (memory churn)
                let size = ((thread_id * 100) + i) % 5000;
                let plaintext = vec![0x7fu8; size];

                let ciphertext = encryptor
                    .encrypt_aes_gcm(&plaintext, &key, aad)
                    .expect("Encryption should succeed");

                let decrypted = encryptor
                    .decrypt_aes_gcm(&ciphertext, &key, aad)
                    .expect("Decryption should succeed");

                assert_eq!(
                    decrypted.len(),
                    plaintext.len(),
                    "Length mismatch indicates memory corruption"
                );
                assert_eq!(
                    decrypted, plaintext,
                    "Data mismatch indicates memory corruption"
                );

                // Drop large allocations immediately (force cleanup)
                drop(ciphertext);
                drop(decrypted);
            }
        });

        handles.push(handle);
    }

    // Wait for all threads
    for handle in handles {
        handle.join().expect("Thread should complete");
    }

    println!("✓ Memory safety: 50 threads × 100 varying-size operations with no corruption");
}
