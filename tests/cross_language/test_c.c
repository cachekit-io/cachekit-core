/* C99 test harness for cachekit-core FFI
 * Tests compression, encryption, and error handling
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "../../include/cachekit.h"

/* ANSI color codes for output */
#define GREEN "\033[0;32m"
#define RED "\033[0;31m"
#define RESET "\033[0m"

/* Test result tracking */
static int total_tests = 0;
static int passed_tests = 0;

void report_test(const char* name, bool success) {
    total_tests++;
    if (success) {
        passed_tests++;
        printf(GREEN "PASS" RESET ": %s\n", name);
    } else {
        printf(RED "FAIL" RESET ": %s\n", name);
    }
}

/* ========== COMPRESSION TESTS ========== */

int test_compress_decompress_roundtrip(void) {
    const char* input = "Hello, CacheKit FFI! This is a test of LZ4 compression with xxHash3-64 checksums.";
    size_t input_len = strlen(input);

    /* Compress */
    uint8_t compressed[4096];
    size_t compressed_len = sizeof(compressed);

    enum CACHEKIT_CachekitError err = cachekit_compress(
        (const uint8_t*)input, input_len,
        compressed, &compressed_len
    );

    if (err != OK) {
        printf("  compress returned error %d\n", err);
        return 1;
    }

    if (compressed_len == 0 || compressed_len >= input_len + 100) {
        printf("  suspicious compressed size: %zu\n", compressed_len);
        return 1;
    }

    /* Decompress */
    uint8_t decompressed[4096];
    size_t decompressed_len = sizeof(decompressed);

    err = cachekit_decompress(
        compressed, compressed_len,
        decompressed, &decompressed_len
    );

    if (err != OK) {
        printf("  decompress returned error %d\n", err);
        return 1;
    }

    /* Verify */
    if (decompressed_len != input_len) {
        printf("  length mismatch: expected %zu, got %zu\n", input_len, decompressed_len);
        return 1;
    }

    if (memcmp(input, decompressed, input_len) != 0) {
        printf("  data mismatch after roundtrip\n");
        return 1;
    }

    return 0;
}

int test_compress_null_pointer_input(void) {
    uint8_t output[1024];
    size_t output_len = sizeof(output);

    enum CACHEKIT_CachekitError err = cachekit_compress(
        NULL, 100,
        output, &output_len
    );

    if (err != NULL_POINTER) {
        printf("  expected NULL_POINTER, got %d\n", err);
        return 1;
    }

    return 0;
}

int test_compress_null_pointer_output(void) {
    const char* input = "test data";
    size_t output_len = 1024;

    enum CACHEKIT_CachekitError err = cachekit_compress(
        (const uint8_t*)input, strlen(input),
        NULL, &output_len
    );

    if (err != NULL_POINTER) {
        printf("  expected NULL_POINTER, got %d\n", err);
        return 1;
    }

    return 0;
}

int test_compress_null_pointer_output_len(void) {
    const char* input = "test data";
    uint8_t output[1024];

    enum CACHEKIT_CachekitError err = cachekit_compress(
        (const uint8_t*)input, strlen(input),
        output, NULL
    );

    if (err != NULL_POINTER) {
        printf("  expected NULL_POINTER, got %d\n", err);
        return 1;
    }

    return 0;
}

int test_compress_buffer_too_small(void) {
    const char* input = "This is a longer string that should require more space when compressed";
    size_t input_len = strlen(input);

    uint8_t output[10]; /* Intentionally too small */
    size_t output_len = sizeof(output);
    size_t original_output_len = output_len;

    enum CACHEKIT_CachekitError err = cachekit_compress(
        (const uint8_t*)input, input_len,
        output, &output_len
    );

    if (err != BUFFER_TOO_SMALL) {
        printf("  expected BUFFER_TOO_SMALL, got %d\n", err);
        return 1;
    }

    /* Verify output_len was updated with required size */
    if (output_len <= original_output_len) {
        printf("  output_len not updated: %zu (should be > %zu)\n", output_len, original_output_len);
        return 1;
    }

    return 0;
}

int test_decompress_corrupted_data(void) {
    /* Random garbage that's not valid compressed data */
    uint8_t corrupted[100];
    for (size_t i = 0; i < sizeof(corrupted); i++) {
        corrupted[i] = (uint8_t)(i * 7 + 13);
    }

    uint8_t output[1024];
    size_t output_len = sizeof(output);

    enum CACHEKIT_CachekitError err = cachekit_decompress(
        corrupted, sizeof(corrupted),
        output, &output_len
    );

    /* Should fail with either INVALID_INPUT, CHECKSUM_MISMATCH, or DECOMPRESSION_FAILED */
    if (err == OK) {
        printf("  corrupted data should not decompress successfully\n");
        return 1;
    }

    return 0;
}

int test_decompress_tampered_checksum(void) {
    const char* input = "Test data for checksum tampering";
    size_t input_len = strlen(input);

    /* Compress valid data */
    uint8_t compressed[1024];
    size_t compressed_len = sizeof(compressed);

    enum CACHEKIT_CachekitError err = cachekit_compress(
        (const uint8_t*)input, input_len,
        compressed, &compressed_len
    );

    if (err != OK) {
        printf("  compress failed: %d\n", err);
        return 1;
    }

    /* Tamper with the compressed data (flip some bits) */
    if (compressed_len > 10) {
        compressed[compressed_len - 5] ^= 0xFF;
    }

    /* Try to decompress tampered data */
    uint8_t output[1024];
    size_t output_len = sizeof(output);

    err = cachekit_decompress(
        compressed, compressed_len,
        output, &output_len
    );

    /* Should fail with CHECKSUM_MISMATCH or DECOMPRESSION_FAILED */
    if (err == OK) {
        printf("  tampered data should not decompress successfully\n");
        return 1;
    }

    return 0;
}

int test_compressed_bound(void) {
    size_t input_len = 1000;
    size_t bound = cachekit_compressed_bound(input_len);

    /* Bound should be larger than input (due to overhead) */
    if (bound <= input_len) {
        printf("  compressed_bound too small: %zu for input %zu\n", bound, input_len);
        return 1;
    }

    /* Bound should be reasonable (not absurdly large) */
    if (bound > input_len * 2 + 1000) {
        printf("  compressed_bound too large: %zu for input %zu\n", bound, input_len);
        return 1;
    }

    return 0;
}

/* ========== ENCRYPTION TESTS ========== */

int test_encrypt_decrypt_roundtrip(void) {
    /* 256-bit key (32 bytes) */
    uint8_t key[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
    };

    const char* plaintext = "Secret message for zero-knowledge encryption test";
    size_t plaintext_len = strlen(plaintext);

    const char* aad = "tenant-id-12345";
    size_t aad_len = strlen(aad);

    /* Create encryptor */
    struct CACHEKIT_CachekitEncryptor* enc = cachekit_encryptor_new();
    if (enc == NULL) {
        printf("  cachekit_encryptor_new returned null\n");
        return 1;
    }

    /* Encrypt */
    uint8_t ciphertext[1024];
    size_t ciphertext_len = sizeof(ciphertext);

    enum CACHEKIT_CachekitError err = cachekit_encrypt(
        enc,
        key, sizeof(key),
        (const uint8_t*)aad, aad_len,
        (const uint8_t*)plaintext, plaintext_len,
        ciphertext, &ciphertext_len
    );

    if (err != OK) {
        printf("  encrypt failed: %d\n", err);
        cachekit_encryptor_free(enc);
        return 1;
    }

    /* Verify ciphertext is longer than plaintext (includes nonce + tag) */
    if (ciphertext_len != plaintext_len + 28) {
        printf("  unexpected ciphertext length: %zu (expected %zu)\n",
               ciphertext_len, plaintext_len + 28);
        cachekit_encryptor_free(enc);
        return 1;
    }

    /* Decrypt */
    uint8_t decrypted[1024];
    size_t decrypted_len = sizeof(decrypted);

    err = cachekit_decrypt(
        key, sizeof(key),
        (const uint8_t*)aad, aad_len,
        ciphertext, ciphertext_len,
        decrypted, &decrypted_len
    );

    if (err != OK) {
        printf("  decrypt failed: %d\n", err);
        cachekit_encryptor_free(enc);
        return 1;
    }

    /* Verify */
    if (decrypted_len != plaintext_len) {
        printf("  length mismatch: expected %zu, got %zu\n", plaintext_len, decrypted_len);
        cachekit_encryptor_free(enc);
        return 1;
    }

    if (memcmp(plaintext, decrypted, plaintext_len) != 0) {
        printf("  data mismatch after roundtrip\n");
        cachekit_encryptor_free(enc);
        return 1;
    }

    cachekit_encryptor_free(enc);
    return 0;
}

int test_encrypt_wrong_aad_fails(void) {
    uint8_t key[32] = {0};
    const char* plaintext = "test";
    const char* aad_encrypt = "correct-aad";
    const char* aad_decrypt = "wrong-aad";

    struct CACHEKIT_CachekitEncryptor* enc = cachekit_encryptor_new();
    if (enc == NULL) {
        return 1;
    }

    /* Encrypt with one AAD */
    uint8_t ciphertext[1024];
    size_t ciphertext_len = sizeof(ciphertext);

    enum CACHEKIT_CachekitError err = cachekit_encrypt(
        enc,
        key, sizeof(key),
        (const uint8_t*)aad_encrypt, strlen(aad_encrypt),
        (const uint8_t*)plaintext, strlen(plaintext),
        ciphertext, &ciphertext_len
    );

    if (err != OK) {
        cachekit_encryptor_free(enc);
        return 1;
    }

    /* Try to decrypt with different AAD */
    uint8_t decrypted[1024];
    size_t decrypted_len = sizeof(decrypted);

    err = cachekit_decrypt(
        key, sizeof(key),
        (const uint8_t*)aad_decrypt, strlen(aad_decrypt),
        ciphertext, ciphertext_len,
        decrypted, &decrypted_len
    );

    if (err != DECRYPTION_FAILED) {
        printf("  expected DECRYPTION_FAILED, got %d\n", err);
        cachekit_encryptor_free(enc);
        return 1;
    }

    cachekit_encryptor_free(enc);
    return 0;
}

int test_encrypt_invalid_key_length(void) {
    uint8_t short_key[16] = {0}; /* Only 128 bits, need 256 */
    const char* plaintext = "test";
    const char* aad = "tenant";

    struct CACHEKIT_CachekitEncryptor* enc = cachekit_encryptor_new();
    if (enc == NULL) {
        return 1;
    }

    uint8_t ciphertext[1024];
    size_t ciphertext_len = sizeof(ciphertext);

    enum CACHEKIT_CachekitError err = cachekit_encrypt(
        enc,
        short_key, sizeof(short_key),
        (const uint8_t*)aad, strlen(aad),
        (const uint8_t*)plaintext, strlen(plaintext),
        ciphertext, &ciphertext_len
    );

    if (err != INVALID_KEY_LENGTH) {
        printf("  expected INVALID_KEY_LENGTH, got %d\n", err);
        cachekit_encryptor_free(enc);
        return 1;
    }

    cachekit_encryptor_free(enc);
    return 0;
}

int test_encryptor_counter(void) {
    struct CACHEKIT_CachekitEncryptor* enc = cachekit_encryptor_new();
    if (enc == NULL) {
        return 1;
    }

    uint64_t initial_counter = cachekit_encryptor_get_counter(enc);

    /* Counter should start at 0 */
    if (initial_counter != 0) {
        printf("  expected initial counter 0, got %llu\n",
               (unsigned long long)initial_counter);
        cachekit_encryptor_free(enc);
        return 1;
    }

    /* Perform encryption */
    uint8_t key[32] = {0};
    const char* plaintext = "test";
    uint8_t ciphertext[1024];
    size_t ciphertext_len = sizeof(ciphertext);

    enum CACHEKIT_CachekitError err = cachekit_encrypt(
        enc,
        key, sizeof(key),
        (const uint8_t*)"", 0,
        (const uint8_t*)plaintext, strlen(plaintext),
        ciphertext, &ciphertext_len
    );

    if (err != OK) {
        cachekit_encryptor_free(enc);
        return 1;
    }

    /* Counter should increment */
    uint64_t after_counter = cachekit_encryptor_get_counter(enc);
    if (after_counter != 1) {
        printf("  expected counter 1 after encryption, got %llu\n",
               (unsigned long long)after_counter);
        cachekit_encryptor_free(enc);
        return 1;
    }

    cachekit_encryptor_free(enc);
    return 0;
}

int test_derive_key_hkdf(void) {
    const uint8_t master[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };

    const char* salt = "tenant-12345";
    const char* domain = "cache-encryption";

    uint8_t derived[32];

    enum CACHEKIT_CachekitError err = cachekit_derive_key(
        master, sizeof(master),
        (const uint8_t*)salt, strlen(salt),
        (const uint8_t*)domain, strlen(domain),
        derived
    );

    if (err != OK) {
        printf("  derive_key failed: %d\n", err);
        return 1;
    }

    /* Derived key should be different from master */
    if (memcmp(master, derived, 32) == 0) {
        printf("  derived key identical to master key\n");
        return 1;
    }

    /* Derive again with same inputs - should be deterministic */
    uint8_t derived2[32];
    err = cachekit_derive_key(
        master, sizeof(master),
        (const uint8_t*)salt, strlen(salt),
        (const uint8_t*)domain, strlen(domain),
        derived2
    );

    if (err != OK || memcmp(derived, derived2, 32) != 0) {
        printf("  key derivation not deterministic\n");
        return 1;
    }

    /* Different salt should produce different key */
    uint8_t derived3[32];
    const char* salt2 = "tenant-67890";
    err = cachekit_derive_key(
        master, sizeof(master),
        (const uint8_t*)salt2, strlen(salt2),
        (const uint8_t*)domain, strlen(domain),
        derived3
    );

    if (err != OK) {
        return 1;
    }

    if (memcmp(derived, derived3, 32) == 0) {
        printf("  different salts produced same derived key\n");
        return 1;
    }

    return 0;
}

int test_derive_key_invalid_master_length(void) {
    const uint8_t short_master[15] = {0}; /* Less than minimum 16 bytes */
    const char* salt = "tenant";
    const char* domain = "cache";
    uint8_t derived[32];

    enum CACHEKIT_CachekitError err = cachekit_derive_key(
        short_master, sizeof(short_master),
        (const uint8_t*)salt, strlen(salt),
        (const uint8_t*)domain, strlen(domain),
        derived
    );

    if (err != INVALID_KEY_LENGTH) {
        printf("  expected INVALID_KEY_LENGTH, got %d\n", err);
        return 1;
    }

    return 0;
}

/* ========== MAIN TEST RUNNER ========== */

int main(void) {
    printf("=== CacheKit C FFI Test Suite ===\n\n");

    printf("--- Compression Tests ---\n");
    report_test("compress_decompress_roundtrip", test_compress_decompress_roundtrip() == 0);
    report_test("compress_null_pointer_input", test_compress_null_pointer_input() == 0);
    report_test("compress_null_pointer_output", test_compress_null_pointer_output() == 0);
    report_test("compress_null_pointer_output_len", test_compress_null_pointer_output_len() == 0);
    report_test("compress_buffer_too_small", test_compress_buffer_too_small() == 0);
    report_test("decompress_corrupted_data", test_decompress_corrupted_data() == 0);
    report_test("decompress_tampered_checksum", test_decompress_tampered_checksum() == 0);
    report_test("compressed_bound", test_compressed_bound() == 0);

    printf("\n--- Encryption Tests ---\n");
    report_test("encrypt_decrypt_roundtrip", test_encrypt_decrypt_roundtrip() == 0);
    report_test("encrypt_wrong_aad_fails", test_encrypt_wrong_aad_fails() == 0);
    report_test("encrypt_invalid_key_length", test_encrypt_invalid_key_length() == 0);
    report_test("encryptor_counter", test_encryptor_counter() == 0);
    report_test("derive_key_hkdf", test_derive_key_hkdf() == 0);
    report_test("derive_key_invalid_master_length", test_derive_key_invalid_master_length() == 0);

    printf("\n=== Summary ===\n");
    printf("Tests run: %d\n", total_tests);
    printf("Passed: " GREEN "%d" RESET "\n", passed_tests);
    printf("Failed: " RED "%d" RESET "\n", total_tests - passed_tests);

    return (passed_tests == total_tests) ? 0 : 1;
}
