/*
 * encryption.c - Encryption module implementation for SecFS
 * 
 * Secure Encrypted and Versioned Filesystem using FUSE
 * 
 * Implements AES-256-CBC encryption and decryption using OpenSSL's
 * EVP (Envelope) API. Key derivation uses PBKDF2 with HMAC-SHA256.
 * 
 * Encrypted file format on disk:
 *   [16-byte random IV][4-byte uint32_t original_size][AES-256-CBC ciphertext]
 * 
 * Security notes:
 *   - A fresh random IV is generated for every write operation
 *   - PKCS#7 padding is handled automatically by OpenSSL EVP
 *   - The derived key is stored in memory; zeroed on cleanup
 */

#include "encryption.h"
#include "common.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

/* ============================================================
 * Module State
 * ============================================================ */

/* Derived AES-256 key (32 bytes) - derived from passphrase via PBKDF2 */
static unsigned char derived_key[AES_KEY_SIZE];

/* Flag indicating whether the encryption subsystem is initialized */
static int encryption_initialized = 0;

/* ============================================================
 * Internal Helper Functions
 * ============================================================ */

/*
 * print_openssl_errors - Print any pending OpenSSL errors to stderr
 */
static void print_openssl_errors(void)
{
    unsigned long err;
    while ((err = ERR_get_error()) != 0) {
        char err_buf[256];
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        SECFS_ERROR("OpenSSL error: %s", err_buf);
    }
}

/* ============================================================
 * Public API Implementation
 * ============================================================ */

int encryption_init(const char *passphrase)
{
    if (encryption_initialized) {
        SECFS_DEBUG("Encryption already initialized");
        return 0;
    }

    if (!passphrase || strlen(passphrase) == 0) {
        SECFS_ERROR("Empty passphrase provided");
        return -1;
    }

    /*
     * Derive a 256-bit key from the passphrase using PBKDF2.
     * 
     * PBKDF2 (Password-Based Key Derivation Function 2) stretches
     * a potentially weak passphrase into a cryptographically strong
     * key by applying HMAC-SHA256 iteratively.
     * 
     * Parameters:
     *   passphrase  - The user-provided password
     *   salt        - Prevents rainbow table attacks
     *   iterations  - Makes brute-force attacks slower
     *   EVP_sha256  - Hash function for HMAC
     *   AES_KEY_SIZE - Output key length (32 bytes for AES-256)
     */
    int ret = PKCS5_PBKDF2_HMAC(
        passphrase, strlen(passphrase),                      /* passphrase */
        (const unsigned char *)PBKDF2_SALT, strlen(PBKDF2_SALT), /* salt */
        PBKDF2_ITERATIONS,                                    /* iterations */
        EVP_sha256(),                                         /* hash function */
        AES_KEY_SIZE,                                         /* output key length */
        derived_key                                           /* output key buffer */
    );

    if (ret != 1) {
        print_openssl_errors();
        SECFS_ERROR("PBKDF2 key derivation failed");
        return -1;
    }

    encryption_initialized = 1;
    SECFS_DEBUG("Encryption initialized successfully (PBKDF2 + AES-256-CBC)");
    return 0;
}

void encryption_cleanup(void)
{
    if (encryption_initialized) {
        /* Securely zero the key material from memory */
        OPENSSL_cleanse(derived_key, AES_KEY_SIZE);
        encryption_initialized = 0;
        SECFS_DEBUG("Encryption cleaned up, key material zeroed");
    }
}

int encrypt_data(const unsigned char *plaintext, size_t plaintext_len,
                 unsigned char *ciphertext, size_t *ciphertext_len)
{
    if (!encryption_initialized) {
        SECFS_ERROR("Encryption not initialized");
        return -1;
    }

    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char iv[AES_IV_SIZE];
    int len = 0;
    int total_len = 0;
    int ret = -1;

    /*
     * Step 1: Generate a random IV for this encryption
     * 
     * Using a unique random IV for each write is critical for CBC mode
     * security. Without this, identical plaintexts would produce
     * identical ciphertexts, leaking information.
     */
    if (RAND_bytes(iv, AES_IV_SIZE) != 1) {
        print_openssl_errors();
        SECFS_ERROR("Failed to generate random IV");
        return -1;
    }

    /*
     * Step 2: Write the file header
     * 
     * Format: [16-byte IV][4-byte original_size]
     * 
     * We store the IV so we can read it back during decryption.
     * We store the original size so we know the exact plaintext
     * length after removing PKCS#7 padding.
     */
    memcpy(ciphertext, iv, AES_IV_SIZE);
    uint32_t orig_size = (uint32_t)plaintext_len;
    memcpy(ciphertext + AES_IV_SIZE, &orig_size, sizeof(uint32_t));
    total_len = AES_IV_SIZE + sizeof(uint32_t);

    /*
     * Step 3: Create and initialize the cipher context
     */
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        print_openssl_errors();
        SECFS_ERROR("Failed to create cipher context");
        return -1;
    }

    /*
     * Step 4: Initialize AES-256-CBC encryption
     * 
     * EVP_aes_256_cbc() selects:
     *   - AES algorithm
     *   - 256-bit key size
     *   - CBC (Cipher Block Chaining) mode
     */
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, derived_key, iv) != 1) {
        print_openssl_errors();
        SECFS_ERROR("EVP_EncryptInit_ex failed");
        goto cleanup;
    }

    /*
     * Step 5: Encrypt the plaintext
     * 
     * EVP_EncryptUpdate processes the input data. For CBC mode,
     * it may buffer up to one block of data internally.
     */
    if (EVP_EncryptUpdate(ctx, ciphertext + total_len, &len,
                          plaintext, plaintext_len) != 1) {
        print_openssl_errors();
        SECFS_ERROR("EVP_EncryptUpdate failed");
        goto cleanup;
    }
    total_len += len;

    /*
     * Step 6: Finalize encryption
     * 
     * EVP_EncryptFinal_ex outputs any remaining buffered data
     * and adds PKCS#7 padding to fill the last block.
     */
    if (EVP_EncryptFinal_ex(ctx, ciphertext + total_len, &len) != 1) {
        print_openssl_errors();
        SECFS_ERROR("EVP_EncryptFinal_ex failed");
        goto cleanup;
    }
    total_len += len;

    *ciphertext_len = total_len;
    ret = 0;

    SECFS_DEBUG("Encrypted %zu bytes -> %d bytes", plaintext_len, total_len);

cleanup:
    if (ctx) {
        EVP_CIPHER_CTX_free(ctx);
    }
    return ret;
}

int decrypt_data(const unsigned char *ciphertext, size_t ciphertext_len,
                 unsigned char *plaintext, size_t *plaintext_len)
{
    if (!encryption_initialized) {
        SECFS_ERROR("Encryption not initialized");
        return -1;
    }

    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char iv[AES_IV_SIZE];
    uint32_t orig_size;
    int len = 0;
    int total_len = 0;
    int ret = -1;

    /*
     * Step 1: Validate minimum ciphertext length
     * 
     * We need at least the header (IV + original_size) plus
     * one block of encrypted data.
     */
    size_t header_size = AES_IV_SIZE + sizeof(uint32_t);
    if (ciphertext_len < header_size) {
        SECFS_ERROR("Ciphertext too short: %zu bytes (need at least %zu)",
                   ciphertext_len, header_size);
        return -1;
    }

    /*
     * Step 2: Read the file header
     * 
     * Extract the IV and original plaintext size from the header.
     */
    memcpy(iv, ciphertext, AES_IV_SIZE);
    memcpy(&orig_size, ciphertext + AES_IV_SIZE, sizeof(uint32_t));

    /* Pointer to the actual encrypted data (after header) */
    const unsigned char *enc_data = ciphertext + header_size;
    size_t enc_data_len = ciphertext_len - header_size;

    /*
     * Step 3: Create and initialize the cipher context for decryption
     */
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        print_openssl_errors();
        SECFS_ERROR("Failed to create cipher context");
        return -1;
    }

    /*
     * Step 4: Initialize AES-256-CBC decryption with the stored IV
     */
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, derived_key, iv) != 1) {
        print_openssl_errors();
        SECFS_ERROR("EVP_DecryptInit_ex failed");
        goto cleanup;
    }

    /*
     * Step 5: Decrypt the ciphertext
     */
    if (EVP_DecryptUpdate(ctx, plaintext, &len, enc_data, enc_data_len) != 1) {
        print_openssl_errors();
        SECFS_ERROR("EVP_DecryptUpdate failed");
        goto cleanup;
    }
    total_len += len;

    /*
     * Step 6: Finalize decryption
     * 
     * EVP_DecryptFinal_ex removes PKCS#7 padding and validates it.
     * If the key is wrong, this will fail (padding check failure).
     */
    if (EVP_DecryptFinal_ex(ctx, plaintext + total_len, &len) != 1) {
        print_openssl_errors();
        SECFS_ERROR("EVP_DecryptFinal_ex failed (wrong key or corrupted data?)");
        goto cleanup;
    }
    total_len += len;

    /*
     * Use the stored original size to return exact plaintext length.
     * This avoids any ambiguity from padding removal.
     */
    *plaintext_len = (size_t)orig_size;
    ret = 0;

    SECFS_DEBUG("Decrypted %zu bytes -> %u bytes", ciphertext_len, orig_size);

cleanup:
    if (ctx) {
        EVP_CIPHER_CTX_free(ctx);
    }
    return ret;
}

size_t get_encrypted_size(size_t plaintext_len)
{
    /*
     * Total encrypted size calculation:
     *   - 16 bytes for the IV
     *   - 4 bytes for the original size
     *   - plaintext_len rounded up to next AES block boundary
     *   - 1 extra AES block for PKCS#7 padding (worst case)
     */
    size_t padded_len = ((plaintext_len / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;
    return AES_IV_SIZE + sizeof(uint32_t) + padded_len;
}
