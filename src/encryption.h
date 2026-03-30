/*
 * encryption.h - Encryption module header for SecFS
 * 
 * Secure Encrypted and Versioned Filesystem using FUSE
 * 
 * Provides AES-256-CBC encryption and decryption functions
 * using OpenSSL's EVP API with PBKDF2 key derivation.
 */

#ifndef SECFS_ENCRYPTION_H
#define SECFS_ENCRYPTION_H

#include <stddef.h>
#include <stdint.h>

/*
 * encryption_init - Initialize the encryption subsystem
 * 
 * Derives the AES-256 key from the passphrase using PBKDF2.
 * Must be called once before any encrypt/decrypt operations.
 * 
 * Parameters:
 *   passphrase - The passphrase to derive the key from
 * 
 * Returns:
 *   0 on success, -1 on error
 */
int encryption_init(const char *passphrase);

/*
 * encryption_cleanup - Clean up the encryption subsystem
 * 
 * Securely zeros and frees the derived key material.
 */
void encryption_cleanup(void);

/*
 * encrypt_data - Encrypt plaintext data using AES-256-CBC
 * 
 * Generates a random IV for each encryption operation.
 * Output format: [16-byte IV][4-byte original_size][ciphertext]
 * 
 * Parameters:
 *   plaintext       - Input data to encrypt
 *   plaintext_len   - Length of input data
 *   ciphertext      - Output buffer (must be large enough)
 *   ciphertext_len  - Output: actual length of encrypted data
 * 
 * Returns:
 *   0 on success, -1 on error
 * 
 * Note: ciphertext buffer should be at least:
 *       plaintext_len + AES_BLOCK_SIZE + ENCRYPTED_HEADER_SIZE
 */
int encrypt_data(const unsigned char *plaintext, size_t plaintext_len,
                 unsigned char *ciphertext, size_t *ciphertext_len);

/*
 * decrypt_data - Decrypt ciphertext data using AES-256-CBC
 * 
 * Reads the IV from the ciphertext header.
 * Input format: [16-byte IV][4-byte original_size][ciphertext]
 * 
 * Parameters:
 *   ciphertext      - Input encrypted data (with header)
 *   ciphertext_len  - Length of encrypted data 
 *   plaintext       - Output buffer for decrypted data
 *   plaintext_len   - Output: actual length of decrypted data
 * 
 * Returns:
 *   0 on success, -1 on error
 */
int decrypt_data(const unsigned char *ciphertext, size_t ciphertext_len,
                 unsigned char *plaintext, size_t *plaintext_len);

/*
 * get_encrypted_size - Calculate the encrypted size for a given plaintext size
 * 
 * Parameters:
 *   plaintext_len - Size of the plaintext data
 * 
 * Returns:
 *   Total size of the encrypted output including headers
 */
size_t get_encrypted_size(size_t plaintext_len);

#endif /* SECFS_ENCRYPTION_H */
