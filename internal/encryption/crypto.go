package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha3"
	"fmt"
	"io"
)

// GenerateECDHKeyPair generates a new ECDH P384 private/public key pair.
func GenerateECDHKeyPair() (*ecdh.PrivateKey, *ecdh.PublicKey, error) {
	// P384 returns a Curve which implements NIST P-384.
	privateKey, err := ecdh.P384().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ECDH private key: %w", err)
	}
	publicKey := privateKey.PublicKey()
	return privateKey, publicKey, nil
}

// DeriveSharedSecret derives a shared secret using the local private key and the remote public key.
// The shared secret is then hashed using SHA3-384 to produce a fixed-size key suitable for AES.
func DeriveSharedSecret(privateKey *ecdh.PrivateKey, remotePublicKey *ecdh.PublicKey) ([]byte, error) {
	// ECDH performs the key agreement to derive the shared secret.
	sharedSecret, err := privateKey.ECDH(remotePublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to derive shared secret: %w", err)
	}

	// Hash the shared secret to derive a fixed-size key for AES.
	// SHA3-384 produces a 48-byte hash, which is suitable for AES-256 (32 bytes) or AES-192 (24 bytes).
	// We'll use the first 32 bytes for AES-256.
	hasher := sha3.New384()
	hasher.Write(sharedSecret)
	derivedKey := hasher.Sum(nil)

	// Return the first 32 bytes for AES-256.
	return derivedKey[:32], nil
}

// EncryptAESGCM encrypts plaintext using AES-GCM mode with the provided key.
// It returns the ciphertext and the Initialization Vector (IV).
func EncryptAESGCM(key, plaintext []byte) (ciphertext, iv []byte, err error) {
	// Create a new AES cipher block from the key.
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Create a new GCM cipher mode.
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create GCM cipher: %w", err)
	}

	// Generate a random nonce (IV) for GCM.
	// The nonce size is fixed for GCM (usually 12 bytes).
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Seal encrypts and authenticates the plaintext.
	// The nonce is prepended to the ciphertext for convenience.
	encryptedContent := aesGCM.Seal(nil, nonce, plaintext, nil)

	return encryptedContent, nonce, nil
}

// DecryptAESGCM decrypts ciphertext using AES-GCM mode with the provided key and IV.
func DecryptAESGCM(key, ciphertext, iv []byte) (plaintext []byte, err error) {
	// Create a new AES cipher block from the key.
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Create a new GCM cipher mode.
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM cipher: %w", err)
	}

	// Open decrypts and authenticates the ciphertext.
	decryptedContent, err := aesGCM.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt content: %w", err)
	}

	return decryptedContent, nil
}
