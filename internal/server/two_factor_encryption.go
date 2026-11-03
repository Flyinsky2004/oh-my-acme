package server

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/Flyinsky2004/oh-my-acme/internal/domain"
)

const twoFactorCipherPrefix = "aes256gcm:v1:"
const twoFactorAssociatedData = "oh-my-acme/admin/totp/v1"

var errTwoFactorKeyRequired = errors.New("two_factor_encryption_key (or TWO_FACTOR_ENCRYPTION_KEY) is required for stored or new two-factor secrets")

func loadTwoFactorCipher(configKey string) (cipher.AEAD, error) {
	raw := strings.TrimSpace(os.Getenv("TWO_FACTOR_ENCRYPTION_KEY"))
	if raw == "" {
		raw = strings.TrimSpace(configKey)
	}
	if raw == "" {
		return nil, nil
	}
	key, err := base64.StdEncoding.Strict().DecodeString(raw)
	if err != nil || len(key) != 32 {
		return nil, errors.New("two_factor_encryption_key (or TWO_FACTOR_ENCRYPTION_KEY) must be a Base64-encoded 32-byte key")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.New("cannot initialize two-factor AES-256 cipher")
	}
	return cipher.NewGCMWithRandomNonce(block)
}

func encryptTwoFactorSecret(aead cipher.AEAD, secret string) (string, error) {
	if aead == nil {
		return "", errTwoFactorKeyRequired
	}
	if secret == "" {
		return "", errors.New("two-factor secret is empty")
	}
	// NewGCMWithRandomNonce prepends a fresh 96-bit nonce and appends the tag.
	sealed := aead.Seal(nil, nil, []byte(secret), []byte(twoFactorAssociatedData))
	return twoFactorCipherPrefix + base64.RawStdEncoding.EncodeToString(sealed), nil
}

func decryptTwoFactorSecret(aead cipher.AEAD, encrypted string) (string, error) {
	if aead == nil {
		return "", errTwoFactorKeyRequired
	}
	if !strings.HasPrefix(encrypted, twoFactorCipherPrefix) {
		return "", errors.New("unsupported two-factor ciphertext format")
	}
	sealed, err := base64.RawStdEncoding.Strict().DecodeString(strings.TrimPrefix(encrypted, twoFactorCipherPrefix))
	if err != nil {
		return "", errors.New("invalid two-factor ciphertext encoding")
	}
	plain, err := aead.Open(nil, nil, sealed, []byte(twoFactorAssociatedData))
	if err != nil || len(plain) == 0 {
		return "", errors.New("cannot decrypt two-factor secret: check two_factor_encryption_key / TWO_FACTOR_ENCRYPTION_KEY and state integrity")
	}
	return string(plain), nil
}

// Run before normal startup writes and listeners. Validate both snapshots before
// changing either, so a wrong/missing key never silently removes protection.
func (s *Server) initTwoFactorEncryption() error {
	if s.twoFactorCipher != nil {
		return nil
	}
	aead, err := loadTwoFactorCipher(s.cfg.TwoFactorEncryptionKey)
	if err != nil {
		return err
	}
	err = s.st.TransformSnapshots(func(st *domain.State) (bool, error) {
		factor := &st.Admin.TwoFactor
		if factor.Secret != "" && factor.EncryptedSecret != "" {
			return false, errors.New("ambiguous two-factor state contains both plaintext and ciphertext")
		}
		if factor.EncryptedSecret != "" {
			if _, err := decryptTwoFactorSecret(aead, factor.EncryptedSecret); err != nil {
				return false, err
			}
			return false, nil
		}
		if factor.Secret != "" {
			encrypted, err := encryptTwoFactorSecret(aead, factor.Secret)
			if err != nil {
				return false, err
			}
			factor.Secret, factor.EncryptedSecret = "", encrypted
			return true, nil
		}
		if factor.Enabled {
			return false, errors.New("enabled two-factor account has no secret")
		}
		return false, nil
	})
	if err != nil {
		return fmt.Errorf("initialize two-factor encryption: %w", err)
	}
	s.twoFactorCipher = aead
	return nil
}
