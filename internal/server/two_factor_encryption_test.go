package server

import (
	"crypto/cipher"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Flyinsky2004/oh-my-acme/internal/domain"
	"github.com/Flyinsky2004/oh-my-acme/internal/store"
	"github.com/pquerna/otp/totp"
)

const testTwoFactorKey = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="

func testTwoFactorCipher(t *testing.T) cipher.AEAD {
	t.Helper()
	t.Setenv("TWO_FACTOR_ENCRYPTION_KEY", testTwoFactorKey)
	aead, err := loadTwoFactorCipher()
	if err != nil {
		t.Fatal(err)
	}
	return aead
}

func TestTwoFactorCipherAuthentication(t *testing.T) {
	aead := testTwoFactorCipher(t)
	secret := "JBSWY3DPEHPK3PXP"
	first, err := encryptTwoFactorSecret(aead, secret)
	if err != nil {
		t.Fatal(err)
	}
	second, err := encryptTwoFactorSecret(aead, secret)
	if err != nil || first == second {
		t.Fatal("encryption did not use a fresh random nonce")
	}
	if plain, err := decryptTwoFactorSecret(aead, first); err != nil || plain != secret {
		t.Fatal("round trip failed")
	}
	payload, _ := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(first, twoFactorCipherPrefix))
	for _, index := range []int{0, 12, len(payload) - 1} { // Nonce, ciphertext, authentication tag.
		changed := append([]byte(nil), payload...)
		changed[index] ^= 1
		encrypted := twoFactorCipherPrefix + base64.RawStdEncoding.EncodeToString(changed)
		if _, err := decryptTwoFactorSecret(aead, encrypted); err == nil {
			t.Fatal("tampered data accepted")
		}
	}
	for _, bad := range []string{secret, "aes256gcm:v2:abc", twoFactorCipherPrefix + "!", twoFactorCipherPrefix + "AA"} {
		if _, err := decryptTwoFactorSecret(aead, bad); err == nil {
			t.Fatal("plaintext or malformed ciphertext accepted")
		}
	}
	t.Setenv("TWO_FACTOR_ENCRYPTION_KEY", base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", 32))))
	wrong, err := loadTwoFactorCipher()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decryptTwoFactorSecret(wrong, first); err == nil {
		t.Fatal("wrong key accepted")
	}
}

func TestTwoFactorEncryptionKeyValidation(t *testing.T) {
	for _, raw := range []string{"not-base64", base64.StdEncoding.EncodeToString(make([]byte, 16)), base64.StdEncoding.EncodeToString(make([]byte, 24)), base64.StdEncoding.EncodeToString(make([]byte, 33))} {
		t.Setenv("TWO_FACTOR_ENCRYPTION_KEY", raw)
		if _, err := loadTwoFactorCipher(); err == nil || strings.Contains(err.Error(), raw) {
			t.Fatal("invalid key accepted or leaked")
		}
	}
	t.Setenv("TWO_FACTOR_ENCRYPTION_KEY", "")
	if aead, err := loadTwoFactorCipher(); err != nil || aead != nil {
		t.Fatal("missing optional key rejected before 2FA is configured")
	}
}

func TestTwoFactorPlaintextMigrationAndRestart(t *testing.T) {
	aead := testTwoFactorCipher(t)
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	secret := "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	// Create both a plaintext primary and plaintext backup as an older server would.
	for i := 0; i < 2; i++ {
		if err := st.WithState(true, func(s *domain.State) error {
			s.Admin.Username = "admin"
			s.Admin.TwoFactor = domain.AdminTwoFactor{Enabled: true, Secret: secret, LastStep: 123, RecoveryHashes: []string{recoveryHash("test-recovery-code")}}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	srv := &Server{st: st}
	if err := srv.initTwoFactorEncryption(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"state.json", "state.json.backup"} {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), secret) || strings.Contains(string(data), `"secret"`) || strings.Contains(string(data), testTwoFactorKey) {
			t.Fatal("plaintext or encryption key leaked to snapshot")
		}
		if !strings.Contains(string(data), `"encrypted_secret"`) {
			t.Fatal("snapshot not encrypted")
		}
		info, _ := os.Stat(filepath.Join(dir, name))
		if info.Mode().Perm() != 0600 {
			t.Fatal("snapshot permissions changed")
		}
	}
	factor := st.State().Admin.TwoFactor
	if factor.Secret != "" || factor.LastStep != 123 || len(factor.RecoveryHashes) != 1 {
		t.Fatal("migration lost 2FA state")
	}
	if plain, err := decryptTwoFactorSecret(aead, factor.EncryptedSecret); err != nil || plain != secret {
		t.Fatal("migration changed binding key")
	}
	reopened, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	restarted := &Server{st: reopened}
	if err := restarted.initTwoFactorEncryption(); err != nil {
		t.Fatal(err)
	}
	w := &Web{srv: restarted}
	code, _ := totp.GenerateCode(secret, time.Now())
	if ok, err := w.consumeSecondFactor(code); err != nil || !ok {
		t.Fatal("TOTP failed after encrypted restart")
	}
}

func TestTwoFactorMissingOrWrongKeyFailsStartupWithoutChanges(t *testing.T) {
	w := loginHistoryWeb(t)
	_, _ = enableTestFactor(t, w)
	before, err := os.ReadFile(w.srv.st.StatePath())
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"", base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", 32)))} {
		t.Setenv("TWO_FACTOR_ENCRYPTION_KEY", raw)
		if _, err := NewWeb(&Server{st: w.srv.st}); err == nil {
			t.Fatal("startup allowed with missing/wrong key")
		}
		after, _ := os.ReadFile(w.srv.st.StatePath())
		if string(after) != string(before) {
			t.Fatal("failed startup modified state")
		}
	}
}

func TestTwoFactorNoKeyCannotEnrollOrMigratePlaintext(t *testing.T) {
	w := loginHistoryWeb(t)
	t.Setenv("TWO_FACTOR_ENCRYPTION_KEY", "")
	w.srv.twoFactorCipher = nil
	if err := w.srv.setAdminPassword("admin", "test-password"); err != nil {
		t.Fatal(err)
	}
	id := w.sessions.create("admin")
	rw := twoFactorRequest(w, "POST", "/settings/2fa/start", id, securityValues(w, id))
	if rw.Code != 503 {
		t.Fatal("enrollment allowed without encryption key")
	}
	if err := w.saveTwoFactor(domain.AdminTwoFactor{Enabled: true, Secret: "test-secret"}); err == nil {
		t.Fatal("plaintext fallback saved")
	}
	if err := w.srv.st.WithState(true, func(st *domain.State) error {
		st.Admin.TwoFactor = domain.AdminTwoFactor{Enabled: true, Secret: "legacy-secret"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := w.srv.initTwoFactorEncryption(); err == nil {
		t.Fatal("plaintext startup allowed without key")
	}
	if w.srv.getAdmin().TwoFactor.Secret != "legacy-secret" {
		t.Fatal("failed migration erased secret")
	}
}

func TestEncryptedTwoFactorRecoveryCannotBypassDecryption(t *testing.T) {
	w := loginHistoryWeb(t)
	_, codes := enableTestFactor(t, w)
	if err := w.srv.st.WithState(true, func(st *domain.State) error {
		st.Admin.TwoFactor.EncryptedSecret = twoFactorCipherPrefix + "AA"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if ok, err := w.consumeSecondFactor(codes[0]); err == nil || ok {
		t.Fatal("recovery bypassed invalid encrypted state")
	}
	if len(w.srv.getAdmin().TwoFactor.RecoveryHashes) != 10 {
		t.Fatal("recovery code consumed on decryption failure")
	}
}
