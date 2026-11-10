package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"image/png"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Flyinsky2004/oh-my-acme/internal/domain"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// allowSensitiveAttempt is the account-wide quota for second-factor and other
// sensitive mutations. Callers hold authMu and must only reach it after the
// current password has already been verified, so anonymous wrong-password
// traffic cannot exhaust the administrator's quota. Per-source limiting is
// handled separately by allowSourceAttempt.
func (w *Web) allowSensitiveAttempt(rw http.ResponseWriter) bool {
	now := w.nowTime()
	if now.Sub(w.authWindow) >= time.Minute {
		w.authWindow, w.authAttempts = now, 0
	}
	if w.authAttempts >= 10 {
		rw.Header().Set("Retry-After", "60")
		http.Error(rw, "验证尝试过于频繁，请一分钟后重试", http.StatusTooManyRequests)
		return false
	}
	w.authAttempts++
	return true
}

// Matching the step ourselves lets us reject reuse even within the skew window.
func matchingTOTPStep(secret, code string, now time.Time, last int64) (int64, bool) {
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return 0, false
	}
	for _, delta := range []int64{0, -1, 1} {
		step := now.Unix()/30 + delta
		if step <= last {
			continue
		}
		expected, err := totp.GenerateCode(secret, time.Unix(step*30, 0))
		if err == nil && subtle.ConstantTimeCompare([]byte(expected), []byte(code)) == 1 {
			return step, true
		}
	}
	return 0, false
}

func recoveryHash(code string) string {
	code = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(code), "-", ""))
	sum := sha256.Sum256([]byte(code))
	return hex.EncodeToString(sum[:])
}

func newRecoveryCodes() ([]string, []string, error) {
	codes, hashes := make([]string, 10), make([]string, 10)
	for i := range codes {
		raw := randomHex(10) // 80 bits of entropy per one-time code.
		if raw == "" {
			return nil, nil, errors.New("generate recovery code")
		}
		codes[i] = raw[:5] + "-" + raw[5:10] + "-" + raw[10:15] + "-" + raw[15:]
		hashes[i] = recoveryHash(codes[i])
	}
	return codes, hashes, nil
}

// saveTwoFactor persists the 2FA state. Store.WithState restores the in-memory
// state when the disk write fails, so a failed activation cannot enable 2FA
// without showing recovery codes and a failed consumption cannot burn a code.
func (w *Web) saveTwoFactor(next domain.AdminTwoFactor) error {
	if next.Enabled {
		if w.srv.twoFactorCipher == nil {
			return errTwoFactorKeyRequired
		}
		if next.Secret != "" {
			encrypted, err := encryptTwoFactorSecret(w.srv.twoFactorCipher, next.Secret)
			if err != nil {
				return err
			}
			next.EncryptedSecret, next.Secret = encrypted, ""
		}
		if _, err := decryptTwoFactorSecret(w.srv.twoFactorCipher, next.EncryptedSecret); err != nil {
			return err
		}
	} else {
		next.Secret, next.EncryptedSecret = "", ""
	}
	return w.srv.st.Update(func(st *domain.State) error { st.Admin.TwoFactor = next; return nil })
}

// consumeSecondFactor verifies and consumes a TOTP step or recovery code. The
// caller must hold Web.authMu: the read-check-write sequence is what makes a
// code one-time under concurrent logins.
func (w *Web) consumeSecondFactor(code string) (bool, error) {
	factor := w.srv.getAdmin().TwoFactor
	if !factor.Enabled {
		return false, nil
	}
	secret, err := decryptTwoFactorSecret(w.srv.twoFactorCipher, factor.EncryptedSecret)
	if err != nil {
		return false, err
	}
	if step, ok := matchingTOTPStep(secret, code, w.nowTime(), factor.LastStep); ok {
		factor.LastStep = step
	} else {
		hash := recoveryHash(code)
		found := -1
		for i, candidate := range factor.RecoveryHashes {
			if subtle.ConstantTimeCompare([]byte(candidate), []byte(hash)) == 1 {
				found = i
			}
		}
		if found < 0 {
			return false, nil
		}
		factor.RecoveryHashes = append(factor.RecoveryHashes[:found], factor.RecoveryHashes[found+1:]...)
	}
	if err := w.saveTwoFactor(factor); err != nil {
		return false, err
	}
	return true, nil
}

// securityForm re-validates the session and session-bound CSRF token after
// authMu is taken, covering a concurrent logout/rotation. The body has already
// been parsed by the auth middleware or prepareBody, so this never reads from
// the client while holding the lock.
func (w *Web) securityForm(rw http.ResponseWriter, r *http.Request) (session, bool) {
	sess, ok := w.sessions.get(requestSession(r))
	if !ok || !validCSRF(r, sess) {
		http.Error(rw, "页面已过期，请刷新后重试", http.StatusForbidden)
		return session{}, false
	}
	return sess, true
}

func (w *Web) twoFactorPage(rw http.ResponseWriter, r *http.Request, message string, codes []string) {
	sess, ok := w.sessions.get(requestSession(r))
	if !ok {
		w.redirect(rw, r, "/login")
		return
	}
	factor := w.srv.getAdmin().TwoFactor
	secret := ""
	if !factor.Enabled && w.nowTime().Before(sess.pendingUntil) {
		secret = sess.pendingSecret
	}
	w.page(rw, r, "两步验证", "/settings", "two-factor", map[string]any{
		"Enabled": factor.Enabled, "Secret": secret, "Username": w.srv.getAdmin().Username, "CSRF": sess.csrf,
		"RecoveryRemaining": len(factor.RecoveryHashes), "RecoveryCodes": codes, "Error": message,
	})
}

func (w *Web) handleTwoFactorPage(rw http.ResponseWriter, r *http.Request) {
	w.twoFactorPage(rw, r, "", nil)
}

func (w *Web) handleTwoFactorStart(rw http.ResponseWriter, r *http.Request) {
	if !w.prepareBody(rw, r, maxTwoFactorBody) {
		return
	}
	if !w.allowSourceAttempt(rw, r) {
		return
	}
	if w.srv.twoFactorCipher == nil {
		http.Error(rw, "请先在服务端 config.json 配置 two_factor_encryption_key 后重启，再绑定两步验证", http.StatusServiceUnavailable)
		return
	}
	admin := w.srv.getAdmin()
	if admin.TwoFactor.Enabled {
		http.Error(rw, "两步验证已启用", http.StatusConflict)
		return
	}
	// Password verification is outside authMu and bounded by the work gate.
	passwordOK, ok := w.verifyPasswordGated(rw, r.PostForm.Get("password"), admin.PasswordHash)
	if !ok {
		return
	}
	if !passwordOK {
		w.twoFactorPage(rw, r, "当前密码错误", nil)
		return
	}
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "oh-my-acme", AccountName: admin.Username, SecretSize: 20})
	if err != nil {
		http.Error(rw, "无法生成绑定密钥", 500)
		return
	}
	w.authMu.Lock()
	defer w.authMu.Unlock()
	sess, ok := w.securityForm(rw, r)
	if !ok || !w.allowSensitiveAttempt(rw) {
		return
	}
	current := w.srv.getAdmin()
	if current.TwoFactor.Enabled || current.PasswordHash != admin.PasswordHash {
		http.Error(rw, "账户状态已变化，请重试", http.StatusConflict)
		return
	}
	w.sessions.setPending(sess.id, key.Secret())
	w.redirect(rw, r, "/settings/2fa")
}

func (w *Web) handleTwoFactorQR(rw http.ResponseWriter, r *http.Request) {
	sess, ok := w.sessions.get(requestSession(r))
	if !ok || w.srv.getAdmin().TwoFactor.Enabled || sess.pendingSecret == "" || !w.nowTime().Before(sess.pendingUntil) {
		http.Error(rw, "绑定已过期，请重新开始", http.StatusNotFound)
		return
	}
	key, err := otp.NewKeyFromURL(provisioningURI(sess.username, sess.pendingSecret))
	if err != nil {
		http.Error(rw, "无法生成二维码", 500)
		return
	}
	img, err := key.Image(256, 256)
	if err != nil {
		http.Error(rw, "无法生成二维码", 500)
		return
	}
	rw.Header().Set("Content-Type", "image/png")
	_ = png.Encode(rw, img)
}

// rotateAdminSession revokes every session and installs one replacement. The
// store rotates atomically and returns the new CSRF token so the response can
// render forms that match the rotated cookie.
func (w *Web) rotateAdminSession(rw http.ResponseWriter, r *http.Request) session {
	sess := w.sessions.rotate(w.srv.getAdmin().Username)
	w.sessionCookieAndSet(rw, r, sess.id)
	return sess
}

func (w *Web) handleTwoFactorEnable(rw http.ResponseWriter, r *http.Request) {
	if !w.prepareBody(rw, r, maxTwoFactorBody) {
		return
	}
	if !w.allowSourceAttempt(rw, r) {
		return
	}
	w.authMu.Lock()
	defer w.authMu.Unlock()
	sess, ok := w.securityForm(rw, r)
	if !ok || !w.allowSensitiveAttempt(rw) {
		return
	}
	if w.srv.getAdmin().TwoFactor.Enabled {
		http.Error(rw, "两步验证已启用", http.StatusConflict)
		return
	}
	if sess.pendingSecret == "" || !w.nowTime().Before(sess.pendingUntil) {
		w.twoFactorPage(rw, r, "绑定已过期，请重新开始", nil)
		return
	}
	step, valid := matchingTOTPStep(sess.pendingSecret, r.PostForm.Get("otp"), w.nowTime(), 0)
	if !valid {
		w.twoFactorPage(rw, r, "验证码错误，请检查手机时间后重试", nil)
		return
	}
	codes, hashes, err := newRecoveryCodes()
	if err == nil {
		err = w.saveTwoFactor(domain.AdminTwoFactor{Enabled: true, Secret: sess.pendingSecret, LastStep: step, RecoveryHashes: hashes})
	}
	if err != nil {
		http.Error(rw, "无法保存两步验证设置，请稍后重试", 500)
		return
	}
	rotated := w.rotateAdminSession(rw, r)
	// Render with the replacement session; recovery plaintext exists only for this response.
	w.page(rw, r, "保存恢复码", "/settings", "two-factor", map[string]any{
		"Enabled": true, "CSRF": rotated.csrf, "RecoveryCodes": codes, "RecoveryRemaining": len(hashes),
	})
}

func (w *Web) handleTwoFactorDisable(rw http.ResponseWriter, r *http.Request) {
	if !w.prepareBody(rw, r, maxTwoFactorBody) {
		return
	}
	if !w.allowSourceAttempt(rw, r) {
		return
	}
	admin := w.srv.getAdmin()
	if !admin.TwoFactor.Enabled {
		w.redirect(rw, r, "/settings/2fa")
		return
	}
	// Password verification is outside authMu and bounded by the work gate.
	passwordOK, ok := w.verifyPasswordGated(rw, r.PostForm.Get("password"), admin.PasswordHash)
	if !ok {
		return
	}
	if !passwordOK {
		w.twoFactorPage(rw, r, "密码或验证码错误", nil)
		return
	}
	w.authMu.Lock()
	defer w.authMu.Unlock()
	if _, ok := w.securityForm(rw, r); !ok || !w.allowSensitiveAttempt(rw) {
		return
	}
	current := w.srv.getAdmin()
	if !current.TwoFactor.Enabled || current.PasswordHash != admin.PasswordHash {
		http.Error(rw, "账户状态已变化，请重试", http.StatusConflict)
		return
	}
	valid, err := w.consumeSecondFactor(r.PostForm.Get("otp"))
	if err != nil {
		http.Error(rw, "无法保存验证状态，请稍后重试", 500)
		return
	}
	if !valid {
		w.twoFactorPage(rw, r, "密码或验证码错误；已使用的验证码不可重复使用", nil)
		return
	}
	if err := w.saveTwoFactor(domain.AdminTwoFactor{}); err != nil {
		http.Error(rw, "无法关闭两步验证，请稍后重试", 500)
		return
	}
	w.rotateAdminSession(rw, r)
	w.redirect(rw, r, "/settings/2fa")
}

func provisioningURI(username, secret string) string {
	u := url.URL{Scheme: "otpauth", Host: "totp", Path: "/oh-my-acme:" + username}
	q := url.Values{"issuer": {"oh-my-acme"}, "secret": {secret}, "period": {"30"}, "digits": {"6"}, "algorithm": {"SHA1"}}
	u.RawQuery = q.Encode()
	return u.String()
}
