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

// All authentication and 2FA mutations are serialized by Web.authMu, including
// session issuance/revocation. Rate limiting is account-wide, not proxy-IP based.
func (w *Web) allowAuthAttempt(rw http.ResponseWriter) bool {
	now := time.Now()
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

// Store.WithState does not roll back failed disk writes. Restore this field on
// failure so a failed activation cannot enable 2FA without showing recovery codes.
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
	previous := w.srv.getAdmin().TwoFactor
	err := w.srv.st.WithState(true, func(st *domain.State) error { st.Admin.TwoFactor = next; return nil })
	if err != nil {
		_ = w.srv.st.WithState(false, func(st *domain.State) error { st.Admin.TwoFactor = previous; return nil })
	}
	return err
}

func (w *Web) consumeSecondFactor(code string) (bool, error) {
	factor := w.srv.getAdmin().TwoFactor
	if !factor.Enabled {
		return false, nil
	}
	secret, err := decryptTwoFactorSecret(w.srv.twoFactorCipher, factor.EncryptedSecret)
	if err != nil {
		return false, err
	}
	if step, ok := matchingTOTPStep(secret, code, time.Now(), factor.LastStep); ok {
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

// securityForm checks a session-bound CSRF token as well as the current session;
// handlers repeat the session check after obtaining authMu to cover revocation.
func (w *Web) securityForm(rw http.ResponseWriter, r *http.Request) (session, bool) {
	r.Body = http.MaxBytesReader(rw, r.Body, 4096)
	if err := r.ParseForm(); err != nil {
		http.Error(rw, "请求无效", http.StatusBadRequest)
		return session{}, false
	}
	sess, ok := w.sessions.get(requestSession(r))
	token := r.PostForm.Get("csrf")
	if !ok || token == "" || subtle.ConstantTimeCompare([]byte(sess.csrf), []byte(token)) != 1 {
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
	if !factor.Enabled && time.Now().Before(sess.pendingUntil) {
		secret = sess.pendingSecret
	}
	w.page(rw, r, "两步验证", "/settings", "two-factor", map[string]any{
		"Enabled": factor.Enabled, "Secret": secret, "Username": w.srv.getAdmin().Username, "CSRF": sess.csrf,
		"RecoveryRemaining": len(factor.RecoveryHashes), "RecoveryCodes": codes, "Error": message,
	})
}

func (w *Web) handleTwoFactorPage(rw http.ResponseWriter, r *http.Request) {
	w.authMu.Lock()
	defer w.authMu.Unlock()
	w.twoFactorPage(rw, r, "", nil)
}

func (w *Web) handleTwoFactorStart(rw http.ResponseWriter, r *http.Request) {
	w.authMu.Lock()
	defer w.authMu.Unlock()
	sess, ok := w.securityForm(rw, r)
	if !ok || !w.allowAuthAttempt(rw) {
		return
	}
	if w.srv.twoFactorCipher == nil {
		http.Error(rw, "请先在服务端配置 TWO_FACTOR_ENCRYPTION_KEY 后重启，再绑定两步验证", http.StatusServiceUnavailable)
		return
	}
	admin := w.srv.getAdmin()
	if admin.TwoFactor.Enabled {
		http.Error(rw, "两步验证已启用", http.StatusConflict)
		return
	}
	if !verifyPassword(r.PostForm.Get("password"), admin.PasswordHash) {
		w.twoFactorPage(rw, r, "当前密码错误", nil)
		return
	}
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "oh-my-acme", AccountName: admin.Username, SecretSize: 20})
	if err != nil {
		http.Error(rw, "无法生成绑定密钥", 500)
		return
	}
	w.sessions.setPending(sess.id, key.Secret())
	w.redirect(rw, r, "/settings/2fa")
}

func (w *Web) handleTwoFactorQR(rw http.ResponseWriter, r *http.Request) {
	w.authMu.Lock()
	defer w.authMu.Unlock()
	sess, ok := w.sessions.get(requestSession(r))
	if !ok || w.srv.getAdmin().TwoFactor.Enabled || sess.pendingSecret == "" || !time.Now().Before(sess.pendingUntil) {
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

func (w *Web) rotateAdminSession(rw http.ResponseWriter, r *http.Request) string {
	w.sessions.revokeAll()
	id := w.sessions.create(w.srv.getAdmin().Username)
	w.sessionCookieAndSet(rw, r, id)
	return id
}

func (w *Web) handleTwoFactorEnable(rw http.ResponseWriter, r *http.Request) {
	w.authMu.Lock()
	defer w.authMu.Unlock()
	sess, ok := w.securityForm(rw, r)
	if !ok || !w.allowAuthAttempt(rw) {
		return
	}
	if w.srv.getAdmin().TwoFactor.Enabled {
		http.Error(rw, "两步验证已启用", http.StatusConflict)
		return
	}
	if sess.pendingSecret == "" || !time.Now().Before(sess.pendingUntil) {
		w.twoFactorPage(rw, r, "绑定已过期，请重新开始", nil)
		return
	}
	step, valid := matchingTOTPStep(sess.pendingSecret, r.PostForm.Get("otp"), time.Now(), 0)
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
	id := w.rotateAdminSession(rw, r)
	// Render with the replacement session; recovery plaintext exists only for this response.
	sess, _ = w.sessions.get(id)
	w.page(rw, r, "保存恢复码", "/settings", "two-factor", map[string]any{
		"Enabled": true, "CSRF": sess.csrf, "RecoveryCodes": codes, "RecoveryRemaining": len(hashes),
	})
}

func (w *Web) handleTwoFactorDisable(rw http.ResponseWriter, r *http.Request) {
	w.authMu.Lock()
	defer w.authMu.Unlock()
	_, ok := w.securityForm(rw, r)
	if !ok || !w.allowAuthAttempt(rw) {
		return
	}
	admin := w.srv.getAdmin()
	if !admin.TwoFactor.Enabled {
		w.redirect(rw, r, "/settings/2fa")
		return
	}
	if !verifyPassword(r.PostForm.Get("password"), admin.PasswordHash) {
		w.twoFactorPage(rw, r, "密码或验证码错误", nil)
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
