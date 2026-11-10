package server

import (
	"bytes"
	"crypto/subtle"
	"errors"
	"io"
	"net/http"
	"time"
)

const (
	// maxMutationBody bounds every authenticated state-changing form. The
	// largest legitimate payload is a deploy selection, far below this.
	maxMutationBody  = 64 << 10
	maxLoginBody     = 16 << 10
	maxSetupBody     = 16 << 10
	maxTwoFactorBody = 4 << 10

	defaultAuthReadTimeout = 10 * time.Second
)

// prepareBody applies a read deadline and a hard size limit before parsing the
// request body. It is called before Web.authMu is taken so a slow or oversized
// client cannot pin the authentication lock.
func (w *Web) prepareBody(rw http.ResponseWriter, r *http.Request, limit int64) bool {
	timeout := w.authReadTimeout
	if timeout <= 0 {
		timeout = defaultAuthReadTimeout
	}
	controller := http.NewResponseController(rw)
	deadline := w.nowTime().Add(timeout)
	_ = controller.SetReadDeadline(deadline)

	var parseErr error
	if r.Body != nil && r.Body != http.NoBody {
		// ParseForm reads only URL-encoded bodies. Read every content type
		// ourselves so JSON, multipart or a missing Content-Type cannot leave
		// an unread network body behind when the deadline is cleared.
		r.Body = http.MaxBytesReader(rw, r.Body, limit)
		var body []byte
		body, parseErr = io.ReadAll(r.Body)
		if parseErr == nil {
			parseErr = r.Body.Close()
			r.Body = io.NopCloser(bytes.NewReader(body))
		}
	}
	if parseErr == nil {
		parseErr = r.ParseForm()
	}
	if parseErr != nil {
		// Do not clear the deadline on failure. net/http may still drain the
		// unfinished body while tearing down the request; with the deadline
		// gone that drain can block forever. Keep the deadline and ask the
		// server to close the connection instead of reusing it.
		rw.Header().Set("Connection", "close")
		r.Close = true
		var tooLarge *http.MaxBytesError
		if errors.As(parseErr, &tooLarge) {
			http.Error(rw, "请求体过大", http.StatusRequestEntityTooLarge)
		} else {
			http.Error(rw, "请求无效", http.StatusBadRequest)
		}
		return false
	}
	// The body was read completely; normal keep-alive handling can resume.
	_ = controller.SetReadDeadline(time.Time{})
	return true
}

// validCSRF compares the session-bound token from the POST body or the
// X-CSRF-Token header. Query-string tokens are intentionally not accepted so a
// token can never be captured from a URL or access log.
func validCSRF(r *http.Request, sess session) bool {
	token := r.PostForm.Get("csrf")
	if token == "" {
		token = r.Header.Get("X-CSRF-Token")
	}
	return token != "" && sess.csrf != "" &&
		subtle.ConstantTimeCompare([]byte(sess.csrf), []byte(token)) == 1
}

// csrfForRequest returns the current session's token for template rendering.
func (w *Web) csrfForRequest(r *http.Request) string {
	if w == nil || w.sessions == nil {
		return ""
	}
	sess, ok := w.sessions.get(requestSession(r))
	if !ok {
		return ""
	}
	return sess.csrf
}
