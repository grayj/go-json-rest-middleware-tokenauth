package tokenauth

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"github.com/ant0ine/go-json-rest/rest"
	"log"
	"net/http"
	"strings"
)

// AuthTokenMiddleware provides a Token Auth implementation. On success, the wrapped middleware
// is called, and the userID is made available as request.Env["REMOTE_USER"].(string)
type AuthTokenMiddleware struct {
	// Realm name to display to the user. Required.
	Realm string

	// Callback function that should perform the authentication of the user based on token.
	// Must return userID as string on success, empty string on failure. Required.
	// The returned userID is normally the primary key for your user record.
	Authenticator func(token string) string

	// Callback function that should perform the authorization of the authenticated user.
	// Must return true on success, false on failure. Optional, defaults to success.
	// Called only after an authentication success.
	Authorizer func(request *rest.Request) bool

	// Nominal token entropy in bytes. Optional, defaults to recommended 32 bytes / 256-bit.
	TokenEntropy int
}

// MiddlewareFunc makes AuthTokenMiddleware implement the Middleware interface.
func (mw *AuthTokenMiddleware) MiddlewareFunc(handler rest.HandlerFunc) rest.HandlerFunc {
	if mw.Realm == "" {
		log.Fatal("Realm is required")
	}

	if mw.Authenticator == nil {
		log.Fatal("Authenticator is required")
	}

	if mw.Authorizer == nil {
		mw.Authorizer = func(request *rest.Request) bool {
			return true
		}
	}

	if mw.TokenEntropy == 0 {
		mw.TokenEntropy = 32 // 32 byte == 256 bit == recommended secure ID entropy
	}

	return func(writer rest.ResponseWriter, request *rest.Request) {
		authHeader := request.Header.Get("Authorization")
		// Authorization header was not provided
		if authHeader == "" {
			mw.unauthorized(writer)
			return
		}

		token, err := mw.decodeAuthHeader(authHeader)
		// Authorization header was *malformed* such that we couldn't extract a token
		if err != nil {
			mw.unauthorized(writer)
			return
		}

		userID := mw.Authenticator(token)
		// The token didn't map to a user, it's most likely either invalid or expired
		if userID == "" {
			mw.unauthorized(writer)
			return
		}

		// The user's token was valid, but they're not authorized for the current request
		if !mw.Authorizer(request) {
			mw.unauthorized(writer)
			return
		}

		request.Env["REMOTE_USER"] = userID
		handler(writer, request)
	}
}

// Extract the token from the current request.
func (mw *AuthTokenMiddleware) decodeAuthHeader(header string) (string, error) {
	parts := strings.SplitN(header, " ", 2)
	if !(len(parts) == 2 && parts[0] == "Token") {
		return "", errors.New("Invalid authentication")
	}
	token, err := base64.URLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", errors.New("Invalid base64")
	}
	return string(token), nil
}

// New generates a new random token
func (mw *AuthTokenMiddleware) New() (string, error) {
	bytes := make([]byte, mw.TokenEntropy)
	_, err := rand.Read(bytes[:cap(bytes)])
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// Equal does constant-time XOR comparison of two tokens
func (mw *AuthTokenMiddleware) Equal(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// Hash applies a simple MD5 hash over a token, making it safe to store
func (mw *AuthTokenMiddleware) Hash(token string) string {
	return base64.URLEncoding.EncodeToString(md5.Sum([]byte(token)))
}

func (mw *AuthTokenMiddleware) unauthorized(writer rest.ResponseWriter) {
	writer.Header().Set("WWW-Authenticate", "Token realm="+mw.Realm)
	rest.Error(writer, "Not Authorized", http.StatusUnauthorized)
}
