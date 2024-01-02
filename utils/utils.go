package utils

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/remiges-tech/idshield/types"
)

const (
	ErrTokenMissing            = "token_missing"
	ErrTokenVerificationFailed = "token_verification_failed"
	ErrUnauthorized            = "Unauthorized"
	ErrWhileGettingInfo        = "Error_while_getting_info"

	ErrInvalidJSON   = "invalid_json"
	ErrAlreadyExist  = "User_already_exists"
	ErrSameEMail     = "User_already_exists_with_same_email"
	ErrRealmNotFound = "Realm_not_found"
	ErrUnknown       = "unknown"

	ErrHTTPUnauthorized     = "401 Unauthorized: HTTP 401 Unauthorized"
	ErrHTTPUserAlreadyExist = "409 Conflict: User exists with same username"
	ErrHTTPRealmNotFound    = "404 Not Found: Realm not found."
	ErrHTTPSameEmail        = "409 Conflict: User exists with same email"

	ErrFailedToLoadDependence            = "Failed_to_load_dependence"
	ErrEitherIDOrUsernameIsSetButNotBoth = "either_ID_or_Username_is_set_but_not_both"
	ERRTokenExpired                      = "token_expired"
	ErrUserNotFound                      = "userName_not_found"
)

// ExtractClaimFromJwt: this will extract the provided singleClaimName as key from the jwt token and return its value as a string
func ExtractClaimFromJwt(tokenString string, singleClaimName string) (string, error) {
	var name string
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return "", fmt.Errorf("invalid token payload")
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		name = fmt.Sprint(claims[singleClaimName])
	}

	if name == "" {
		return "", fmt.Errorf("invalid token payload")
	}

	return name, nil
}

func Authz_check(op types.OpReq, trace bool) (bool, []string) {
	var caplist []string
	return true, caplist
}

// UnixMilliToTimestamp: will return the unixmilli time (int64) to time.Time using time package
func UnixMilliToTimestamp(unix int64) time.Time {
	tm := time.UnixMilli(unix)
	return tm
}
