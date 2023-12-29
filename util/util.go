package util

import (
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
)

// UnixMilliToTimestamp: will return the unixmilli time (int64) to time.Time using time package
func UnixMilliToTimestamp(unix int64) time.Time {
	tm := time.UnixMilli(unix)
	return tm
}

// ExtractClaimFromJwt:
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

	fmt.Println("name:", name)
	return name, nil
}

func Authz_check() bool {
	return true
}
