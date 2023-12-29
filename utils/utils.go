package utils

import (
	"fmt"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/remiges-tech/alya/router"
)

const (
	ErrTokenMissing            = "token_missing"
	ErrTokenVerificationFailed = "token_verification_failed"
	ErrUnauthorized            = "Unauthorized"

	ErrInvalidJSON      = "invalid_json"
	ErrAlreadyExist = "already_exists"
	ErrRealmNotFound    = "Realm_not_found"
	ErrUnknown          = "unknown"

	ErrHTTPUnauthorized     = "401 Unauthorized"
	ErrHTTPAlreadyExist = "409 Conflict"
	ErrHTTPRealmNotFound    = "404 Not Found"

	ErrFailedToGetDependence = "Failed_to_get_dependence"
)

// Capabilities representing user capabilities.
type Capabilities struct {
	Caplist []Caplist `json:"caplist"`
}

type Caplist struct {
	Cap   string   `json:"cap"`
	Scope []string `json:"scope"`
	Limit []string `json:"limit"`
}

type OpReq struct {
	User      string            `json:"user"`
	CapNeeded []string          `json:"capneeded"`
	Scope     map[string]string `json:"scope"`
	Limit     map[string]string `json:"limit"`
}

// Extract roles from the claims
func extractUserCapabilities(claims jwt.MapClaims) ([]string, error) {
	var capabilities []string
	if realmAccess, ok := claims["userCapabilities"].(map[string]interface{}); ok {
		if capabilitiesClaims, ok := realmAccess["userCapabilities"].([]interface{}); ok {
			for _, role := range capabilitiesClaims {
				if r, ok := role.(string); ok {
					capabilities = append(capabilities, r)
				}
			}
		}
	} else {
		return nil, fmt.Errorf("error while extracting realm_access from token claims")
	}
	return capabilities, nil
}

// GetRealm extracts and returns the realm from the Keycloak token
func GetRealm(c *gin.Context) (string, error) {
	accessToken, err := router.ExtractToken(c.GetHeader("Authorization"))
	if err != nil {
		return "", fmt.Errorf("missing or incorrect Authorization header format: %v", err)
	}

	token, _, err := new(jwt.Parser).ParseUnverified(accessToken, jwt.MapClaims{})
	if err != nil {
		return "", fmt.Errorf("error parsing token: %v", err)
	}

	// Extract realm from the Issuer (iss) field
	realm := extractRealmFromIssuer(token.Claims.(jwt.MapClaims)["iss"].(string))
	if realm == "" {
		return "", fmt.Errorf("unable to extract realm from the token")
	}

	return realm, nil
}

func extractRealmFromIssuer(issuer string) string {
	// Extract the realm from the issuer URL
	// Assuming the issuer URL format is "http://<hostname>/realms/<realm>"
	parts := strings.Split(issuer, "/realms/")
	fmt.Println("parts", parts)
	if len(parts) == 2 {
		return parts[1]
	}

	return ""
}

func Authz_check() (bool, []string) {
	var caplist []string
	return true, caplist
}
