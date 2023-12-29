package usersvc

import (
	"strconv"
	"strings"

	"github.com/Nerzal/gocloak/v13"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"

	"github.com/remiges-tech/alya/router"
	"github.com/remiges-tech/alya/service"
	"github.com/remiges-tech/alya/wscutils"
	"github.com/remiges-tech/idshield/utils"
	"github.com/remiges-tech/logharbour/logharbour"
)

type user struct {
	ID         string              `json:"id,omitempty"`
	Username   string              `json:"username" validate:"required"`
	Email      string              `json:"email" validate:"required,email"`
	FirstName  string              `json:"firstName"`
	LastName   string              `json:"lastName"`
	Attributes map[string][]string `json:"attributes"`
	Enabled    bool                `json:"enabled" validate:"required"`
}

// HandleCreateUserRequest is creating a new user in keycloak.
func User_new(c *gin.Context, s *service.Service) {
	l := s.LogHarbour
	l.Log("Starting execution of User_new()")

	isCapable, _ := utils.Authz_check()
	if !isCapable {
		l.Log("Unauthorized user:")
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(utils.ErrUnauthorized))
		return
	}

	var u user

	// Unmarshal JSON request into user struct
	err := wscutils.BindJSON(c, &u)
	if err != nil {
		l.LogActivity("Error Unmarshalling JSON to struct:", logharbour.DebugInfo{Variables: map[string]any{"Error": err.Error()}})
		// wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(wscutils.ErrcodeInvalidJson))
		return
	}

	// Validate the user creation request
	validationErrors := validateCreateUser(u, c)
	if len(validationErrors) > 0 {
		l.Debug0().LogDebug("Validation errors:", logharbour.DebugInfo{Variables: map[string]any{"validationErrors": validationErrors}})
		wscutils.SendErrorResponse(c, wscutils.NewResponse(wscutils.ErrorStatus, nil, validationErrors))
		return
	}

	realm, err := utils.GetRealm(c)
	if err != nil {
		l.Debug0().LogDebug("Missing or incorrect realm:", logharbour.DebugInfo{Variables: map[string]any{"error": err}})
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(utils.ErrUnauthorized))
		return
	}

	token, err := router.ExtractToken(c.GetHeader("Authorization"))
	if err != nil {
		l.Debug0().LogDebug("Missing or incorrect Authorization header format:", logharbour.DebugInfo{Variables: map[string]any{"error": err}})
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(utils.ErrTokenMissing))
		return
	}
	keycloakUser := gocloak.User{
		Username:   &u.Username,
		FirstName:  &u.FirstName,
		LastName:   &u.LastName,
		Email:      &u.Email,
		Attributes: &u.Attributes,
		Enabled:    &u.Enabled,
	}

	// Extracting the GoCloak client from the service dependencies
	gcClient, ok := s.Dependencies["goclock"].(*gocloak.GoCloak)
	if !ok {
		l.Log("Failed to convert the dependency to *gocloak.GoCloak")
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(utils.ErrFailedToGetDependence))
	}
	// CreateUser creates the given user in the given realm and returns it's userID
	ID, err := gcClient.CreateUser(c, token, realm, keycloakUser)
	if err != nil {
		l.LogActivity("Error while creating user:", logharbour.DebugInfo{Variables: map[string]any{"error": err}})
		errCode := strings.Split(err.Error(), ":")
		switch errCode[0] {
		case utils.ErrHTTPUnauthorized:
			l.Debug0().LogDebug("Unauthorized error occurred: ", logharbour.DebugInfo{Variables: map[string]any{"error": err}})
			wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(utils.ErrUnauthorized))
			return
		case utils.ErrHTTPAlreadyExist:
			l.Debug0().LogDebug("User already exists error: ", logharbour.DebugInfo{Variables: map[string]any{"error": err}})
			wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(utils.ErrAlreadyExist))
			return
		case utils.ErrHTTPRealmNotFound:
			l.Debug0().LogDebug("Realm not found error: ", logharbour.DebugInfo{Variables: map[string]any{"error": err}})
			wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(utils.ErrRealmNotFound))
			return
		default:
			l.Debug0().LogDebug("Unknown error occurred: ", logharbour.DebugInfo{Variables: map[string]any{"error": err}})
			wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(utils.ErrUnknown))
			return
		}
	}

	// Send success response
	wscutils.SendSuccessResponse(c, &wscutils.Response{Status: wscutils.SuccessStatus, Data: ID})

	l.Log("Finished execution of User_new()")
}

// validateCreateUser performs validation for the createUserRequest.
func validateCreateUser(u user, c *gin.Context) []wscutils.ErrorMessage {
	// Validate the request body
	validationErrors := wscutils.WscValidate(u, u.getValsForUser)

	if len(validationErrors) > 0 {
		return validationErrors
	}

	return validationErrors
}

// getValsForUser returns validation error details based on the field and tag.
func (u *user) getValsForUser(err validator.FieldError) []string {
	var vals []string

	switch err.Field() {
	case "Username":
		switch err.Tag() {
		case "required":
			vals = append(vals, "non-empty")
			vals = append(vals, u.Username)
		}
	case "Email":
		switch err.Tag() {
		case "required":
			vals = append(vals, "non-empty")
			vals = append(vals, u.Email)
		case "email":
			vals = append(vals, "valid email format")
			vals = append(vals, u.Email)
		}
	case "Enabled":
		switch err.Tag() {
		case "required":
			vals = append(vals, "non-empty")
			vals = append(vals, strconv.FormatBool(u.Enabled))
		}
	}

	return vals
}
