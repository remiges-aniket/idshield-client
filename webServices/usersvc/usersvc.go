package usersvc

import (
	"errors"
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

type userActivity struct {
	ID       string `json:"id,omitempty"`
	Username string `json:"username,omitempty"`
}

// HandleCreateUserRequest is creating a new user in keycloak.
func User_new(c *gin.Context, s *service.Service) {
	l := s.LogHarbour
	l.Log("Starting execution of User_new()")
	token, err := router.ExtractToken(c.GetHeader("Authorization"))
	if err != nil {
		l.Debug0().LogDebug("Missing or incorrect Authorization header format:", logharbour.DebugInfo{Variables: map[string]any{"error": err}})
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(utils.ErrTokenMissing))
		return
	}
	r, err := utils.ExtractClaimFromToken(token, "iss")
	if err != nil {
		l.Debug0().LogDebug("Missing or incorrect realm:", logharbour.DebugInfo{Variables: map[string]any{"error": err}})
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(utils.ErrRealmNotFound))
		return
	}
	parts := strings.Split(r, "/realms/")
	realm := parts[1]
	username, err := utils.ExtractClaimFromToken(token, "preferred_username")
	if err != nil {
		l.Debug0().LogDebug("Missing username:", logharbour.DebugInfo{Variables: map[string]any{"error": err}})
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(utils.ErrUserNotFound))
		return
	}

	isCapable, _ := utils.Authz_check(utils.OpReq{
		User:      username,
		CapNeeded: []string{"UserCreate"},
	}, false)

	if !isCapable {
		l.Log("Unauthorized user:")
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(utils.ErrUnauthorized))
		return
	}

	var u user

	// Unmarshal JSON request into user struct
	err = wscutils.BindJSON(c, &u)
	if err != nil {
		l.LogActivity("Error Unmarshalling JSON to struct:", logharbour.DebugInfo{Variables: map[string]any{"Error": err.Error()}})
		return
	}

	// Validate the user creation request
	validationErrors := validateCreateUser(u, c)
	if len(validationErrors) > 0 {
		l.Debug0().LogDebug("Validation errors:", logharbour.DebugInfo{Variables: map[string]any{"validationErrors": validationErrors}})
		wscutils.SendErrorResponse(c, wscutils.NewResponse(wscutils.ErrorStatus, nil, validationErrors))
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
	gcClient, ok := s.Dependencies["gocloak"].(*gocloak.GoCloak)
	if !ok {
		l.Log("Failed to load the dependency to *gocloak.GoCloak")
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(utils.ErrFailedToLoadDependence))
		return
	}
	// CreateUser creates the given user in the given realm and returns it's userID
	ID, err := gcClient.CreateUser(c, token, realm, keycloakUser)
	if err != nil {
		l.LogActivity("Error while creating user:", logharbour.DebugInfo{Variables: map[string]any{"error": err}})
		switch err.Error() {
		case utils.ErrHTTPUnauthorized:
			s.LogHarbour.Debug0().LogDebug("Unauthorized error occurred: ", logharbour.DebugInfo{Variables: map[string]interface{}{"error": err}})
			wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(utils.ErrUnauthorized))
			return
		case utils.ErrHTTPUserAlreadyExist:
			s.LogHarbour.Debug0().LogDebug("User already exists error: ", logharbour.DebugInfo{Variables: map[string]interface{}{"error": err}})
			wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(utils.ErrAlreadyExist))
			return
		case utils.ErrHTTPRealmNotFound:
			s.LogHarbour.Debug0().LogDebug("Realm not found error: ", logharbour.DebugInfo{Variables: map[string]interface{}{"error": err}})
			wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(utils.ErrRealmNotFound))
			return
		case utils.ErrHTTPSameEmail:
			s.LogHarbour.Debug0().LogDebug("User exists with same email: ", logharbour.DebugInfo{Variables: map[string]interface{}{"error": err}})
			wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(utils.ErrSameEMail))
			return
		default:
			s.LogHarbour.Debug0().LogDebug("Unknown error occurred: ", logharbour.DebugInfo{Variables: map[string]interface{}{"error": err}})
			wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(wscutils.ErrcodeUnknown))
			return
		}
	}

	// Send success response
	wscutils.SendSuccessResponse(c, &wscutils.Response{Status: wscutils.SuccessStatus, Data: ID, Messages: []wscutils.ErrorMessage{}})

	l.Log("Finished execution of User_new()")
}

func User_activate(c *gin.Context, s *service.Service) {
	l := s.LogHarbour
	l.Log("Starting execution of User_activate()")
	token, err := router.ExtractToken(c.GetHeader("Authorization"))
	if err != nil {
		l.Debug0().LogDebug("Missing or incorrect Authorization header format:", logharbour.DebugInfo{Variables: map[string]any{"error": err}})
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(utils.ErrTokenMissing))
		return
	}
	r, err := utils.ExtractClaimFromToken(token, "iss")
	if err != nil {
		l.Debug0().LogDebug("Missing or incorrect realm:", logharbour.DebugInfo{Variables: map[string]any{"error": err}})
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(utils.ErrRealmNotFound))
		return
	}
	parts := strings.Split(r, "/realms/")
	realm := parts[1]
	username, err := utils.ExtractClaimFromToken(token, "preferred_username")
	if err != nil {
		l.Debug0().LogDebug("Missing username:", logharbour.DebugInfo{Variables: map[string]any{"error": err}})
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(utils.ErrUserNotFound))
		return
	}

	isCapable, _ := utils.Authz_check(utils.OpReq{
		User:      username,
		CapNeeded: []string{"UserActivate"},
	}, false)

	if !isCapable {
		l.Log("Unauthorized user:")
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(utils.ErrUnauthorized))
		return
	}

	var u userActivity
	err = wscutils.BindJSON(c, &u)
	if err != nil {
		l.LogActivity("Error Unmarshalling JSON to struct:", logharbour.DebugInfo{Variables: map[string]any{"Error": err.Error()}})
		return
	}

	err = u.CustomValidate()
	if err != nil {
		l.Debug0().LogDebug("either ID or Username is set, but not both", logharbour.DebugInfo{Variables: map[string]any{"error": err}})
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(utils.ErrEitherIDOrUsernameIsSetButNotBoth))
		return
	}

	// Extracting the GoCloak client from the service dependencies
	gcClient, ok := s.Dependencies["gocloak"].(*gocloak.GoCloak)
	if !ok {
		l.Log("Failed to convert the dependency to *gocloak.GoCloak")
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(utils.ErrFailedToLoadDependence))
		return
	}

	var keycloakUser gocloak.User
	if u.ID == "" {
		users, err := gcClient.GetUsers(c, token, realm, gocloak.GetUsersParams{
			Username: &u.Username,
		})
		if err != nil || len(users) < 1 {
			l.Log("Error while getting user info")
			wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(utils.ErrWhileGettingInfo))
			return
		}
		id := users[0].ID
		keycloakUser = gocloak.User{
			ID:       id,
			Username: &u.Username,
			Enabled:  gocloak.BoolP(true),
		}
	} else {
		keycloakUser = gocloak.User{
			ID:       &u.ID,
			Username: &u.Username,
			Enabled:  gocloak.BoolP(true),
		}
	}
	err = gcClient.UpdateUser(c, token, realm, keycloakUser)
	if err != nil {
		l.LogActivity("Error while activating user:", logharbour.DebugInfo{Variables: map[string]any{"error": err}})
		wscutils.SendErrorResponse(c, &wscutils.Response{Status: "400", Data: err})
		return
	}

	// Send success response
	wscutils.SendSuccessResponse(c, &wscutils.Response{Status: wscutils.SuccessStatus})

	l.Log("Finished execution of User_activate()")
}

func User_deactivate(c *gin.Context, s *service.Service) {
	l := s.LogHarbour
	l.Log("Starting execution of User_deactivate()")
	token, err := router.ExtractToken(c.GetHeader("Authorization"))
	if err != nil {
		l.Debug0().LogDebug("Missing or incorrect Authorization header format:", logharbour.DebugInfo{Variables: map[string]any{"error": err}})
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(utils.ErrTokenMissing))
		return
	}
	r, err := utils.ExtractClaimFromToken(token, "iss")
	if err != nil {
		l.Debug0().LogDebug("Missing or incorrect realm:", logharbour.DebugInfo{Variables: map[string]any{"error": err}})
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(utils.ErrRealmNotFound))
		return
	}
	parts := strings.Split(r, "/realms/")
	realm := parts[1]
	username, err := utils.ExtractClaimFromToken(token, "preferred_username")
	if err != nil {
		l.Debug0().LogDebug("Missing username:", logharbour.DebugInfo{Variables: map[string]any{"error": err}})
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(utils.ErrUserNotFound))
		return
	}

	isCapable, _ := utils.Authz_check(utils.OpReq{
		User:      username,
		CapNeeded: []string{"UserDeactivate"},
	}, false)

	if !isCapable {
		l.Log("Unauthorized user:")
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(utils.ErrUnauthorized))
		return
	}
	var u userActivity
	err = wscutils.BindJSON(c, &u)
	if err != nil {
		l.LogActivity("Error Unmarshalling JSON to struct:", logharbour.DebugInfo{Variables: map[string]any{"Error": err.Error()}})
		return
	}

	err = u.CustomValidate()
	if err != nil {
		l.Debug0().LogDebug("either ID or Username is set, but not both", logharbour.DebugInfo{Variables: map[string]any{"error": err}})
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse("either ID or Username is set, but not both"))
		return
	}

	// Extracting the GoCloak client from the service dependencies
	gcClient, ok := s.Dependencies["gocloak"].(*gocloak.GoCloak)
	if !ok {
		l.Log("Failed to convert the dependency to *gocloak.GoCloak")
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(utils.ErrFailedToLoadDependence))
	}

	var keycloakUser gocloak.User
	if u.ID == "" {
		users, err := gcClient.GetUsers(c, token, realm, gocloak.GetUsersParams{
			Username: &u.Username,
		})
		if err != nil || len(users) < 1 {
			l.Log("Error while getting user info")
			wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(utils.ErrWhileGettingInfo))
			return
		}
		id := users[0].ID
		keycloakUser = gocloak.User{
			ID:       id,
			Username: &u.Username,
			Enabled:  gocloak.BoolP(false),
		}
	} else {
		keycloakUser = gocloak.User{
			ID:       &u.ID,
			Username: &u.Username,
			Enabled:  gocloak.BoolP(false),
		}
	}
	err = gcClient.UpdateUser(c, token, realm, keycloakUser)
	if err != nil {
		l.LogActivity("Error while activating user:", logharbour.DebugInfo{Variables: map[string]any{"error": err}})
		wscutils.SendErrorResponse(c, &wscutils.Response{Data: err})
		return
	}

	// Send success response
	wscutils.SendSuccessResponse(c, &wscutils.Response{Status: wscutils.SuccessStatus})

	l.Log("Finished execution of User_activate()")
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

// Validate checks if either ID or Username is set, but not both.
func (u *userActivity) CustomValidate() error {
	if u.ID != "" && u.Username != "" {
		return errors.New("both ID and Username cannot be set")
	}
	if u.ID == "" && u.Username == "" {
		return errors.New("either ID or Username must be set")
	}
	return nil
}
