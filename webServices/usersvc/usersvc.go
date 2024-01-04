package usersvc

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Nerzal/gocloak/v13"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"

	"github.com/remiges-tech/alya/router"
	"github.com/remiges-tech/alya/service"
	"github.com/remiges-tech/alya/wscutils"
	"github.com/remiges-tech/idshield/types"
	"github.com/remiges-tech/idshield/utils"
	"github.com/remiges-tech/logharbour/logharbour"
)

type user struct {
	ID         string            `json:"id,omitempty"`
	Username   string            `json:"username" validate:"required"`
	Email      string            `json:"email" validate:"required,email"`
	FirstName  string            `json:"firstName,omitempty"`
	LastName   string            `json:"lastName,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
	Enabled    bool              `json:"enabled" validate:"required"`
}

// type userUpdateReq struct {
// 	ID            *string `json:"id"`
// 	Username      *string `json:"username" validate:"required"`
// 	Email         *string `json:"email" validate:"required,email"`
// 	FirstName     *string `json:"firstName"`
// 	LastName      *string `json:"lastName"`
// 	EmailVerified *bool   `json:"emailVerified,omitempty"`
// 	Attributes    *string `json:"attributes"`
// 	Enabled       *bool   `json:"enabled" validate:"required"`
// }

type UserListRequest struct {
	Email         *string `json:"email,omitempty"`
	FirstName     *string `json:"firstName,omitempty"`
	LastName      *string `json:"lastName,omitempty"`
	EmailVerified *bool   `json:"emailVerified,omitempty"`
	Enabled       *bool   `json:"enabled,omitempty"`
	Attributes    *string `json:"attributes,omitempty"`
	Search        *string `json:"search,omitempty"`
	CreatedAfter  *string `json:"createdafter,omitempty"`
}

type UserResponse struct {
	Id            *string              `json:"id,omitempty"`
	Username      *string              `json:"username,omitempty"`
	Email         *string              `json:"email,omitempty"`
	FirstName     *string              `json:"firstName,omitempty"`
	LastName      *string              `json:"lastName,omitempty"`
	EmailVerified *bool                `json:"emailVerified,omitempty"`
	Enabled       *bool                `json:"enabled,omitempty" validate:"required"`
	Attributes    *map[string][]string `json:"attributes,omitempty"`
	CreatedAt     time.Time            `json:"createdat,omitempty"`
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
	r, err := utils.ExtractClaimFromJwt(token, "iss")
	if err != nil {
		l.Debug0().LogDebug("Missing or incorrect realm:", logharbour.DebugInfo{Variables: map[string]any{"error": err}})
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(utils.ErrRealmNotFound))
		return
	}
	parts := strings.Split(r, "/realms/")
	realm := parts[1]
	username, err := utils.ExtractClaimFromJwt(token, "preferred_username")
	if err != nil {
		l.Debug0().LogDebug("Missing username:", logharbour.DebugInfo{Variables: map[string]any{"error": err}})
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(utils.ErrUserNotFound))
		return
	}

	isCapable, _ := utils.Authz_check(types.OpReq{
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
	if err = wscutils.BindJSON(c, &u); err != nil {
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
	attr := make(map[string][]string)
	for key, value := range u.Attributes {
		attr[key] = []string{value}
	}

	keycloakUser := gocloak.User{
		Username:   &u.Username,
		FirstName:  &u.FirstName,
		LastName:   &u.LastName,
		Email:      &u.Email,
		Attributes: &attr,
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
		utils.GocloakErrorHandler(c, l, err)
		return
	}

	// Send success response
	wscutils.SendSuccessResponse(c, &wscutils.Response{Status: wscutils.SuccessStatus, Data: ID, Messages: []wscutils.ErrorMessage{}})

	l.Log("Finished execution of User_new()")
}

// User_list handles the GET /userlist request
func User_list(c *gin.Context, s *service.Service) {
	lh := s.LogHarbour
	lh.Log("User_list request received")
	var usrListRequest UserListRequest
	var eachUserResp UserResponse
	var response []UserResponse
	var afterDate time.Time
	// step 1: bind request body to struct if not null
	err := wscutils.BindJSON(c, &usrListRequest)
	if err != nil {
		lh.LogActivity("Error Unmarshalling JSON to struct:", logharbour.DebugInfo{Variables: map[string]any{"Error": err.Error()}})
		return
	}

	if !gocloak.NilOrEmpty(usrListRequest.CreatedAfter) {
		afterDate, err = time.Parse(time.DateOnly, *usrListRequest.CreatedAfter)
		if err != nil {
			wscutils.SendErrorResponse(c, wscutils.NewResponse(wscutils.ErrorStatus, nil, []wscutils.ErrorMessage{wscutils.BuildErrorMessage("invalid_date_format", nil, "CreatedAfter", *usrListRequest.CreatedAfter)}))
			lh.Debug0().Log(fmt.Sprintf("failed to parse afterDate: %v", map[string]any{"error": err.Error()}))
			return
		}
	}

	client := s.Dependencies["gocloak"].(*gocloak.GoCloak)

	token, err := router.ExtractToken(c.GetHeader("Authorization")) // separate "Bearer " word from token
	if err != nil {
		wscutils.SendErrorResponse(c, wscutils.NewResponse(wscutils.ErrorStatus, nil, []wscutils.ErrorMessage{wscutils.BuildErrorMessage(wscutils.ErrcodeMissing, nil, "token")}))
		lh.Debug0().Log(fmt.Sprintf("token_missing: %v", map[string]any{"error": err.Error()}))
		return
	}
	lh.Log("token extracted from header")

	reqUserName, err := utils.ExtractClaimFromJwt(token, "preferred_username")
	if err != nil {
		wscutils.SendErrorResponse(c, wscutils.NewResponse(wscutils.ErrorStatus, nil, []wscutils.ErrorMessage{wscutils.BuildErrorMessage(wscutils.ErrcodeMissing, nil, "preferred_username")}))
		lh.LogActivity("Error while extracting preferred_username from token:", logharbour.DebugInfo{Variables: map[string]any{"preferred_username": err.Error()}})
		return
	}
	// Authz_check():
	isCapable, _ := utils.Authz_check(types.OpReq{User: reqUserName, CapNeeded: []string{"devloper", "admin"}}, false)
	if !isCapable {
		wscutils.SendErrorResponse(c, wscutils.NewResponse(wscutils.ErrorStatus, nil, []wscutils.ErrorMessage{wscutils.BuildErrorMessage(utils.ErrUserNotAuthorized, nil)}))
		lh.Debug0().Log(utils.ErrUserNotAuthorized)
		return
	}

	realm := getRealmFromJwt(c, token)
	if gocloak.NilOrEmpty(&realm) {
		wscutils.SendErrorResponse(c, wscutils.NewResponse(wscutils.ErrorStatus, nil, []wscutils.ErrorMessage{wscutils.BuildErrorMessage(utils.ErrRealmNotFound, &realm)}))
		lh.Debug0().Log(fmt.Sprintf("realm_not_found: %v", map[string]any{"realm": realm}))
		return
	}
	lh.Log(fmt.Sprintf("User_update realm parsed: %v", map[string]any{"realm": realm}))

	// step 4: process the request
	users, err := client.GetUsers(c, token, realm, gocloak.GetUsersParams{
		Email:         usrListRequest.Email,
		EmailVerified: usrListRequest.EmailVerified,
		Enabled:       usrListRequest.Enabled,
		FirstName:     usrListRequest.FirstName,
		LastName:      usrListRequest.LastName,
		Q:             usrListRequest.Attributes,
		Search:        usrListRequest.Search,
	})
	if err != nil {
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(wscutils.ErrcodeDatabaseError))
		lh.LogActivity(wscutils.ErrcodeDatabaseError, err.Error)
		return
	}

	if !gocloak.NilOrEmpty(usrListRequest.CreatedAfter) {
		for _, eachUser := range users {
			if afterDate.Before(utils.UnixMilliToTimestamp(*eachUser.CreatedTimestamp)) {
				// setting response fields
				eachUserResp = UserResponse{
					Id:            eachUser.ID,
					Username:      eachUser.Username,
					Email:         eachUser.Email,
					FirstName:     eachUser.FirstName,
					LastName:      eachUser.LastName,
					EmailVerified: eachUser.EmailVerified,
					Enabled:       eachUser.Enabled,
					Attributes:    eachUser.Attributes,
					CreatedAt:     utils.UnixMilliToTimestamp(*eachUser.CreatedTimestamp),
				}
				response = append(response, eachUserResp)
			}
		}
	} else {
		for _, eachUser := range users {
			// setting response fields
			eachUserResp = UserResponse{
				Id:            eachUser.ID,
				Username:      eachUser.Username,
				Email:         eachUser.Email,
				FirstName:     eachUser.FirstName,
				LastName:      eachUser.LastName,
				EmailVerified: eachUser.EmailVerified,
				Enabled:       eachUser.Enabled,
				Attributes:    eachUser.Attributes,
				CreatedAt:     utils.UnixMilliToTimestamp(*eachUser.CreatedTimestamp),
			}
			response = append(response, eachUserResp)
		}
	}
	// step 5: if there are no errors, send success response
	wscutils.SendSuccessResponse(c, wscutils.NewSuccessResponse(response))
}

// User_get: handles the GET /userget request, accept id or username as exact match if found will return else user_not_found
func User_get(c *gin.Context, s *service.Service) {
	lh := s.LogHarbour
	lh.Log("User_get request received")
	client := s.Dependencies["gocloak"].(*gocloak.GoCloak)
	params := gocloak.GetUsersParams{}

	var user *gocloak.User
	var users []*gocloak.User
	exactMatch := true

	token, err := router.ExtractToken(c.GetHeader("Authorization")) // separate "Bearer_" word from token
	if err != nil {
		wscutils.SendErrorResponse(c, wscutils.NewResponse(wscutils.ErrorStatus, nil, []wscutils.ErrorMessage{wscutils.BuildErrorMessage(wscutils.ErrcodeMissing, nil, "token")}))
		lh.Debug0().Log(fmt.Sprintf("token_missing: %v", map[string]any{"error": err.Error()}))
		return
	}
	lh.Log("token extracted from header")

	reqUserName, _ := utils.ExtractClaimFromJwt(token, "preferred_username")

	// Authz_check():
	isCapable, _ := utils.Authz_check(types.OpReq{User: reqUserName, CapNeeded: []string{"devloper", "admin"}}, false)
	if !isCapable {
		wscutils.SendErrorResponse(c, wscutils.NewResponse(wscutils.ErrorStatus, nil, []wscutils.ErrorMessage{wscutils.BuildErrorMessage(utils.ErrUserNotAuthorized, nil)}))
		lh.Debug0().Log(utils.ErrUserNotAuthorized)
		return
	}

	realm := getRealmFromJwt(c, token)
	if gocloak.NilOrEmpty(&realm) {
		wscutils.SendErrorResponse(c, wscutils.NewResponse(wscutils.ErrorStatus, nil, []wscutils.ErrorMessage{wscutils.BuildErrorMessage(utils.ErrRealmNotFound, &realm)}))
		lh.Debug0().Log(fmt.Sprintf("realm_not_found: %v", map[string]any{"realm": realm}))
		return
	}
	lh.Log(fmt.Sprintf("User_update realm parsed: %v", map[string]any{"realm": realm}))

	id := c.Query("id")
	userName := c.Query("name")
	if gocloak.NilOrEmpty(&id) && gocloak.NilOrEmpty(&userName) {
		wscutils.SendErrorResponse(c, wscutils.NewResponse(wscutils.ErrorStatus, nil, []wscutils.ErrorMessage{wscutils.BuildErrorMessage(wscutils.ErrcodeMissing, nil, "id", "name")}))
		lh.Debug0().Log(utils.ErrIDandUserNameMissing)
		return
	}

	// step 4: process the request
	if !gocloak.NilOrEmpty(&id) {
		user, err = client.GetUserByID(c, token, realm, id)
		lh.Log("GetUserByID() request received")
		users = append(users, user)
	} else if !gocloak.NilOrEmpty(&userName) {
		params.Username = &userName
		params.Exact = &exactMatch
		users, err = client.GetUsers(c, token, realm, params)
		lh.Log("GetUsers() by name param request received")
	}

	if err != nil || len(users) == 0 {
		switch err.Error() {
		case utils.ErrHTTPUnauthorized:
			wscutils.SendErrorResponse(c, wscutils.NewResponse(wscutils.ErrorStatus, nil, []wscutils.ErrorMessage{wscutils.BuildErrorMessage(wscutils.ErrcodeTokenVerificationFailed, &realm, err.Error())}))
			lh.Debug0().Log(fmt.Sprintf("token expired error from keycloak: %v", map[string]any{"error": err.Error()}))
		default:
			wscutils.SendErrorResponse(c, wscutils.NewResponse(wscutils.ErrorStatus, nil, []wscutils.ErrorMessage{wscutils.BuildErrorMessage(utils.ErrUserNotFound, &realm, err.Error())}))
			lh.Debug0().Log(fmt.Sprintf("user not found in given realm: %v", map[string]any{"realm": realm, "error": err.Error()}))
		}
		return
	}
	user = users[0]

	// setting response fields
	userResp := UserResponse{
		Id:            user.ID,
		Username:      user.Username,
		Email:         user.Email,
		FirstName:     user.FirstName,
		LastName:      user.LastName,
		EmailVerified: user.EmailVerified,
		Enabled:       user.Enabled,
		Attributes:    user.Attributes,
		CreatedAt:     utils.UnixMilliToTimestamp(*user.CreatedTimestamp),
	}

	// step 5: if there are no errors, send success response
	lh.Log(fmt.Sprintf("User found: %v", map[string]any{"user": userResp}))
	wscutils.SendSuccessResponse(c, wscutils.NewSuccessResponse(userResp))
}

// User_update handles the PUT /user/update request
func User_update(c *gin.Context, s *service.Service) {
	lh := s.LogHarbour
	lh.Log("User_update request received")
	var gcUser *gocloak.User
	var users []*gocloak.User

	// step 1: bind request body to struct if not null
	err := wscutils.BindJSON(c, &gcUser)
	if err != nil {
		lh.LogActivity("Error Unmarshalling JSON to struct:", logharbour.DebugInfo{Variables: map[string]any{"Error": err.Error()}})
		return
	}

	if gocloak.NilOrEmpty(gcUser.ID) && gocloak.NilOrEmpty(gcUser.Username) {
		wscutils.SendErrorResponse(c, wscutils.NewResponse(wscutils.ErrorStatus, nil, []wscutils.ErrorMessage{wscutils.BuildErrorMessage(wscutils.ErrcodeMissing, nil, "id", "username")}))
		lh.Debug0().Log(utils.ErrIDandUserNameMissing)
		return
	}

	client := s.Dependencies["gocloak"].(*gocloak.GoCloak)

	token, err := router.ExtractToken(c.GetHeader("Authorization")) // separate "Bearer " word from token
	if err != nil {
		wscutils.SendErrorResponse(c, wscutils.NewResponse(wscutils.ErrorStatus, nil, []wscutils.ErrorMessage{wscutils.BuildErrorMessage(wscutils.ErrcodeMissing, nil, "token")}))
		lh.Debug0().Log(fmt.Sprintf("token_missing: %v", map[string]any{"error": err.Error()}))
		return
	}
	lh.Log("token extracted from header")

	reqUserName, err := utils.ExtractClaimFromJwt(token, "preferred_username")
	if err != nil {
		wscutils.SendErrorResponse(c, wscutils.NewResponse(wscutils.ErrorStatus, nil, []wscutils.ErrorMessage{wscutils.BuildErrorMessage(wscutils.ErrcodeMissing, nil, "preferred_username")}))
		lh.LogActivity("Error while extracting preferred_username from token:", logharbour.DebugInfo{Variables: map[string]any{"preferred_username": err.Error()}})
		return
	}
	// Authz_check():
	isCapable, _ := utils.Authz_check(types.OpReq{User: reqUserName, CapNeeded: []string{"devloper", "admin"}}, false)
	if !isCapable {
		wscutils.SendErrorResponse(c, wscutils.NewResponse(wscutils.ErrorStatus, nil, []wscutils.ErrorMessage{wscutils.BuildErrorMessage(utils.ErrUserNotAuthorized, nil)}))
		lh.Debug0().Log(utils.ErrUserNotAuthorized)
		return
	}

	realm := getRealmFromJwt(c, token)
	if gocloak.NilOrEmpty(&realm) {
		wscutils.SendErrorResponse(c, wscutils.NewResponse(wscutils.ErrorStatus, nil, []wscutils.ErrorMessage{wscutils.BuildErrorMessage(utils.ErrRealmNotFound, &realm)}))
		lh.Debug0().Log(fmt.Sprintf("realm_not_found: %v", map[string]any{"realm": realm}))
		return
	}
	lh.Log(fmt.Sprintf("User_update realm parsed: %v", map[string]any{"realm": realm}))

	// step 4: process the request
	if !gocloak.NilOrEmpty(gcUser.Username) {
		exactMatch := true
		users, _ = client.GetUsers(c, token, realm, gocloak.GetUsersParams{Exact: &exactMatch, Username: gcUser.Username})
		if len(users) != 0 {
			gcUser.ID = users[0].ID
		}
	}
	err = client.UpdateUser(c, token, realm, *gcUser)
	if err != nil {
		switch err.Error() {
		case "401 Unauthorized: HTTP 401 Unauthorized":
			wscutils.SendErrorResponse(c, wscutils.NewResponse(wscutils.ErrorStatus, nil, []wscutils.ErrorMessage{wscutils.BuildErrorMessage(wscutils.ErrcodeTokenVerificationFailed, &realm, err.Error())}))
			lh.Debug0().Log(fmt.Sprintf("token expired error from keycloak: %v", map[string]any{"error": err.Error()}))
		default:
			wscutils.SendErrorResponse(c, wscutils.NewResponse(wscutils.ErrorStatus, nil, []wscutils.ErrorMessage{wscutils.BuildErrorMessage("user_not_found", &realm)}))
			lh.Debug0().Log(fmt.Sprintf("user not found in given realm: %v", map[string]any{"realm": realm, "error": err.Error()}))
		}
		return
	}

	// step 5: if there are no errors, send success response
	wscutils.SendSuccessResponse(c, wscutils.NewSuccessResponse([]string{}))
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
	r, err := utils.ExtractClaimFromJwt(token, "iss")
	if err != nil {
		l.Debug0().LogDebug("Missing or incorrect realm:", logharbour.DebugInfo{Variables: map[string]any{"error": err}})
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(utils.ErrRealmNotFound))
		return
	}
	parts := strings.Split(r, "/realms/")
	realm := parts[1]
	username, err := utils.ExtractClaimFromJwt(token, "preferred_username")
	if err != nil {
		l.Debug0().LogDebug("Missing username:", logharbour.DebugInfo{Variables: map[string]any{"error": err}})
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(utils.ErrUserNotFound))
		return
	}

	isCapable, _ := utils.Authz_check(types.OpReq{
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
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(utils.ErrIDandUserNameMissing))
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
		if err != nil {
			utils.GocloakErrorHandler(c, l, err)
			return
		}
		if len(users) == 0 {
			l.Log("Error while gcClient.GetUsers username doesn't exist ")
			str := "username"
			wscutils.SendErrorResponse(c, wscutils.NewResponse("error", nil, []wscutils.ErrorMessage{wscutils.BuildErrorMessage(utils.ErrNotExist, &str)}))
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
		utils.GocloakErrorHandler(c, l, err)
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
	r, err := utils.ExtractClaimFromJwt(token, "iss")
	if err != nil {
		l.Debug0().LogDebug("Missing or incorrect realm:", logharbour.DebugInfo{Variables: map[string]any{"error": err}})
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(utils.ErrRealmNotFound))
		return
	}
	parts := strings.Split(r, "/realms/")
	realm := parts[1]
	username, err := utils.ExtractClaimFromJwt(token, "preferred_username")
	if err != nil {
		l.Debug0().LogDebug("Missing username:", logharbour.DebugInfo{Variables: map[string]any{"error": err}})
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(utils.ErrUserNotFound))
		return
	}

	isCapable, _ := utils.Authz_check(types.OpReq{
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
		if err != nil {
			utils.GocloakErrorHandler(c, l, err)
			return
		}
		if len(users) == 0 {
			l.Log("Error while gcClient.GetUsers username doesn't exist ")
			str := "username"
			wscutils.SendErrorResponse(c, wscutils.NewResponse("error", nil, []wscutils.ErrorMessage{wscutils.BuildErrorMessage(utils.ErrNotExist, &str)}))
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
		utils.GocloakErrorHandler(c, l, err)
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

func getRealmFromJwt(c *gin.Context, token string) string {
	realm, err := utils.ExtractClaimFromJwt(token, "iss")
	if err != nil {
		return ""
	}
	split := strings.Split(realm, "/")
	realm = split[len(split)-1]
	return realm
}
