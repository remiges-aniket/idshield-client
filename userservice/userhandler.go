package user

import (
	"fmt"
	"strings"
	"time"

	"github.com/Nerzal/gocloak/v13"
	"github.com/gin-gonic/gin"
	"github.com/remiges-tech/alya/router"
	"github.com/remiges-tech/alya/service"
	"github.com/remiges-tech/alya/wscutils"
	"github.com/remiges-tech/idshield-client/util"
)

type UserRequest struct {
	Realm    string                     `json:"realm" validate:"required,min=4"`
	User     gocloak.User               `json:"user,omitempty"`
	Params   gocloak.GetUsersParams     `json:"params,omitempty"`
	Password gocloak.SetPasswordRequest `json:"password,omitempty"`
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

type CreateUserResponse struct {
	Id        *string `json:"id,omitempty"`
	Username  *string `json:"username,omitempty"`
	Email     *string `json:"email,omitempty"`
	FirstName *string `json:"firstName,omitempty"`
	LastName  *string `json:"lastName,omitempty"`
	Enabled   *bool   `json:"enabled,omitempty"`
}

// User_get: handles the GET /user request, this will ignore the case & return the exact match if found in case of username
func User_get(c *gin.Context, s *service.Service) {
	lh := s.LogHarbour
	lh.Log("User_get request received")
	client := s.Dependencies["gocloak"].(*gocloak.GoCloak)
	params := gocloak.GetUsersParams{}

	var user *gocloak.User
	var users []*gocloak.User
	var err error

	token, err := router.ExtractToken(c.GetHeader("Authorization")) // separate "Bearer_" word from token
	lh.Log("token extracted from header")
	if err != nil {
		wscutils.SendErrorResponse(c, wscutils.NewResponse(wscutils.ErrorStatus, nil, []wscutils.ErrorMessage{wscutils.BuildErrorMessage(wscutils.ErrcodeMissing, &token)}))
		lh.Debug0().Log(fmt.Sprintf("token_missing: %v", map[string]any{"error": err.Error()}))
		return
	}

	realm, err := util.ExtractClaimFromJwt(token, "iss")
	split := strings.Split(realm, "/")
	realm = split[len(split)-1]

	lh.Log(fmt.Sprintf("User_get realm parsed: %v", map[string]any{"realm": realm}))
	if gocloak.NilOrEmpty(&realm) {
		wscutils.SendErrorResponse(c, wscutils.NewResponse(wscutils.ErrorStatus, nil, []wscutils.ErrorMessage{wscutils.BuildErrorMessage("realm_not_found", &realm)}))
		lh.Debug0().Log(fmt.Sprintf("realm_not_found: %v", map[string]any{"realm": realm}))
		return
	}
	id := c.Query("id")
	userName := c.Query("name")
	if gocloak.NilOrEmpty(&id) && gocloak.NilOrEmpty(&userName) {
		id, userName = "id", "userName"
		wscutils.SendErrorResponse(c, wscutils.NewResponse(wscutils.ErrorStatus, nil, []wscutils.ErrorMessage{wscutils.BuildErrorMessage(wscutils.ErrcodeMissing, &id), wscutils.BuildErrorMessage(wscutils.ErrcodeMissing, &userName)}))
		lh.Debug0().Log("id & name both are null")
		return
	}

	// step 4: process the request
	if !gocloak.NilOrEmpty(&id) {
		user, err = client.GetUserByID(c, token, realm, id)
		lh.Log("GetUserByID() request received")
		users = append(users, user)
	} else if !gocloak.NilOrEmpty(&userName) {
		params.Username = &userName
		users, err = client.GetUsers(c, token, realm, params)
		lh.Log("GetUsers() request received")

	}

	user = users[0]

	if err != nil {
		wscutils.SendErrorResponse(c, wscutils.NewResponse(wscutils.ErrorStatus, nil, []wscutils.ErrorMessage{wscutils.BuildErrorMessage("user_not_found", &realm)}))
		lh.Debug0().Log(fmt.Sprintf("user not found in given realm error: %v", map[string]any{"error": err.Error()}))
		return
	}

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
		CreatedAt:     util.UnixMilliToTimestamp(*user.CreatedTimestamp),
	}

	// step 5: if there are no errors, send success response
	lh.Log(fmt.Sprintf("User found: %v", map[string]any{"user": userResp}))
	wscutils.SendSuccessResponse(c, wscutils.NewSuccessResponse(userResp))
}
