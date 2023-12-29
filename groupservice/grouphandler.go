package group

import (
	"fmt"
	"strings"

	"github.com/Nerzal/gocloak/v13"
	"github.com/gin-gonic/gin"
	"github.com/remiges-tech/alya/router"
	"github.com/remiges-tech/alya/service"
	"github.com/remiges-tech/alya/wscutils"
	"github.com/remiges-tech/idshield-client/util"
)

// User_get: handles the GET /user request, this will ignore the case & return the exact match if found in case of username
func Group_get(c *gin.Context, s *service.Service) {
	lh := s.LogHarbour
	lh.Log("Group_get request received")
	client := s.Dependencies["gocloak"].(*gocloak.GoCloak)

	var groupParams gocloak.GetGroupsParams
	// Authz_check():
	isCapable := util.Authz_check()
	if !isCapable {
		wscutils.SendErrorResponse(c, wscutils.NewResponse(wscutils.ErrorStatus, nil, []wscutils.ErrorMessage{wscutils.BuildErrorMessage("User_not_authorized_to_perform_this_action", nil, "group_get")}))
		lh.Debug0().Log("User_not_authorized_to_perform_this_action")
		return
	}

	token, err := router.ExtractToken(c.GetHeader("Authorization")) // separate "Bearer_" word from token
	lh.Log("token extracted from header")
	if err != nil {
		wscutils.SendErrorResponse(c, wscutils.NewResponse(wscutils.ErrorStatus, nil, []wscutils.ErrorMessage{wscutils.BuildErrorMessage(wscutils.ErrcodeMissing, nil, "token")}))
		lh.Debug0().Log(fmt.Sprintf("token_missing: %v", map[string]any{"error": err.Error()}))
		return
	}

	realm, err := util.ExtractClaimFromJwt(token, "iss")
	if err != nil {
		wscutils.SendErrorResponse(c, wscutils.NewResponse(wscutils.ErrorStatus, nil, []wscutils.ErrorMessage{wscutils.BuildErrorMessage("invalid_token_payload", &realm)}))
		lh.Debug0().Log(fmt.Sprintf("invalid token payload: %v", map[string]any{"error": err.Error()}))
		return
	}
	split := strings.Split(realm, "/")
	realm = split[len(split)-1]

	lh.Log(fmt.Sprintf("Group_get realm parsed: %v", map[string]any{"realm": realm}))
	if gocloak.NilOrEmpty(&realm) {
		wscutils.SendErrorResponse(c, wscutils.NewResponse(wscutils.ErrorStatus, nil, []wscutils.ErrorMessage{wscutils.BuildErrorMessage("realm_not_found", &realm)}))
		lh.Debug0().Log(fmt.Sprintf("realm_not_found: %v", map[string]any{"realm": realm}))
		return
	}
	// id := c.Query("id")
	shortName := c.Query("shortName")
	if gocloak.NilOrEmpty(&shortName) {
		wscutils.SendErrorResponse(c, wscutils.NewResponse(wscutils.ErrorStatus, nil, []wscutils.ErrorMessage{wscutils.BuildErrorMessage(wscutils.ErrcodeMissing, nil, "shortName")}))
		lh.Debug0().Log("shortName missing")
		return
	}

	// step 4: process the request
	groupParams.Search = &shortName
	groups, err := client.GetGroups(c, token, realm, groupParams)
	lh.Log("GetGroups() request received")

	if err != nil || len(groups) == 0 {
		wscutils.SendErrorResponse(c, wscutils.NewResponse(wscutils.ErrorStatus, nil, []wscutils.ErrorMessage{wscutils.BuildErrorMessage("group_not_found", &realm)}))
		lh.Debug0().Log(fmt.Sprintf("group not found in given realm error: %v", map[string]any{"realm": realm}))
		return
	}

	// step 5: if there are no errors, send success response
	lh.Log(fmt.Sprintf("Group found: %v", groups[0]))
	wscutils.SendSuccessResponse(c, wscutils.NewSuccessResponse(groups[0]))
}
