package groupsvc

import (
	"github.com/Nerzal/gocloak/v13"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/remiges-tech/alya/router"
	"github.com/remiges-tech/alya/service"
	"github.com/remiges-tech/alya/wscutils"
	"github.com/remiges-tech/idshield/utils"
	"github.com/remiges-tech/logharbour/logharbour"
)

type group struct {
	ID         string              `json:"id,omitempty"`
	ShortName  string              `json:"shortName" validate:"required"`
	LongName   string              `json:"longName" validate:"required"`
	Attributes map[string][]string `json:"attr" validate:"required"`
}

func Group_new(c *gin.Context, s *service.Service) {
	l := s.LogHarbour
	l.Log("Starting execution of Group_new()")

	isCapable, _ := utils.Authz_check()
	if !isCapable {
		l.Log("Unauthorized user:")
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(utils.ErrUnauthorized))
		return
	}

	var g group

	if err := wscutils.BindJSON(c, &g); err != nil {
		l.LogActivity("Error Unmarshalling JSON to struct:", logharbour.DebugInfo{Variables: map[string]any{"Error": err.Error()}})
		return
	}

	//Validate incoming request
	validationErrors := validateGroup(c, g)
	if len(validationErrors) > 0 {
		l.Debug0().LogDebug("Validation errors:", logharbour.DebugInfo{Variables: map[string]interface{}{"validationErrors": validationErrors}})
		wscutils.SendErrorResponse(c, wscutils.NewResponse(wscutils.ErrorStatus, nil, validationErrors))
		return
	}

	// Extracting the GoCloak client from the service dependencies
	gcClient, ok := s.Dependencies["gocloak"].(*gocloak.GoCloak)
	if !ok {
		l.Log("Failed to convert the dependency to *gocloak.GoCloak")
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(utils.ErrFailedToLoadDependence))
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
	g.Attributes["longName"] = []string{g.LongName}

	group := gocloak.Group{
		Name:       &g.ShortName,
		Attributes: &g.Attributes,
	}

	// Create a group
	_, err = gcClient.CreateGroup(c, token, realm, group)
	if err != nil {
		l.LogActivity("Error while creating user:", logharbour.DebugInfo{Variables: map[string]any{"error": err}})
		utils.GocloakErrorHandler(c, l, err)
		return
	}

	// Send success response
	wscutils.SendSuccessResponse(c, &wscutils.Response{Status: "success"})

	// Log the completion of execution
	l.Log("Finished execution of Group_new()")
}

// HandleCreateUserRequest is for updating group capabilities.
func Group_update(c *gin.Context, s *service.Service) {
	l := s.LogHarbour
	l.Log("Starting execution of Group_update() ")

	isCapable, _ := utils.Authz_check()
	if !isCapable {
		l.Log("Unauthorized user:")
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(utils.ErrUnauthorized))
		return
	}

	var g group

	// Unmarshal JSON request into group struct
	err := wscutils.BindJSON(c, &g)
	if err != nil {
		l.LogActivity("Error Unmarshalling JSON to struct:", logharbour.DebugInfo{Variables: map[string]any{"Error": err.Error()}})
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(wscutils.ErrcodeInvalidJson))
		return
	}

	// Validate the group struct
	validationErrors := validateGroup(c, g)
	if len(validationErrors) > 0 {
		l.Debug0().LogDebug("Validation errors:", logharbour.DebugInfo{Variables: map[string]any{"validationErrors": validationErrors}})
		wscutils.SendErrorResponse(c, wscutils.NewResponse(wscutils.ErrorStatus, nil, validationErrors))
		return
	}

	// Extracting the GoCloak client from the service dependencies
	gcClient, ok := s.Dependencies["gocloak"].(*gocloak.GoCloak)
	if !ok {
		l.Log("Failed to convert the dependency to *gocloak.GoCloak")
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(utils.ErrFailedToLoadDependence))
	}

	realm := s.Dependencies["realm"].(string)

	token, err := router.ExtractToken(c.GetHeader("Authorization"))
	if err != nil {
		l.Debug0().LogDebug("Missing or incorrect Authorization header format:", logharbour.DebugInfo{Variables: map[string]any{"error": err}})
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(utils.ErrTokenMissing))
		return
	}

	groups, err := gcClient.GetGroups(c, token, realm, gocloak.GetGroupsParams{
		Search: &g.ShortName,
	})
	if err != nil {
		l.LogActivity("Error while getting group ID:", logharbour.DebugInfo{Variables: map[string]any{"Error": err.Error()}})
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(utils.ErrUnauthorized))
		return
	}
	g.Attributes["longName"] = []string{g.LongName}

	UpdateGroupParm := gocloak.Group{
		ID:         groups[0].ID,
		Name:       &g.ShortName,
		Attributes: &g.Attributes,
	}
	// UpdateGroup updates the given group by group name
	err = gcClient.UpdateGroup(c, token, realm, UpdateGroupParm)
	if err != nil {
		l.LogActivity("Error while creating user:", logharbour.DebugInfo{Variables: map[string]any{"error": err}})
		utils.GocloakErrorHandler(c, l, err)
		return
	}

	// Send success response
	wscutils.SendSuccessResponse(c, &wscutils.Response{Status: "success"})

	l.Log("Finished update Group_Update()")
}

// validateCreateUser performs validation for the createUserRequest.
func validateGroup(c *gin.Context, g group) []wscutils.ErrorMessage {
	// Validate the request body
	validationErrors := wscutils.WscValidate(g, g.getValsForGroup)

	if len(validationErrors) > 0 {
		return validationErrors
	}
	return validationErrors
}

// getValsForUser returns validation error details based on the field and tag.
func (g *group) getValsForGroup(err validator.FieldError) []string {
	var vals []string
	switch err.Field() {
	case "Name":
		switch err.Tag() {
		case "required":
			vals = append(vals, "non-empty")
			vals = append(vals, g.ShortName)
		}
	case "LongName":
		switch err.Tag() {
		case "required":
			vals = append(vals, "non-empty")
			vals = append(vals, g.LongName)
		}
	case "Attributes":
		switch err.Tag() {
		case "required":
			vals = append(vals, "non-empty")
			vals = append(vals, " ")
		}
	}
	return vals
}
