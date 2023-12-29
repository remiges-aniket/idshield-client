package user

const (
	// Validation error messages
	AgeRange    = "10-150"
	NotProvided = "Not provided"
	//EmailDomain = "@domain.com" // this should come from config

	// User structure fields
	FIRST_NAME     = "FirstName"
	USER_AGE       = "Age"
	USER_FULL_NAME = "Fullname"
	USER_NAME      = "UserName"
	USER_EMAIL     = "Email"
	EMAIL_VERIFIED = "EmailVerified"
	ENABLED        = "Enabled"
	PASSWORD       = "Password"
	REALM          = "Realm"

	// Validation error messages
	RequiredError  = "required"
	InvalidEmail   = "email"
	EmailDomainErr = "emaildomain"
)
