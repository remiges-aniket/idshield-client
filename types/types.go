package types

type AppConfig struct {
	DBConnURL        string `json:"db_conn_url"`
	DBHost           string `json:"db_host"`
	DBPort           int    `json:"db_port"`
	DBUser           string `json:"db_user"`
	DBPassword       string `json:"db_password"`
	DBName           string `json:"db_name"`
	AppServerPort    string `json:"app_server_port"`
	ProviderUrl      string `json:"provider_url"`
	KeycloakURL      string `json:"keycloak_url"`
	KeycloakClientID string `json:"keycloak_client_id"`
}

type OpReq struct {
	User      string   `json:"user"`
	CapNeeded []string `json:"capNeeded"`
	Scope     scope    `json:"scope"`
	Limit     limit    `json:"limit"`
}

type scope map[string]string
type limit map[string]int64

// Capabilities representing user capabilities.
type Capabilities struct {
	Caplist []Caplist `json:"caplist"`
}

type Caplist struct {
	Cap   string   `json:"cap"`
	Scope []string `json:"scope"`
	Limit []string `json:"limit"`
}
