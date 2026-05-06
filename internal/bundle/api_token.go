package bundle

// APIToken is the relevant subset of an /api/v2/apiTokens entry.
// Token values themselves are never returned by the list endpoint, so this
// struct only carries metadata.
type APIToken struct {
	ID                   string   `json:"id"`
	Name                 string   `json:"name"`
	Owner                string   `json:"owner"`
	Enabled              bool     `json:"enabled"`
	PersonalAccessToken  bool     `json:"personalAccessToken"`
	CreationDate         string   `json:"creationDate"`         // RFC3339
	ExpirationDate       *string  `json:"expirationDate"`       // null = no expiration
	LastUsedDate         *string  `json:"lastUsedDate"`         // null = never used
	ModifiedDate         string   `json:"modifiedDate"`
	Scopes               []string `json:"scopes"`
}
