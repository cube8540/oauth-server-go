package oauth

// Client OAuth2 클라이언트
type Client struct {
	ID           string
	Secret       string
	OwnerID      string
	RedirectUris []string
}
