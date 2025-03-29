package oauth

// Client OAuth2 클라이언트
type Client struct {
	ID           uint
	ClientID     string
	Secret       string
	OwnerID      string
	RedirectUris []string
}
