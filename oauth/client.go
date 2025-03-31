package oauth

import (
	"database/sql/driver"
	"strings"
)

type Strings []string

func (s *Strings) Scan(src any) error {
	val, _ := src.([]byte)
	*s = strings.Split(string(val), ",")
	return nil
}

func (s Strings) Value() (driver.Value, error) {
	if len(s) == 0 {
		return nil, nil
	}
	return []byte(strings.Join(s, ",")), nil
}

// Client OAuth2 클라이언트
type Client struct {
	ID           uint
	ClientID     string
	Secret       string
	OwnerID      string
	RedirectUris Strings
	Scopes       Strings
}
