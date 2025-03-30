package oauth

import (
	"database/sql/driver"
	"strings"
)

type RedirectUris []string

func (r *RedirectUris) Scan(src any) error {
	val, _ := src.([]byte)
	*r = strings.Split(string(val), ",")
	return nil
}

func (r RedirectUris) Value() (driver.Value, error) {
	if len(r) == 0 {
		return nil, nil
	}
	return []byte(strings.Join(r, ",")), nil
}

// Client OAuth2 클라이언트
type Client struct {
	ID           uint
	ClientID     string
	Secret       string
	OwnerID      string
	RedirectUris RedirectUris
}
