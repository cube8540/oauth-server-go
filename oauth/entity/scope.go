package entity

import "time"

type Scope struct {
	ID           uint
	Code         string
	Name         string
	Desc         string
	RegisteredAt time.Time
}

func (s Scope) TableName() string {
	return "users.oauth2_scope"
}
