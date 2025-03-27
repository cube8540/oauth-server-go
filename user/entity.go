package user

import (
	"database/sql"
)

type AccountEntity struct {
	ID                     uint           `gorm:"primaryKey;column:id"`
	Username               string         `gorm:"column:username"`
	Password               string         `gorm:"column:password"`
	Active                 bool           `gorm:"column:active"`
	ActiveToken            sql.NullString `gorm:"column:active_token"`
	ActiveTokenExpires     sql.NullTime   `gorm:"column:active_token_expires"`
	PasswordToken          sql.NullString `gorm:"column:password_token"`
	PasswordTokenExpires   sql.NullTime   `gorm:"column:password_token_expires"`
	LastPasswordModifiedAt sql.NullTime   `gorm:"column:last_mod_password_at"`
	RegisteredAt           sql.NullTime   `gorm:"column:reg_at"`
	ModifiedAt             sql.NullTime   `gorm:"column:mod_at"`
}

func (_ AccountEntity) TableName() string {
	return "users.account"
}

func (entity AccountEntity) ToDomain() *Account {
	account := Account{
		ID:            entity.ID,
		Username:      entity.Username,
		password:      entity.Password,
		active:        entity.Active,
		activeToken:   nil,
		passwordToken: nil,
	}

	if entity.ActiveToken.Valid {
		account.activeToken = &verificationToken{
			token:     entity.ActiveToken.String,
			expiresAt: entity.ActiveTokenExpires.Time,
		}
	}

	if entity.PasswordToken.Valid {
		account.passwordToken = &verificationToken{
			token:     entity.PasswordToken.String,
			expiresAt: entity.PasswordTokenExpires.Time,
		}
	}

	return &account
}
