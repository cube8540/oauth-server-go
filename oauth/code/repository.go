package code

import (
	"errors"
	"fmt"
	"gorm.io/gorm"
)

type Repository struct {
	db *gorm.DB
}

func NewRepository(db *gorm.DB) *Repository {
	return &Repository{db: db}
}

func (r *Repository) Save(c *AuthorizationCode) error {
	return r.db.Omit("Scopes.*").Create(c).Error
}

func (r *Repository) FindByCode(code string) (*AuthorizationCode, error) {
	var e AuthorizationCode
	if err := r.db.Preload("Scopes").Where(&AuthorizationCode{Value: code}).First(&e).Error; err != nil {
		switch {
		case errors.Is(err, gorm.ErrRecordNotFound):
			return nil, fmt.Errorf("%w: authroization code(%s)", ErrNotFound, code)
		default:
			return nil, fmt.Errorf("error occurred duraing select authorization code (%s): %w", code, err)
		}
	}
	return &e, nil
}

func (r *Repository) Delete(c *AuthorizationCode) error {
	err := r.db.Model(c).Association("Scopes").Clear()
	if err != nil {
		return err
	}
	return r.db.Delete(c).Error
}
