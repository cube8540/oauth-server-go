package client

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

func (r *Repository) FindByClientID(id string) (*Client, error) {
	var c Client
	if err := r.db.Preload("Scopes").Where(&Client{ClientID: id}).First(&c).Error; err != nil {
		switch {
		case errors.Is(err, gorm.ErrRecordNotFound):
			return nil, fmt.Errorf("%w: client(%s)", ErrNotFound, id)
		default:
			return nil, fmt.Errorf("error occurred during select client(%s): %w", id, err)
		}
	}
	return &c, nil
}
