package repository

import (
	"gorm.io/gorm"
	"oauth-server-go/oauth/entity"
)

type ClientRepository struct {
	db *gorm.DB
}

func NewClientRepository(db *gorm.DB) *ClientRepository {
	return &ClientRepository{db: db}
}

func (r ClientRepository) FindByClientID(id string) (*entity.Client, error) {
	var c entity.Client
	err := r.db.Preload("Scopes").Where(&entity.Client{ClientID: id}).First(&c).Error
	if err != nil {
		return nil, err
	}
	return &c, nil
}

type TokenRepository struct {
	db *gorm.DB
}

func NewTokenRepository(db *gorm.DB) *TokenRepository {
	return &TokenRepository{db: db}
}

func (r TokenRepository) Save(t *entity.Token, fn func(t *entity.Token) *entity.RefreshToken) error {
	return r.db.Transaction(func(db *gorm.DB) error {
		if err := db.Save(t).Error; err != nil {
			return err
		}
		if refresh := fn(t); refresh != nil {
			if err := db.Save(refresh).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

type AuthCodeRepository struct {
	db *gorm.DB
}

func NewAuthCodeRepository(db *gorm.DB) *AuthCodeRepository {
	return &AuthCodeRepository{db: db}
}

func (r AuthCodeRepository) Save(c *entity.AuthorizationCode) error {
	return r.db.Save(c).Error
}

func (r AuthCodeRepository) FindByCode(code string) (*entity.AuthorizationCode, error) {
	var e entity.AuthorizationCode
	err := r.db.Preload("Scopes").Where(&entity.AuthorizationCode{Value: code}).First(&e).Error
	if err != nil {
		return nil, err
	}
	return &e, nil
}

func (r AuthCodeRepository) Delete(c *entity.AuthorizationCode) error {
	err := r.db.Model(c).Association("Scopes").Clear()
	if err != nil {
		return err
	}
	return r.db.Delete(c).Error
}
