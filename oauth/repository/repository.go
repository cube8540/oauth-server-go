package repository

import (
	"errors"
	"gorm.io/gorm"
	"oauth-server-go/oauth"
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
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, oauth.ErrClientNotFound
	}
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
		if err := db.Omit("Scopes.*").Create(t).Error; err != nil {
			return err
		}
		if refresh := fn(t); refresh != nil {
			if err := db.Create(refresh).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

func (r TokenRepository) FindAccessTokenByValue(v string) (*entity.Token, error) {
	var t entity.Token
	err := r.db.Preload("Scopes").Joins("Client").Where(&entity.Token{Value: v}).First(&t).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, oauth.ErrTokenNotFound
	}
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func (r TokenRepository) FindRefreshTokenByValue(v string) (*entity.RefreshToken, error) {
	var t entity.RefreshToken
	err := r.db.Joins("Token").Joins("Token.Client").Preload("Token.Scopes").Where(&entity.RefreshToken{Value: v}).First(&t).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, oauth.ErrTokenNotFound
	}
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func (r TokenRepository) Refresh(oldRefreshToken *entity.RefreshToken, newToken *entity.Token, fn func(t *entity.Token) *entity.RefreshToken) error {
	return r.db.Transaction(func(db *gorm.DB) error {
		oldToken := oldRefreshToken.Token
		if err := db.Delete(oldRefreshToken).Error; err != nil {
			return err
		}
		if err := db.Model(&oldToken).Association("Scopes").Clear(); err != nil {
			return err
		}
		if err := db.Delete(oldToken).Error; err != nil {
			return err
		}
		if err := db.Omit("Scopes.*").Create(newToken).Error; err != nil {
			return err
		}
		if nrt := fn(newToken); nrt != nil {
			if err := db.Save(nrt).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

func (r TokenRepository) FindAccessTokenByUsername(u string) ([]entity.Token, error) {
	var tokens []entity.Token
	if err := r.db.Preload("Scopes").Joins("Client").Where(&entity.Token{Username: u}).Find(&tokens).Error; err != nil {
		return nil, err
	}
	return tokens, nil
}

func (r TokenRepository) FindRefreshTokenByTokenID(id uint) (*entity.RefreshToken, error) {
	var rt *entity.RefreshToken
	err := r.db.Where(&entity.RefreshToken{TokenID: id}).First(&rt).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, oauth.ErrTokenNotFound
	}
	return rt, nil
}

func (r TokenRepository) Delete(t *entity.Token, rt *entity.RefreshToken) error {
	return r.db.Transaction(func(db *gorm.DB) error {
		if rt != nil {
			if err := db.Delete(rt).Error; err != nil {
				return err
			}
		}
		if err := db.Model(&t).Association("Scopes").Clear(); err != nil {
			return nil
		}
		return db.Delete(t).Error
	})
}

type AuthCodeRepository struct {
	db *gorm.DB
}

func NewAuthCodeRepository(db *gorm.DB) *AuthCodeRepository {
	return &AuthCodeRepository{db: db}
}

func (r AuthCodeRepository) Save(c *entity.AuthorizationCode) error {
	return r.db.Omit("Scopes.*").Create(c).Error
}

func (r AuthCodeRepository) FindByCode(code string) (*entity.AuthorizationCode, error) {
	var e entity.AuthorizationCode
	err := r.db.Preload("Scopes").Where(&entity.AuthorizationCode{Value: code}).First(&e).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, oauth.ErrAuthorizationCodeNotFound
	}
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
