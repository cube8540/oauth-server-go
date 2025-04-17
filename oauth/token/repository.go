package token

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

func (r Repository) Save(t *Token, fn func(t *Token) *RefreshToken) error {
	return r.db.Transaction(func(db *gorm.DB) error {
		if err := db.Omit("Scopes.*").Create(t).Error; err != nil {
			return err
		}
		if refresh := fn(t); refresh != nil {
			if err := db.Omit("Token").Create(refresh).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

func (r *Repository) FindAccessTokenByValue(v string) (*Token, error) {
	var t Token
	if err := r.db.Preload("Scopes").Joins("Client").Where(&Token{Value: v}).First(&t).Error; err != nil {
		switch {
		case errors.Is(err, gorm.ErrRecordNotFound):
			return nil, fmt.Errorf("%w: access token(%s)", ErrAccessTokenNotFound, v)
		default:
			return nil, fmt.Errorf("error occurred during select access token(%s): %w", v, err)
		}
	}
	return &t, nil
}

func (r *Repository) FindRefreshTokenByValue(v string) (*RefreshToken, error) {
	var t RefreshToken
	if err := r.db.Joins("Token").Joins("Token.Client").Preload("Token.Scopes").Where(&RefreshToken{Value: v}).First(&t).Error; err != nil {
		switch {
		case errors.Is(err, gorm.ErrRecordNotFound):
			return nil, fmt.Errorf("%w: refresh token(%s)", ErrRefreshTokenNotFound, v)
		default:
			return nil, fmt.Errorf("error occurred during select refresh token(%s): %w", v, err)
		}
	}
	return &t, nil
}

func (r *Repository) Refresh(oldRefreshToken *RefreshToken, newToken *Token, fn func(t *Token) *RefreshToken) error {
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

func (r *Repository) FindAccessTokenByUsername(u string) ([]Token, error) {
	var tokens []Token
	if err := r.db.Preload("Scopes").Joins("Client").Where(&Token{Username: u}).Find(&tokens).Error; err != nil {
		return nil, err
	}
	return tokens, nil
}

func (r *Repository) FindRefreshTokenByTokenID(id uint) (*RefreshToken, error) {
	var rt *RefreshToken
	if err := r.db.Where(&RefreshToken{TokenID: id}).First(&rt).Error; err != nil {
		switch {
		case errors.Is(err, gorm.ErrRecordNotFound):
			return nil, fmt.Errorf("%w: refresh token(%d)", ErrRefreshTokenNotFound, id)
		default:
			return nil, fmt.Errorf("error occrred during select refresh token(%d): %w", id, err)
		}
	}
	return rt, nil
}

func (r *Repository) Delete(t *Token, rt *RefreshToken) error {
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
