package repository

import (
	"errors"
	"fmt"
	"gorm.io/gorm"
	"oauth-server-go/internal/config/log"
	oautherr "oauth-server-go/internal/oauth/errors"
	"oauth-server-go/internal/oauth/token"
	"oauth-server-go/pkg/array"
	"slices"
)

// FindAccessTokenByValue Gorm을 이용해 데이터베이스에서 엑세스 토큰을 조회한다.
//
// Returns:
//   - *AccessToken: 조회된 엑세스 토큰 모델
//   - bool: 조회 성공 여부
func FindAccessTokenByValue(db *gorm.DB, value string) (*AccessToken, bool) {
	var accessToken AccessToken
	if err := db.Preload("Scopes").Joins("Client").Where(&AccessToken{Value: value}).First(&accessToken).Error; err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			log.Sugared().Errorf("error occurred during select access token(%s): %v", value, err)
		}
		return nil, false
	}
	return &accessToken, true
}

// FindAccessTokenByUsername Gorm을 이용해 데이터베이스에서 인자로 받은 사용자 아이디로 발급된 엑세스 토큰을 모두 조회한다.
func FindAccessTokenByUsername(db *gorm.DB, username string) []AccessToken {
	var accessTokens []AccessToken
	if err := db.Preload("Scopes").Joins("Client").Where(&AccessToken{Username: username}).Find(&accessTokens).Error; err != nil {
		log.Sugared().Errorf("error occurred during select access token(%s): %v", username, err)
	}
	return accessTokens
}

// FindRefreshTokenByValue Gorm을 이용해 데이터베이스에서 리플레시 토큰을 조회한다.
//
// Returns:
//   - *RefreshToken: 조회된 리플레시 토큰 모델
//   - bool: 조회 성공 여부
func FindRefreshTokenByValue(db *gorm.DB, value string) (*RefreshToken, bool) {
	var refreshToken RefreshToken
	if err := db.Joins("Token").Joins("Token.Client").Preload("Token.Scopes").Where(&RefreshToken{Value: value}).First(&refreshToken).Error; err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			log.Sugared().Errorf("error occurred during select refresh token(%s): %v", value, err)
		}
		return nil, false
	}
	return &refreshToken, true
}

// SaveAccessToken Gorm을 이용하여 데이터베이스에 엑세스 토큰을 저장한다.
func SaveAccessToken(db *gorm.DB, accessToken *AccessToken) error {
	return db.Omit("Scopes.*").Create(accessToken).Error
}

// SaveRefreshToken Gorm을 이용해 데이터베이스에 리플레시 토큰을 저장한다.
func SaveRefreshToken(db *gorm.DB, refreshToken *RefreshToken) error {
	return db.Omit("Token").Create(refreshToken).Error
}

// DeleteByAccessToken Gorm을 이용해 데이터베이스에서 엑세스 토큰을 삭제한다.
func DeleteByAccessToken(db *gorm.DB, accessToken *AccessToken) error {
	if err := db.Model(accessToken).Association("Scopes").Clear(); err != nil {
		return err
	}
	return db.Delete(accessToken).Error
}

// DeleteByRefreshToken Gorm을 이용해 데이터베이스에서 리플래시 토큰을 삭제한다.
func DeleteByRefreshToken(db *gorm.DB, refreshToken *RefreshToken) error {
	return db.Delete(refreshToken).Error
}

// TokenGormBridge Gorm을 이용하여 엑세스 토큰 및 리플래시 토큰 도메인을 데이터베이스에 CRUD 할 수 있도록 변환 및 연결 작업을 하는 객체
type TokenGormBridge struct {
	db *gorm.DB
}

func NewTokenGormBridge(db *gorm.DB) *TokenGormBridge {
	return &TokenGormBridge{db: db}
}

// FindAccessTokenByValue Gorm을 이용해 엑세스 토큰을 조회하고 도메인 모델로 변환하여 반환한다.
//
// Returns:
//   - *token.AccessToken: 조회된 엑세스 토큰
//   - bool: 조회 성공 여부
func (b *TokenGormBridge) FindAccessTokenByValue(value string) (*token.AccessToken, bool) {
	if accessTokenModel, ok := FindAccessTokenByValue(b.db, value); ok {
		return accessTokenModel.Domain(), true
	} else {
		return nil, false
	}
}

// FindAccessTokenByUsername Gorm을 이용해 인자로 주어진 사용자 아이디로 발급된 엑세스 토큰을 조회하고 도메인 모델로 변환하여 반환한다.
func (b *TokenGormBridge) FindAccessTokenByUsername(username string) []token.AccessToken {
	tokens := FindAccessTokenByUsername(b.db, username)
	return array.Map(tokens, func(e AccessToken) token.AccessToken {
		return *e.Domain()
	})
}

// FindRefreshTokenByValue Gorm을 이용해 리플레시 토큰을 조회하고 도메인 모델로 변환하여 반환한다.
//
// Returns:
//   - *token.RefreshToken: 조회된 리플레시 토큰
//   - bool: 조회 성공 여부
func (b *TokenGormBridge) FindRefreshTokenByValue(value string) (*token.RefreshToken, bool) {
	if refreshTokenModel, ok := FindRefreshTokenByValue(b.db, value); ok {
		return refreshTokenModel.Domain(), true
	} else {
		return nil, false
	}
}

// SaveAccessToken Gorm을 이용해 엑세스 토큰을 저장한다.
func (b *TokenGormBridge) SaveAccessToken(accessToken *token.AccessToken) error {
	clientModel, ok := FindClientByClientID(b.db, accessToken.Client().Id())
	if !ok {
		return fmt.Errorf("%w: client(%s) not found", oautherr.ErrInvalidClient, accessToken.Client().Id())
	}

	scopes := array.FilterFunc(clientModel.Scopes, func(s Scope) bool {
		return slices.Contains(accessToken.Scopes(), s.Code)
	})

	tokenModel := &AccessToken{
		Value:     accessToken.Value(),
		ClientID:  clientModel.ID,
		Username:  accessToken.Username(),
		Scopes:    scopes,
		IssuedAt:  accessToken.Start(),
		ExpiredAt: accessToken.End(),
	}

	return SaveAccessToken(b.db, tokenModel)
}

// SaveRefreshToken Gorm을 이용해 리플레시 토큰을 저장한다.
func (b *TokenGormBridge) SaveRefreshToken(refreshToken *token.RefreshToken) error {
	tokenModel, ok := FindAccessTokenByValue(b.db, refreshToken.Token().Value())
	if !ok {
		return fmt.Errorf("%w: token(%s) not found", oautherr.ErrUnknown, refreshToken.Token().Value())
	}

	refreshTokenModel := &RefreshToken{
		Value:         refreshToken.Value(),
		AccessTokenID: tokenModel.ID,
		IssuedAt:      refreshToken.Start(),
		ExpiredAt:     refreshToken.End(),
	}
	return SaveRefreshToken(b.db, refreshTokenModel)
}

// DeleteAccessToken Gorm을 이용해 엑세스 토큰을 삭제한다.
func (b *TokenGormBridge) DeleteAccessToken(accessToken *token.AccessToken) error {
	tokenModel, ok := FindAccessTokenByValue(b.db, accessToken.Value())
	if !ok {
		return fmt.Errorf("%w: token(%s) not found", oautherr.ErrUnknown, accessToken.Value())
	}
	return DeleteByAccessToken(b.db, tokenModel)
}

// DeleteRefreshToken Gorm을 이용해 리플레시 토큰을 삭제한다.
func (b *TokenGormBridge) DeleteRefreshToken(refreshToken *token.RefreshToken) error {
	tokenModel, ok := FindRefreshTokenByValue(b.db, refreshToken.Value())
	if !ok {
		return fmt.Errorf("%w: token(%s) not found", oautherr.ErrUnknown, refreshToken.Value())
	}
	return DeleteByRefreshToken(b.db, tokenModel)
}

func (b *TokenGormBridge) Transaction(fn func(TokenRepository) error) error {
	return b.db.Transaction(func(tx *gorm.DB) error {
		return fn(NewTokenGormBridge(tx))
	})
}
