package repository

import (
	"context"
	"errors"
	"fmt"
	"gorm.io/gorm"
	"oauth-server-go/internal/config/log"
	oautherr "oauth-server-go/internal/oauth/errors"
	"oauth-server-go/internal/oauth/token"
	"oauth-server-go/pkg/array"
	"slices"
)

const accessTokenCacheName cacheKey = "oauth/server/repository/token_gorm/access_token"

// accessTokenCache 엑세스 토큰 및 리플래시 토큰 캐싱 저장소
type accessTokenCache struct {
	accessToken  map[string]*AccessToken
	refreshToken map[string]*RefreshToken
}

// WithAccessTokenCaching 엑세스 토큰을 캐싱할 수 있는 컨텍스트를 생성하여 반환한다.
func WithAccessTokenCaching(ctx context.Context) context.Context {
	if _, ok := ctx.Value(accessTokenCacheName).(*accessTokenCache); ok {
		return ctx
	}

	cache := accessTokenCache{
		accessToken:  make(map[string]*AccessToken),
		refreshToken: make(map[string]*RefreshToken),
	}

	return context.WithValue(ctx, accessTokenCacheName, &cache)
}

// FindAccessTokenByValue Gorm을 이용해 데이터베이스에서 엑세스 토큰을 조회한다.
//
// Returns:
//   - *AccessToken: 조회된 엑세스 토큰 모델
//   - bool: 조회 성공 여부
func FindAccessTokenByValue(ctx context.Context, db *gorm.DB, value string) (*AccessToken, bool) {
	cache, caching := ctx.Value(accessTokenCacheName).(*accessTokenCache)
	if caching {
		if accessToken, ok := cache.accessToken[value]; ok {
			return accessToken, true
		}
	}
	var accessToken AccessToken
	if err := db.WithContext(ctx).Preload("Scopes").Joins("Client").Where(&AccessToken{Value: value}).First(&accessToken).Error; err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			log.Sugared().Errorf("error occurred during select access token(%s): %v", value, err)
		}
		return nil, false
	}
	if caching {
		cache.accessToken[value] = &accessToken
	}
	return &accessToken, true
}

// FindAccessTokenByUsername Gorm을 이용해 데이터베이스에서 인자로 받은 사용자 아이디로 발급된 엑세스 토큰을 모두 조회한다.
func FindAccessTokenByUsername(ctx context.Context, db *gorm.DB, username string) []AccessToken {
	var accessTokens []AccessToken
	if err := db.WithContext(ctx).Preload("Scopes").Joins("Client").Where(&AccessToken{Username: username}).Find(&accessTokens).Error; err != nil {
		log.Sugared().Errorf("error occurred during select access token(%s): %v", username, err)
	}
	if cache, caching := ctx.Value(accessTokenCacheName).(*accessTokenCache); caching {
		for _, accessToken := range accessTokens {
			cache.accessToken[accessToken.Value] = &accessToken
		}
	}
	return accessTokens
}

// FindRefreshTokenByValue Gorm을 이용해 데이터베이스에서 리플레시 토큰을 조회한다.
//
// Returns:
//   - *RefreshToken: 조회된 리플레시 토큰 모델
//   - bool: 조회 성공 여부
func FindRefreshTokenByValue(ctx context.Context, db *gorm.DB, value string) (*RefreshToken, bool) {
	cache, caching := ctx.Value(accessTokenCacheName).(*accessTokenCache)
	if caching {
		if refreshToken, ok := cache.refreshToken[value]; ok {
			return refreshToken, true
		}
	}
	var refreshToken RefreshToken
	if err := db.WithContext(ctx).Joins("AccessToken").Joins("AccessToken.Client").Preload("AccessToken.Scopes").Where(&RefreshToken{Value: value}).First(&refreshToken).Error; err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			log.Sugared().Errorf("error occurred during select refresh token(%s): %v", value, err)
		}
		return nil, false
	}
	if caching {
		cache.refreshToken[value] = &refreshToken
	}
	return &refreshToken, true
}

// SaveAccessToken Gorm을 이용하여 데이터베이스에 엑세스 토큰을 저장한다.
func SaveAccessToken(ctx context.Context, db *gorm.DB, accessToken *AccessToken) error {
	err := db.WithContext(ctx).Omit("Scopes.*").Create(accessToken).Error
	if cache, caching := ctx.Value(accessTokenCacheName).(*accessTokenCache); err != nil && caching {
		cache.accessToken[accessToken.Value] = accessToken
	}
	return err
}

// SaveRefreshToken Gorm을 이용해 데이터베이스에 리플레시 토큰을 저장한다.
func SaveRefreshToken(ctx context.Context, db *gorm.DB, refreshToken *RefreshToken) error {
	err := db.WithContext(ctx).Omit("Token").Create(refreshToken).Error
	if cache, caching := ctx.Value(accessTokenCacheName).(*accessTokenCache); err != nil && caching {
		cache.refreshToken[refreshToken.Value] = refreshToken
	}
	return err
}

// DeleteByAccessToken Gorm을 이용해 데이터베이스에서 엑세스 토큰을 삭제한다.
func DeleteByAccessToken(ctx context.Context, db *gorm.DB, accessToken *AccessToken) error {
	if err := db.WithContext(ctx).Model(accessToken).Association("Scopes").Clear(); err != nil {
		return err
	}
	err := db.Delete(accessToken).Error
	if cache, caching := ctx.Value(accessTokenCacheName).(*accessTokenCache); err != nil && caching {
		delete(cache.accessToken, accessToken.Value)
	}
	return err
}

// DeleteByRefreshToken Gorm을 이용해 데이터베이스에서 리플래시 토큰을 삭제한다.
func DeleteByRefreshToken(ctx context.Context, db *gorm.DB, refreshToken *RefreshToken) error {
	err := db.WithContext(ctx).Delete(refreshToken).Error
	if cache, caching := ctx.Value(accessTokenCacheName).(*accessTokenCache); err != nil && caching {
		delete(cache.refreshToken, refreshToken.Value)
	}
	return err
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
func (b *TokenGormBridge) FindAccessTokenByValue(ctx context.Context, value string) (*token.AccessToken, bool) {
	if accessTokenModel, ok := FindAccessTokenByValue(ctx, b.db, value); ok {
		return accessTokenModel.Domain(), true
	} else {
		return nil, false
	}
}

// FindAccessTokenByUsername Gorm을 이용해 인자로 주어진 사용자 아이디로 발급된 엑세스 토큰을 조회하고 도메인 모델로 변환하여 반환한다.
func (b *TokenGormBridge) FindAccessTokenByUsername(ctx context.Context, username string) []token.AccessToken {
	tokens := FindAccessTokenByUsername(ctx, b.db, username)
	return array.Map(tokens, func(e AccessToken) token.AccessToken {
		return *e.Domain()
	})
}

// FindRefreshTokenByValue Gorm을 이용해 리플레시 토큰을 조회하고 도메인 모델로 변환하여 반환한다.
//
// Returns:
//   - *token.RefreshToken: 조회된 리플레시 토큰
//   - bool: 조회 성공 여부
func (b *TokenGormBridge) FindRefreshTokenByValue(ctx context.Context, value string) (*token.RefreshToken, bool) {
	if refreshTokenModel, ok := FindRefreshTokenByValue(ctx, b.db, value); ok {
		return refreshTokenModel.Domain(), true
	} else {
		return nil, false
	}
}

// SaveAccessToken Gorm을 이용해 엑세스 토큰을 저장한다.
func (b *TokenGormBridge) SaveAccessToken(ctx context.Context, accessToken *token.AccessToken) error {
	clientModel, ok := FindClientByClientID(ctx, b.db, accessToken.Client().Id())
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

	return SaveAccessToken(ctx, b.db, tokenModel)
}

// SaveRefreshToken Gorm을 이용해 리플레시 토큰을 저장한다.
func (b *TokenGormBridge) SaveRefreshToken(ctx context.Context, refreshToken *token.RefreshToken) error {
	tokenModel, ok := FindAccessTokenByValue(ctx, b.db, refreshToken.Token().Value())
	if !ok {
		return fmt.Errorf("%w: token(%s) not found", oautherr.ErrUnknown, refreshToken.Token().Value())
	}

	refreshTokenModel := &RefreshToken{
		Value:         refreshToken.Value(),
		AccessTokenID: tokenModel.ID,
		IssuedAt:      refreshToken.Start(),
		ExpiredAt:     refreshToken.End(),
	}
	return SaveRefreshToken(ctx, b.db, refreshTokenModel)
}

// DeleteAccessToken Gorm을 이용해 엑세스 토큰을 삭제한다.
func (b *TokenGormBridge) DeleteAccessToken(ctx context.Context, accessToken *token.AccessToken) error {
	tokenModel, ok := FindAccessTokenByValue(ctx, b.db, accessToken.Value())
	if !ok {
		return fmt.Errorf("%w: token(%s) not found", oautherr.ErrUnknown, accessToken.Value())
	}
	return DeleteByAccessToken(ctx, b.db, tokenModel)
}

// DeleteRefreshToken Gorm을 이용해 리플레시 토큰을 삭제한다.
func (b *TokenGormBridge) DeleteRefreshToken(ctx context.Context, refreshToken *token.RefreshToken) error {
	tokenModel, ok := FindRefreshTokenByValue(ctx, b.db, refreshToken.Value())
	if !ok {
		return fmt.Errorf("%w: token(%s) not found", oautherr.ErrUnknown, refreshToken.Value())
	}
	return DeleteByRefreshToken(ctx, b.db, tokenModel)
}

func (b *TokenGormBridge) Transaction(ctx context.Context, fn func(TokenRepository) error) error {
	return b.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return fn(NewTokenGormBridge(tx))
	})
}
