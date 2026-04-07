package repository

import (
	"context"
	"oauth-server-go/internal/oauth/authorization"
	"oauth-server-go/internal/oauth/client"
	"oauth-server-go/internal/oauth/scope"
	"oauth-server-go/internal/oauth/token"
)

type cacheKey string

// TokenRepository 엑세스 토큰 저장소
type TokenRepository interface {
	// FindAccessTokenByValue 저장소에서 엑세스 토큰을 조회한다.
	//
	// Returns:
	//	 - *token.AccessToken: 조회된 엑세스 토큰
	//	 - bool: 조회 성공 여부
	FindAccessTokenByValue(ctx context.Context, token string) (*token.AccessToken, bool)

	// FindRefreshTokenByValue 저장소에서 리플레시 토큰을 조회한다.
	//
	// Returns:
	//	 - *token.RefreshToken: 조회된 리플레시 토큰
	//	 - bool: 조회 성공 여부
	FindRefreshTokenByValue(ctx context.Context, token string) (*token.RefreshToken, bool)

	// FindAccessTokenByUsername 인자로 받은 유저 아이디로 발급된 엑세스 토큰을 조회한다.
	//
	// Returns:
	//		- []*token.AccessToken: 유저 아이디로 발급된 엑세스 토큰 리스트
	FindAccessTokenByUsername(ctx context.Context, username string) []token.AccessToken

	// SaveAccessToken 저장소에 엑세스 토큰을 저장한다.
	SaveAccessToken(ctx context.Context, accessToken *token.AccessToken) error

	// SaveRefreshToken 저장소에 리플레시 토큰을 저장한다.
	SaveRefreshToken(ctx context.Context, refreshToken *token.RefreshToken) error

	// DeleteAccessToken 저장소에서 엑세스 토큰을 삭제한다.
	DeleteAccessToken(ctx context.Context, accessToken *token.AccessToken) error

	// DeleteRefreshToken 저장소에서 리플레시 토큰을 삭제한다.
	DeleteRefreshToken(ctx context.Context, refreshToken *token.RefreshToken) error

	// Transaction 트랜잭션을 수행한다.
	// 트랜잭션을 생성하고 인자로 받은 함수를 실행시킨다.
	// 함수가 모두 에러 없이 성공한 경우 커밋을 하며 하나라도 실패한 경우 롤백을 한다.
	Transaction(ctx context.Context, fn func(TokenRepository) error) error
}

// AuthCodeRepository 인가 코드 저장소
type AuthCodeRepository interface {

	// FindByValue 저장소에서 인가 코드를 조회한다.
	//
	// Returns:
	//	 - *authorization.Code: 조회된 인가 코드
	//	 - bool: 조회 성공 여부
	FindByValue(context.Context, string) (*authorization.Code, bool)

	// Save 인가 코드를 저장소에 저장한다.
	Save(context.Context, *authorization.Code) error

	// Delete 인가 코드를 저장소에서 삭제 한다.
	Delete(context.Context, *authorization.Code) error
}

// ScopeRepository 스코프 저장소
type ScopeRepository interface {

	// FindByValue 저장소에서 스코프들을 조회한다.
	FindByValue(ctx context.Context, value ...string) []scope.Scope
}

// ClientRepository 클라이언트 저장소
type ClientRepository interface {

	// FindByClientID 저장소에서 클라이언트를 조회 한다.
	//
	// Returns:
	//	 - *client.Client: 조회된 클라이언트
	//	 - bool: 조회 성공 여부
	FindByClientID(ctx context.Context, clientID string) (*client.Client, bool)
}
