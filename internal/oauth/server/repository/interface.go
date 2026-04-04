package repository

import (
	"oauth-server-go/internal/oauth/authorization"
	"oauth-server-go/internal/oauth/client"
	"oauth-server-go/internal/oauth/scope"
	"oauth-server-go/internal/oauth/token"
)

// TokenRepository 엑세스 토큰 저장소
type TokenRepository interface {
	// FindAccessTokenByValue 저장소에서 엑세스 토큰을 조회한다.
	//
	// Returns:
	//	 - *token.AccessToken: 조회된 엑세스 토큰
	//	 - bool: 조회 성공 여부
	FindAccessTokenByValue(token string) (*token.AccessToken, bool)

	// FindRefreshTokenByValue 저장소에서 리플레시 토큰을 조회한다.
	//
	// Returns:
	//	 - *token.RefreshToken: 조회된 리플레시 토큰
	//	 - bool: 조회 성공 여부
	FindRefreshTokenByValue(token string) (*token.RefreshToken, bool)

	// SaveAccessToken 저장소에 엑세스 토큰을 저장한다.
	SaveAccessToken(accessToken *token.AccessToken) error

	// SaveRefreshToken 저장소에 리플레시 토큰을 저장한다.
	SaveRefreshToken(refreshToken *token.RefreshToken) error

	// DeleteAccessToken 저장소에서 엑세스 토큰을 삭제한다.
	DeleteAccessToken(accessToken *token.AccessToken) error

	// DeleteRefreshToken 저장소에서 리플레시 토큰을 삭제한다.
	DeleteRefreshToken(refreshToken *token.RefreshToken) error

	// Transaction 트랜잭션을 수행한다.
	// 트랜잭션을 생성하고 인자로 받은 함수를 실행시킨다.
	// 함수가 모두 에러 없이 성공한 경우 커밋을 하며 하나라도 실패한 경우 롤백을 한다.
	Transaction(fn func(TokenRepository) error) error
}

// AuthCodeRepository 인가 코드 저장소
type AuthCodeRepository interface {

	// FindByValue 저장소에서 인가 코드를 조회한다.
	//
	// Returns:
	//	 - *authorization.Code: 조회된 인가 코드
	//	 - bool: 조회 성공 여부
	FindByValue(cd string) (*authorization.Code, bool)

	// Save 인가 코드를 저장소에 저장한다.
	Save(*authorization.Code) error

	// Delete 인가 코드를 저장소에서 삭제 한다.
	Delete(*authorization.Code) error
}

// ScopeRepository 스코프 저장소
type ScopeRepository interface {

	// FindByValue 저장소에서 스코프들을 조회한다.
	FindByValue(value ...string) []scope.Scope
}

// ClientRepository 클라이언트 저장소
type ClientRepository interface {

	// FindByClientID 저장소에서 클라이언트를 조회 한다.
	//
	// Returns:
	//	 - *client.Client: 조회된 클라이언트
	//	 - bool: 조회 성공 여부
	FindByClientID(clientID string) (*client.Client, bool)
}
