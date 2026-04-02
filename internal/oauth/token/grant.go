package token

import (
	"fmt"
	"oauth-server-go/internal/oauth/authorization"
	"oauth-server-go/internal/oauth/client"
	oautherr "oauth-server-go/internal/oauth/errors"
	"oauth-server-go/internal/oauth/scope"
	"oauth-server-go/pkg/array"
)

// RetrieveAuthorizationCode 인가 코드를 조회하여 반환한다.
//
// Returns:
//   - *authorization.Code: 조회된 인가 코드
//   - bool: 조회 성공 여부
type RetrieveAuthorizationCode func(code string) (*authorization.Code, bool)

// AuthorizationCodeGrant OAuth2 인가 코드 승인 방식
type AuthorizationCodeGrant struct {
	// accessTokenGenerator 텍스트 형태의 랜덤 문자열로 토큰을 생성하는 함수
	// 엑세스 토큰의 실제 토큰값을 생성하는데 사용한다.
	accessTokenGenerator GenerateToken

	// refreshTokenGenerator 텍스트 형태의 랜덤 문자열 토큰을 생성하는 함수
	// 리플레시 토큰의 실제 토큰값을 생성하는데 사용한다.
	refreshTokenGenerator GenerateToken

	// retrieveAuthorizationCode 인가 코드를 조회 하는 함수
	retrieveAuthorizationCode RetrieveAuthorizationCode
}

// NewAuthorizationCodeGrant 새로운 인가 코드 승인 방식 인스턴스를 생성한다.
func NewAuthorizationCodeGrant(tokenGenerator GenerateToken, refreshTokenGenerator GenerateToken, codeRetriever RetrieveAuthorizationCode) *AuthorizationCodeGrant {
	return &AuthorizationCodeGrant{
		accessTokenGenerator:      tokenGenerator,
		refreshTokenGenerator:     refreshTokenGenerator,
		retrieveAuthorizationCode: codeRetriever,
	}
}

// GenerateToken 인가 코드를 검증하고 엑세스 토큰과 리플레시 토큰을 발급한다.
func (srv *AuthorizationCodeGrant) GenerateToken(c *client.Client, request *Request) (*AccessToken, *RefreshToken, error) {
	if request.Code == "" {
		return nil, nil, fmt.Errorf("%w: code", oautherr.ErrMissingParameter)
	}

	authCode, ok := srv.retrieveAuthorizationCode(request.Code)
	if !ok {
		return nil, nil, fmt.Errorf("%w: authoriation code is not found", oautherr.ErrInvalidRequest)
	}

	if !authCode.Available() {
		return nil, nil, fmt.Errorf("%w: authroization code is expired", oautherr.ErrExpiredResource)
	}

	if authCode.Client().Id() != c.Id() {
		return nil, nil, oautherr.ErrInvalidClient
	}

	if authCode.Redirect() != request.Redirect {
		return nil, nil, fmt.Errorf("%w: invalid redirect_uri", oautherr.ErrInvalidRequest)
	}

	if verify, err := authCode.Verify(request.CodeVerifier); !verify || err != nil {
		return nil, nil, fmt.Errorf("%w: mismatch code_verifier", oautherr.ErrInvalidRequest)
	}

	token := New(c, srv.accessTokenGenerator)
	token.ApplyAuthorizationCode(authCode)

	if c.T() == client.TypeConfidential {
		return token, NewRefreshToken(token, srv.refreshTokenGenerator), nil
	} else {
		return token, nil, nil
	}
}

// ImplicitGrant OAuth2 암묵적 승인 방식 구현체
type ImplicitGrant struct {
	// accessTokenGenerator 텍스트 형태의 랜덤 문자열로 토큰을 생성하는 함수
	// 엑세스 토큰의 실제 토큰값을 생성하는데 사용한다.
	accessTokenGenerator GenerateToken
}

func NewImplicitGrant(tokenGenerator GenerateToken) *ImplicitGrant {
	return &ImplicitGrant{
		accessTokenGenerator: tokenGenerator,
	}
}

// GenerateToken 새 엑세스 토큰을 생성하며 리플레시 토큰은 항상 nil을 반환한다.
func (srv *ImplicitGrant) GenerateToken(c *client.Client, request *Request) (*AccessToken, error) {
	scopes := scope.Split(request.Scope)
	if !array.ContainsAll(c.Scopes(), scopes) {
		return nil, oautherr.ErrInvalidScope
	}

	if _, err := c.ValidateRedirectURI(request.Redirect); err != nil {
		return nil, fmt.Errorf("%w: invalid redirect_uri", oautherr.ErrInvalidRequest)
	}

	token := New(c, srv.accessTokenGenerator)
	token.ApplyResourceOwnerInfo(request.Username, scopes)

	return token, nil
}

// AuthenticateResourceOwner 자원 소유자 인증 함수
// 자원 소유자의 식별자(아이디)와 패스워드를 받아 인증을 수행하고 인증 완료시 true를 반환한다.
type AuthenticateResourceOwner func(username, password string) (bool, error)

// ResourceOwnerPasswordCredentialsGrant 자원 소유자 비밀번호 자격 증명 승인 방식
type ResourceOwnerPasswordCredentialsGrant struct {
	// authentication 자원 소유자의 인증을 수행하는 함수
	authentication AuthenticateResourceOwner

	// accessTokenGenerator 텍스트 형태의 랜덤 문자열로 토큰을 생성하는 함수
	// 엑세스 토큰의 실제 토큰값을 생성하는데 사용한다.
	accessTokenGenerator GenerateToken

	// refreshTokenGenerator 텍스트 형태의 랜덤 문자열 토큰을 생성하는 함수
	// 리플레시 토큰의 실제 토큰값을 생성하는데 사용한다.
	refreshTokenGenerator GenerateToken
}

// GenerateToken 자원 소유자의 식별자(아이디)와 패스워드를 가지고 인증을 진행하고 인증 성공시 새로운 엑세스 토큰을 발급한다.
func (srv *ResourceOwnerPasswordCredentialsGrant) GenerateToken(c *client.Client, request *Request) (*AccessToken, *RefreshToken, error) {
	if request.Username == "" || request.Password == "" {
		return nil, nil, fmt.Errorf("%w: username or password is required", oautherr.ErrMissingParameter)
	}

	// 자원 소유자 인증 진행
	if auth, err := srv.authentication(request.Username, request.Password); err != nil || !auth {
		msg := "resource owner failed authentication"
		if err != nil {
			msg = fmt.Sprintf("%s (%v)", msg, err)
		}
		return nil, nil, fmt.Errorf("%w: %s", oautherr.ErrUnauthorized, msg)
	}

	scopes := scope.Split(request.Scope)
	if !array.ContainsAll(c.Scopes(), scopes) {
		return nil, nil, oautherr.ErrInvalidScope
	}

	token := New(c, srv.accessTokenGenerator)
	token.ApplyResourceOwnerInfo(request.Username, scopes)

	if c.T() == client.TypeConfidential {
		return token, NewRefreshToken(token, srv.refreshTokenGenerator), nil
	} else {
		return token, nil, nil
	}
}

// ClientCredentialsGrant 클라이언트 자격 증명 방식
type ClientCredentialsGrant struct {
	// accessTokenGenerator 텍스트 형태의 랜덤 문자열로 토큰을 생성하는 함수
	// 엑세스 토큰의 실제 토큰값을 생성하는데 사용한다.
	accessTokenGenerator GenerateToken
}

// GenerateToken 클라이언트 자격 증명을 이용하여 새 엑세스 토큰을 발급한다.
func (srv *ClientCredentialsGrant) GenerateToken(c *client.Client, request *Request) (*AccessToken, error) {
	// 비공개 클라이언트만 자격증명을 이용한 토큰 발급 가능
	if c.T() != client.TypeConfidential {
		return nil, fmt.Errorf("%w: public client", oautherr.ErrInvalidClient)
	}

	scopes := scope.Split(request.Scope)
	if !array.ContainsAll(c.Scopes(), scopes) {
		return nil, oautherr.ErrInvalidScope
	}

	token := New(c, srv.accessTokenGenerator)
	// 자원 소유자가 없음으로 공백("")을 저장한다.
	token.ApplyResourceOwnerInfo("", scopes)

	return token, nil
}

// RetrieveRefreshToken 리플레시 토큰을 조회하는 함수
//
// Returns:
//   - *RefreshToken: 조회된 리플래시 토큰
//   - bool: 조회 성공 여부
type RetrieveRefreshToken func(refreshToken string) (*RefreshToken, bool)

// RefreshTokenGrant 리플레시 토큰 승인 방식
type RefreshTokenGrant struct {
	// accessTokenGenerator 텍스트 형태의 랜덤 문자열로 토큰을 생성하는 함수
	// 엑세스 토큰의 실제 토큰값을 생성하는데 사용한다.
	accessTokenGenerator GenerateToken

	// refreshTokenGenerator 텍스트 형태의 랜덤 문자열 토큰을 생성하는 함수
	// 리플레시 토큰의 실제 토큰값을 생성하는데 사용한다.
	refreshTokenGenerator GenerateToken

	// retrieveRefreshToken 리플레시 토큰을 조회하는 함수
	retrieveRefreshToken RetrieveRefreshToken

	// rotation 신규 토큰 발행 후 기존의 리플래시 토큰을 재사용할지 여부
	rotation bool
}

func NewRefreshTokenGrant(tokenGenerator GenerateToken, refreshTokenGenerator GenerateToken, refreshTokenRetriever RetrieveRefreshToken) *RefreshTokenGrant {
	return &RefreshTokenGrant{
		accessTokenGenerator:  tokenGenerator,
		refreshTokenGenerator: refreshTokenGenerator,
		retrieveRefreshToken:  refreshTokenRetriever,
		rotation:              true,
	}
}

func NewRefreshTokenGrantWithoutRotation(tokenGenerator GenerateToken, refreshTokenRetriever RetrieveRefreshToken) *RefreshTokenGrant {
	return &RefreshTokenGrant{
		accessTokenGenerator:  tokenGenerator,
		refreshTokenGenerator: nil,
		retrieveRefreshToken:  refreshTokenRetriever,
		rotation:              false,
	}
}

// GenerateToken 리플레시 토큰을 이용하여 새 엑세스 토큰과 리플레시 토큰을 생성한다.
func (srv *RefreshTokenGrant) GenerateToken(c *client.Client, request *Request) (*AccessToken, *RefreshToken, error) {
	if request.RefreshToken == "" {
		return nil, nil, fmt.Errorf("%w: refresh_token is required", oautherr.ErrMissingParameter)
	}

	storedRefreshToken, ok := srv.retrieveRefreshToken(request.RefreshToken)
	if !ok {
		return nil, nil, fmt.Errorf("%w: token(%s) could not find", oautherr.ErrInvalidRequest, request.RefreshToken)
	}

	expiredToken := storedRefreshToken.Token()
	if expiredToken.Client().Id() != c.Id() {
		return nil, nil, oautherr.ErrInvalidClient
	}

	if !storedRefreshToken.Available() {
		return nil, nil, fmt.Errorf("%w: refresh token is expired", oautherr.ErrExpiredResource)
	}

	// 따로 요청된 스코프가 없을 경우 기존 토큰의 스코프를 그대로 사용
	scopes := scope.Split(request.Scope)
	if len(scopes) == 0 {
		scopes = expiredToken.Scopes()
	}

	// 부여하려는 스코프 중 기존 토큰에 없는 스코프가 있을 경우 에러
	if !array.ContainsAll(expiredToken.Scopes(), scopes) {
		return nil, nil, oautherr.ErrInvalidScope
	}

	token := New(c, srv.accessTokenGenerator)
	token.ApplyResourceOwnerInfo(expiredToken.Username(), scopes)

	var refreshToken *RefreshToken
	if srv.refreshTokenGenerator != nil && srv.rotation {
		refreshToken = NewRefreshToken(token, srv.refreshTokenGenerator)
	} else {
		storedRefreshToken.token = token
		refreshToken = storedRefreshToken
	}
	return token, refreshToken, nil
}
