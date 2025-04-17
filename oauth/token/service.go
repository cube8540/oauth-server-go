package token

import (
	"errors"
	"fmt"
	"oauth-server-go/oauth/client"
	"oauth-server-go/oauth/code"
	"oauth-server-go/oauth/pkg"
	"oauth-server-go/security"
	"time"
)

// Store OAuth2 토큰 저장소
// 엑세스 토큰과 리프레시 토큰을 저장하고 조회하는 인터페이스
type Store interface {
	// Save 인자로 받은 엑세스 토큰을 저장하고 fn 함수를 통해 토큰을 재발행 할 수 있는 리플레시 토큰을 생성하여 저장한다.
	// 만약 fn이 nil을 반환 했을 경우 엑세스 토큰은 리플레시 토큰을 가지지 않는다.
	Save(t *Token, fn func(t *Token) *RefreshToken) error

	// FindAccessTokenByValue v와 일치하는 엑세스 토큰을 조회하여 반환한다.
	// 토큰이 존재하지 않을 경우 oauth.ErrTokenNotFound 오류를 반환한다.
	FindAccessTokenByValue(v string) (*Token, error)

	// FindRefreshTokenByValue v와 일치하는 리플레시 토큰을 조회하여 반환한다.
	// 토큰이 존재하지 않을 경우 oauth.ErrTokenNotFound 오류를 반환한다.
	FindRefreshTokenByValue(v string) (*RefreshToken, error)

	// Refresh 기존의 oldRefreshToken는 삭제 하고 신규 newToken을 저장한다 그 후 fn 함수를 통해 newToken을 재발행 할 수 있는 리플레시 토큰을 생성하여 저장한다.
	// 만약 fn이 nil을 반환 했을 경우 newToken은 리플레시 토큰을 가지지 않는다.
	Refresh(oldRefreshToken *RefreshToken, newToken *Token, fn func(t *Token) *RefreshToken) error
}

// AuthCodeConsume 인자로 인가코드를 받아 그 인가코드의 엔티티 반환하고 저장소에서 삭제한다.
type AuthCodeConsume func(code string) (*code.AuthorizationCode, error)

// AuthorizationCodeFlow OAuth2 인가 코드 흐름(Authorization Code Flow) 구현체 [RFC 6749 문단 4.1] 참조
//
// [RFC 6749 문단 4.1]: https://datatracker.ietf.org/doc/html/rfc6749#section-4.1
type AuthorizationCodeFlow struct {
	store   Store
	consume AuthCodeConsume

	IDGenerator IDGenerator
}

func NewAuthorizationCodeFlow(tr Store, consume AuthCodeConsume) *AuthorizationCodeFlow {
	return &AuthorizationCodeFlow{
		store:       tr,
		consume:     consume,
		IDGenerator: UUIDTokenIDGenerator,
	}
}

// Generate 인가 코드를 통해 액세스 토큰과 리프레시 토큰을 생성한다.
// PKCE(Proof Key for Code Exchange) 메커니즘을 지원한다. [RFC 7636] 참조
//
// [RFC 7636]: https://datatracker.ietf.org/doc/html/rfc7636
func (s *AuthorizationCodeFlow) Generate(c *client.Client, r *pkg.TokenRequest) (*Token, *RefreshToken, error) {
	if r.Code == "" {
		return nil, nil, fmt.Errorf("%w: authorization code is required", ErrInvalidRequest)
	}
	authCode, err := s.consume(r.Code)
	if err != nil {
		switch {
		case errors.Is(err, code.ErrNotFound):
			return nil, nil, fmt.Errorf("%w: authorization code is not found(%s)", ErrTokenCannotGrant, r.Code)
		default:
			return nil, nil, err
		}
	}
	if authCode.ClientID != c.ID {
		return nil, nil, fmt.Errorf("%w: authorization code client is different", ErrUnauthorized)
	}
	if !authCode.Available() {
		return nil, nil, fmt.Errorf("%w: authoriation code is expires", ErrTokenCannotGrant)
	}
	// PKCE 검증 (code_verifier와 code_challenge 검증)
	verifier, err := authCode.Verifier(r.CodeVerifier)
	if err != nil {
		return nil, nil, err
	}
	if !verifier {
		return nil, nil, fmt.Errorf("%w: verify is not matched", ErrInvalidRequest)
	}
	// 리다이렉트 URI 일치 여부 검증
	if to, _ := c.RedirectURL(authCode.Redirect); to != r.Redirect {
		return nil, nil, fmt.Errorf("%w: redirect uri is required", ErrInvalidRequest)
	}
	accessToken := NewTokenWithCode(s.IDGenerator, authCode)
	var refresh *RefreshToken
	// 액세스 토큰 저장 및 리프레시 토큰 생성 (기밀 클라이언트만 리프레시 토큰 발급)
	err = s.store.Save(accessToken, func(t *Token) *RefreshToken {
		if c.Type == pkg.ClientTypeConfidential {
			refresh = NewRefreshToken(t, s.IDGenerator)
		}
		return refresh
	})
	if err != nil {
		return nil, nil, err
	}
	return accessToken, refresh, nil
}

// ImplicitFlow OAuth2 암묵적 흐름(Implicit Flow) 구현체 [RFC 6749 문단 4.2] 참조
// 보안상 이유로 리프레시 토큰을 발급하지 않는다.
//
// [RFC 6749 문단 4.2]: https://datatracker.ietf.org/doc/html/rfc6749#section-4.2
type ImplicitFlow struct {
	store Store

	IDGenerator IDGenerator
}

// NewImplicitFlow 새로운 ImplicitFlow 인스턴스를 생성한다.
func NewImplicitFlow(r Store) *ImplicitFlow {
	return &ImplicitFlow{store: r}
}

// Generate 인가 요청을 통해 액세스 토큰을 생성한다.
// 암묵적 흐름은 리프레시 토큰을 발급하지 않는다.
func (f *ImplicitFlow) Generate(c *client.Client, r *pkg.AuthorizationRequest) (*Token, error) {
	// CSRF 방지를 위한 state 파라미터 필수 검증
	if r.State == "" {
		return nil, fmt.Errorf("%w: implicit flow is required state parameter", ErrInvalidRequest)
	}
	scopes, err := c.Scopes.GetAll(pkg.SplitScope(r.Scopes))
	if err != nil {
		return nil, err
	}
	accessToken := NewToken(f.IDGenerator, c)
	accessToken.Username = r.Username
	accessToken.Scopes = scopes
	err = f.store.Save(accessToken, func(_ *Token) *RefreshToken {
		// Implicit Flow는 리플레시 토큰을 생성하지 않는다.
		return nil
	})
	return accessToken, nil
}

// ResourceOwnerAuthentication 리소스 소유자(사용자) 인증을 위한 함수 타입
// username과 password를 받아 인증 성공 여부를 반환한다.
type ResourceOwnerAuthentication func(username, password string) (bool, error)

// ResourceOwnerPasswordCredentialsFlow OAuth2 리소스 소유자 비밀번호 자격 증명 흐름 구현체 [RFC 6749 문단 Section 4.3] 참조
//
// [RFC 6749 문단 Section 4.3]: https://datatracker.ietf.org/doc/html/rfc6749#section-4.3
type ResourceOwnerPasswordCredentialsFlow struct {
	authentication ResourceOwnerAuthentication
	store          Store

	IDGenerator IDGenerator
}

func NewResourceOwnerPasswordCredentialsFlow(auth ResourceOwnerAuthentication, r Store) *ResourceOwnerPasswordCredentialsFlow {
	return &ResourceOwnerPasswordCredentialsFlow{authentication: auth, store: r}
}

// Generate 사용자 자격 증명을 통해 액세스 토큰과 리프레시 토큰을 생성한다.
func (f *ResourceOwnerPasswordCredentialsFlow) Generate(c *client.Client, r *pkg.TokenRequest) (*Token, *RefreshToken, error) {
	if r.Username == "" || r.Password == "" {
		return nil, nil, fmt.Errorf("%w: username/password is required", ErrInvalidRequest)
	}
	auth, err := f.authentication(r.Username, r.Password)
	if err != nil {
		return nil, nil, err
	}
	if !auth {
		return nil, nil, fmt.Errorf("%w: resource owner authentication is failed", ErrUnauthorized)
	}
	scopes, err := c.Scopes.GetAll(pkg.SplitScope(r.Scope))
	if err != nil {
		return nil, nil, err
	}
	accessToken := NewToken(f.IDGenerator, c)
	accessToken.Username = r.Username
	accessToken.Scopes = scopes
	var refresh *RefreshToken
	// 액세스 토큰 저장 및 리프레시 토큰 생성 (기밀 클라이언트만 리프레시 토큰 발급)
	err = f.store.Save(accessToken, func(t *Token) *RefreshToken {
		if c.Type == pkg.ClientTypeConfidential {
			refresh = NewRefreshToken(t, f.IDGenerator)
		}
		return refresh
	})
	if err != nil {
		return nil, nil, err
	}
	return accessToken, refresh, nil
}

// RefreshFlow OAuth2 리프레시 토큰 흐름 구현체 [RFC 6749 - 문단 6] 참조
//
// [RFC 6749 - 문단 6]: https://datatracker.ietf.org/doc/html/rfc6749#section-6
type RefreshFlow struct {
	store Store

	IDGenerator IDGenerator
}

func NewRefreshFlow(r Store) *RefreshFlow {
	return &RefreshFlow{store: r}
}

// Generate 리프레시 토큰을 통해 새로운 액세스 토큰과 리프레시 토큰을 생성한다.
func (f *RefreshFlow) Generate(c *client.Client, r *pkg.TokenRequest) (*Token, *RefreshToken, error) {
	if r.RefreshToken == "" {
		return nil, nil, fmt.Errorf("%w: refresh token is required", ErrInvalidRequest)
	}
	rt, err := f.store.FindRefreshTokenByValue(r.RefreshToken)
	if errors.Is(err, ErrRefreshTokenNotFound) {
		return nil, nil, fmt.Errorf("%w: refresh token is not found", ErrTokenCannotGrant)
	}
	if err != nil {
		return nil, nil, err
	}
	if rt.Token.ClientID != c.ID {
		return nil, nil, fmt.Errorf("%w: client is different", ErrUnauthorized)
	}
	if rt.ExpiredAt.Before(time.Now()) {
		return nil, nil, fmt.Errorf("%w: refresh token is expires", ErrTokenCannotGrant)
	}
	// 스코프 결정 (새 스코프가 요청되지 않은 경우 기존 스코프 유지)
	var scopes client.GrantedScopes
	if r.Scope != "" {
		scopes, err = c.Scopes.GetAll(pkg.SplitScope(r.Scope))
	} else {
		scopes = rt.Token.Scopes
	}
	if err != nil {
		return nil, nil, err
	}
	newToken := NewToken(f.IDGenerator, c)
	newToken.Username = rt.Token.Username
	newToken.Scopes = scopes
	var newRefreshToken *RefreshToken
	// 기존 리프레시 토큰 삭제 및 새 토큰 저장
	err = f.store.Refresh(rt, newToken, func(t *Token) *RefreshToken {
		newRefreshToken = NewRefreshToken(t, f.IDGenerator)
		return newRefreshToken
	})
	if err != nil {
		return nil, nil, err
	}

	return newToken, newRefreshToken, nil
}

// ClientCredentialsFlow OAuth2 클라이언트 자격 증명 흐름 구현체 [RFC 6749 - 문단 4.4] 참조
//
// [RFC 6749 문단 4.4]: https://datatracker.ietf.org/doc/html/rfc6749#section-4.4
type ClientCredentialsFlow struct {
	tokenRepository Store
}

func NewClientCredentialsFlow(r Store) *ClientCredentialsFlow {
	return &ClientCredentialsFlow{tokenRepository: r}
}

// Generate 클라이언트 자격 증명을 통해 액세스 토큰을 생성한다.
// 클라이언트 자격 증명 흐름은 리프레시 토큰을 발급하지 않는다.
func (f *ClientCredentialsFlow) Generate(c *client.Client, r *pkg.TokenRequest) (*Token, *RefreshToken, error) {
	// 공개 클라이언트는 클라이언트 자격 증명 흐름 사용 불가
	if c.Type == pkg.ClientTypePublic {
		return nil, nil, fmt.Errorf("%w: public client cannot grant client credentials", ErrUnauthorized)
	}
	scopes, err := c.Scopes.GetAll(pkg.SplitScope(r.Scope))
	if err != nil {
		return nil, nil, err
	}
	newToken := NewToken(UUIDTokenIDGenerator, c)
	newToken.Scopes = scopes
	// 토큰 저장 (리프레시 토큰 없음)
	err = f.tokenRepository.Save(newToken, func(t *Token) *RefreshToken {
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return newToken, nil, nil
}

// TokenInspector 토큰 상세 정보를 반환하는 인터페이스
// 토큰 검사(Introspection)에 필요한 정보를 제공한다. [RFC 7662] 참조
//
// [RFC 7662]: https://datatracker.ietf.org/doc/html/rfc7662
type TokenInspector interface {
	// GetValue 자장되어 있는 토큰 값을 반환한다.
	GetValue() string

	// IsActive 현재 토큰이 유효한지 여부를 반환한다.
	IsActive() bool

	// GetClientID 이 토큰을 소유하고 있는 문자열로 이루어진 클라이언트의 아이디를 반환한다.
	// 클라이언트 아이디에 관해서는 [RFC 6749] 문서를 참고
	//
	// [RFC 6749]: https://datatracker.ietf.org/doc/html/rfc6749#section-2.2
	GetClientID() string

	// GetUsername 이 토큰을 발급한 유저의 아이디를 반환한다.
	GetUsername() string

	// GetScopes 이 토큰이 부여된 스코프를 반환한다. 스코프가 여러개일 경우 각 스코프는 공백(" ")으로 구분하여 반환한다.
	// 스코프에 관해서는 [RFC 6749] 문서를 참고
	//
	// [RFC 6749]: https://datatracker.ietf.org/doc/html/rfc6749#section-3.3
	GetScopes() string

	// GetIssuedAt 토큰의 발급일을 유닉스 타임으로 반환한다.
	GetIssuedAt() uint

	// GetExpiredAt 만료일 까지 남은 시간을 초로 환산하여 반환한다.
	GetExpiredAt() uint
}

// IntrospectionService 토큰 서비스
// 토큰 검사(Introspection) 기능을 제공한다.
type IntrospectionService struct {
	repository Store
}

// NewIntrospectionService 새로운 IntrospectionService 인스턴스를 생성한다.
func NewIntrospectionService(r Store) *IntrospectionService {
	return &IntrospectionService{repository: r}
}

// Introspection 토큰 검사를 수행한다. [RFC 7662] 참조
//
// [RFC 7662]: https://datatracker.ietf.org/doc/html/rfc7662
func (s *IntrospectionService) Introspection(c *client.Client, r *pkg.IntrospectionRequest) (*pkg.Introspection, error) {
	var accessToken TokenInspector
	var err error
	switch r.TokenTypeHint {
	case "", pkg.TokenHintAccessToken:
		accessToken, err = s.repository.FindAccessTokenByValue(r.Token)
	case pkg.TokenHintRefreshToken:
		accessToken, err = s.repository.FindRefreshTokenByValue(r.Token)
	default:
		return nil, fmt.Errorf("%w: token type hint must be empty or access_token, refresh_token", ErrInvalidRequest)
	}
	if err != nil {
		return nil, err
	}
	if accessToken.GetClientID() != c.ClientID {
		return nil, fmt.Errorf("%w: client is different", ErrUnauthorized)
	}
	if !accessToken.IsActive() {
		return &pkg.Introspection{Active: false}, nil
	}
	intro := &pkg.Introspection{
		Active:    true,
		Scope:     accessToken.GetScopes(),
		ClientID:  accessToken.GetClientID(),
		Username:  accessToken.GetUsername(),
		TokenType: pkg.TokenTypeBearer,
		ExpiresIn: accessToken.GetExpiredAt(),
		IssuedAt:  accessToken.GetIssuedAt(),
	}

	return intro, nil
}

// TokenManagementRepository OAuth2 토큰 관리용 저장소
// 사용자별 토큰 관리를 위한 기능을 제공한다.
type TokenManagementRepository interface {
	// FindAccessTokenByUsername username으로 발급된 엑세스 토큰을 반환한다.
	FindAccessTokenByUsername(u string) ([]Token, error)

	// FindAccessTokenByValue v와 일치하는 엑세스 토큰을 조회하여 반환한다.
	// 토큰이 존재하지 않을 경우 oauth.ErrTokenNotFound 오류를 반환한다.
	FindAccessTokenByValue(v string) (*Token, error)

	// FindRefreshTokenByTokenID 엑세스 토큰을 리플레시할 수 있는 리플레시 토큰을 검색하여 반환한다.
	// 토큰이 존재하지 않을 경우 oauth.ErrTokenNotFound 오류를 반환한다.
	FindRefreshTokenByTokenID(t uint) (*RefreshToken, error)

	// Delete 입력 받은 토큰들을 모두 삭제한다.
	// 리플레시 토큰(rt)은 nil일 수 있으며 nil일 경우 삭제하지 않는다.
	Delete(t *Token, rt *RefreshToken) error
}

// ManagementService 토큰 관리 서비스
// 사용자별 토큰 관리 기능을 제공한다.
type ManagementService struct {
	repository TokenManagementRepository
}

func NewManagementService(r TokenManagementRepository) *ManagementService {
	return &ManagementService{repository: r}
}

// GetGrantedTokens 사용자에게 발급된 모든 액세스 토큰을 조회한다.
func (s *ManagementService) GetGrantedTokens(username string) ([]Token, error) {
	return s.repository.FindAccessTokenByUsername(username)
}

// Delete 지정된 액세스 토큰과 연관된 리프레시 토큰을 삭제한다.
func (s *ManagementService) Delete(owner *security.Login, t string) error {
	accessToken, err := s.repository.FindAccessTokenByValue(t)
	if err != nil {
		return err
	}
	if owner.Username != accessToken.Username {
		return ErrUnauthorized
	}
	rt, err := s.repository.FindRefreshTokenByTokenID(accessToken.ID)
	if err != nil && !errors.Is(err, ErrAccessTokenNotFound) {
		return err
	}
	return s.repository.Delete(accessToken, rt)
}
