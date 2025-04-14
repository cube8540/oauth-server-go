package service

import (
	"context"
	"errors"
	"oauth-server-go/oauth"
	"oauth-server-go/oauth/entity"
	"oauth-server-go/security"
	"time"
)

// TokenRepository OAuth2 토큰 저장소
// 엑세스 토큰과 리프레시 토큰을 저장하고 조회하는 인터페이스
type TokenRepository interface {
	// Save 인자로 받은 엑세스 토큰을 저장하고 fn 함수를 통해 토큰을 재발행 할 수 있는 리플레시 토큰을 생성하여 저장한다.
	// 만약 fn이 nil을 반환 했을 경우 엑세스 토큰은 리플레시 토큰을 가지지 않는다.
	Save(t *entity.Token, fn func(t *entity.Token) *entity.RefreshToken) error

	// FindAccessTokenByValue v와 일치하는 엑세스 토큰을 조회하여 반환한다.
	// 토큰이 존재하지 않을 경우 oauth.ErrTokenNotFound 오류를 반환한다.
	FindAccessTokenByValue(v string) (*entity.Token, error)

	// FindRefreshTokenByValue v와 일치하는 리플레시 토큰을 조회하여 반환한다.
	// 토큰이 존재하지 않을 경우 oauth.ErrTokenNotFound 오류를 반환한다.
	FindRefreshTokenByValue(v string) (*entity.RefreshToken, error)

	// Refresh 기존의 oldRefreshToken는 삭제 하고 신규 newToken을 저장한다 그 후 fn 함수를 통해 newToken을 재발행 할 수 있는 리플레시 토큰을 생성하여 저장한다.
	// 만약 fn이 nil을 반환 했을 경우 newToken은 리플레시 토큰을 가지지 않는다.
	Refresh(oldRefreshToken *entity.RefreshToken, newToken *entity.Token, fn func(t *entity.Token) *entity.RefreshToken) error
}

// AuthCodeConsume 인자로 인가코드를 받아 그 인가코드의 엔티티 반환하고 저장소에서 삭제한다.
type AuthCodeConsume func(code string) (*entity.AuthorizationCode, error)

// AuthorizationCodeFlow OAuth2 인가 코드 흐름(Authorization Code Flow) 구현체 [RFC 6749 문단 4.1] 참조
//
// [RFC 6749 문단 4.1]: https://datatracker.ietf.org/doc/html/rfc6749#section-4.1
type AuthorizationCodeFlow struct {
	tokenRepository TokenRepository
	consume         AuthCodeConsume
}

func NewAuthorizationCodeFlow(tr TokenRepository, consume AuthCodeConsume) *AuthorizationCodeFlow {
	return &AuthorizationCodeFlow{
		tokenRepository: tr,
		consume:         consume,
	}
}

// Generate 인가 코드를 통해 액세스 토큰과 리프레시 토큰을 생성한다.
// PKCE(Proof Key for Code Exchange) 메커니즘을 지원한다. [RFC 7636] 참조
//
// [RFC 7636]: https://datatracker.ietf.org/doc/html/rfc7636
func (s *AuthorizationCodeFlow) Generate(c *entity.Client, r *oauth.TokenRequest) (*entity.Token, *entity.RefreshToken, error) {
	if r.Code == "" {
		return nil, nil, oauth.NewErr(oauth.ErrInvalidRequest, "authorization code is required")
	}
	code, err := s.consume(r.Code)
	if err != nil {
		return nil, nil, err
	}
	if code.ClientID != c.ID {
		return nil, nil, oauth.NewErr(oauth.ErrUnauthorizedClient, "authorization code client is different")
	}
	if !code.Available() {
		return nil, nil, oauth.NewErr(oauth.ErrInvalidGrant, "authorization code is expires")
	}
	// PKCE 검증 (code_verifier와 code_challenge 검증)
	verifier, err := code.Verifier(r.CodeVerifier)
	if err != nil {
		return nil, nil, err
	}
	if !verifier {
		return nil, nil, oauth.NewErr(oauth.ErrInvalidRequest, "code_verifier is not matched")
	}
	// 리다이렉트 URI 일치 여부 검증
	if to, _ := c.RedirectURL(code.Redirect); to != r.Redirect {
		return nil, nil, oauth.NewErr(oauth.ErrInvalidRequest, "redirect_uri is not matched")
	}
	token := entity.NewTokenWithCode(entity.UUIDTokenIDGenerator, code)
	var refresh *entity.RefreshToken
	// 액세스 토큰 저장 및 리프레시 토큰 생성 (기밀 클라이언트만 리프레시 토큰 발급)
	err = s.tokenRepository.Save(token, func(t *entity.Token) *entity.RefreshToken {
		if c.Type == oauth.ClientTypeConfidential {
			refresh = entity.NewRefreshToken(t, entity.UUIDTokenIDGenerator)
		}
		return refresh
	})
	if err != nil {
		return nil, nil, err
	}
	return token, refresh, nil
}

// ImplicitFlow OAuth2 암묵적 흐름(Implicit Flow) 구현체 [RFC 6749 문단 4.2] 참조
// 보안상 이유로 리프레시 토큰을 발급하지 않는다.
//
// [RFC 6749 문단 4.2]: https://datatracker.ietf.org/doc/html/rfc6749#section-4.2
type ImplicitFlow struct {
	tokenRepository TokenRepository
}

// NewImplicitFlow 새로운 ImplicitFlow 인스턴스를 생성한다.
func NewImplicitFlow(r TokenRepository) *ImplicitFlow {
	return &ImplicitFlow{tokenRepository: r}
}

// Generate 인가 요청을 통해 액세스 토큰을 생성한다.
// 암묵적 흐름은 리프레시 토큰을 발급하지 않는다.
func (f *ImplicitFlow) Generate(c *entity.Client, r *oauth.AuthorizationRequest) (*entity.Token, error) {
	// CSRF 방지를 위한 state 파라미터 필수 검증
	if r.State == "" {
		return nil, oauth.NewErr(oauth.ErrInvalidRequest, "implicit flow is required state parameter")
	}
	scopes, err := c.Scopes.GetAll(oauth.SplitScope(r.Scopes))
	if err != nil {
		return nil, err
	}
	token := entity.NewToken(entity.UUIDTokenIDGenerator, c)
	token.Username = r.Username
	token.Scopes = scopes
	err = f.tokenRepository.Save(token, func(_ *entity.Token) *entity.RefreshToken {
		// Implicit Flow는 리플레시 토큰을 생성하지 않는다.
		return nil
	})
	return token, nil
}

// ResourceOwnerAuthentication 리소스 소유자(사용자) 인증을 위한 함수 타입
// username과 password를 받아 인증 성공 여부를 반환한다.
type ResourceOwnerAuthentication func(username, password string) (bool, error)

// ResourceOwnerPasswordCredentialsFlow OAuth2 리소스 소유자 비밀번호 자격 증명 흐름 구현체 [RFC 6749 문단 Section 4.3] 참조
//
// [RFC 6749 문단 Section 4.3]: https://datatracker.ietf.org/doc/html/rfc6749#section-4.3
type ResourceOwnerPasswordCredentialsFlow struct {
	authentication  ResourceOwnerAuthentication
	tokenRepository TokenRepository
}

func NewResourceOwnerPasswordCredentialsFlow(auth ResourceOwnerAuthentication, r TokenRepository) *ResourceOwnerPasswordCredentialsFlow {
	return &ResourceOwnerPasswordCredentialsFlow{authentication: auth, tokenRepository: r}
}

// Generate 사용자 자격 증명을 통해 액세스 토큰과 리프레시 토큰을 생성한다.
func (f *ResourceOwnerPasswordCredentialsFlow) Generate(c *entity.Client, r *oauth.TokenRequest) (*entity.Token, *entity.RefreshToken, error) {
	if r.Username == "" || r.Password == "" {
		return nil, nil, oauth.NewErr(oauth.ErrInvalidRequest, "username, password is required")
	}
	auth, err := f.authentication(r.Username, r.Password)
	if err != nil {
		return nil, nil, err
	}
	if !auth {
		return nil, nil, oauth.NewErr(oauth.ErrAccessDenied, "failed resource owner authentication")
	}
	scopes, err := c.Scopes.GetAll(oauth.SplitScope(r.Scope))
	if err != nil {
		return nil, nil, err
	}
	token := entity.NewToken(entity.UUIDTokenIDGenerator, c)
	token.Username = r.Username
	token.Scopes = scopes
	var refresh *entity.RefreshToken
	// 액세스 토큰 저장 및 리프레시 토큰 생성 (기밀 클라이언트만 리프레시 토큰 발급)
	err = f.tokenRepository.Save(token, func(t *entity.Token) *entity.RefreshToken {
		if c.Type == oauth.ClientTypeConfidential {
			refresh = entity.NewRefreshToken(t, entity.UUIDTokenIDGenerator)
		}
		return refresh
	})
	if err != nil {
		return nil, nil, err
	}
	return token, refresh, nil
}

// RefreshFlow OAuth2 리프레시 토큰 흐름 구현체 [RFC 6749 - 문단 6] 참조
//
// [RFC 6749 - 문단 6]: https://datatracker.ietf.org/doc/html/rfc6749#section-6
type RefreshFlow struct {
	tokenRepository TokenRepository
}

func NewRefreshFlow(r TokenRepository) *RefreshFlow {
	return &RefreshFlow{tokenRepository: r}
}

// Generate 리프레시 토큰을 통해 새로운 액세스 토큰과 리프레시 토큰을 생성한다.
func (f *RefreshFlow) Generate(c *entity.Client, r *oauth.TokenRequest) (*entity.Token, *entity.RefreshToken, error) {
	if r.RefreshToken == "" {
		return nil, nil, oauth.NewErr(oauth.ErrInvalidRequest, "refresh_token is required")
	}
	rt, err := f.tokenRepository.FindRefreshTokenByValue(r.RefreshToken)
	if errors.Is(err, oauth.ErrTokenNotFound) {
		return nil, nil, oauth.NewErr(oauth.ErrInvalidGrant, "refresh token is not found")
	}
	if err != nil {
		return nil, nil, err
	}
	if rt.InspectClientID() != c.ClientID {
		return nil, nil, oauth.NewErr(oauth.ErrAccessDenied, "refresh token client is different")
	}
	if rt.ExpiredAt.Before(time.Now()) {
		return nil, nil, oauth.NewErr(oauth.ErrInvalidGrant, "refresh token is invalid")
	}
	// 스코프 결정 (새 스코프가 요청되지 않은 경우 기존 스코프 유지)
	var scopes entity.GrantedScopes
	if r.Scope != "" {
		scopes, err = c.Scopes.GetAll(oauth.SplitScope(r.Scope))
	} else {
		scopes = rt.Token.Scopes
	}
	if err != nil {
		return nil, nil, err
	}
	newToken := entity.NewToken(entity.UUIDTokenIDGenerator, c)
	newToken.Username = rt.Token.Username
	newToken.Scopes = scopes
	var newRefreshToken *entity.RefreshToken
	// 기존 리프레시 토큰 삭제 및 새 토큰 저장
	err = f.tokenRepository.Refresh(rt, newToken, func(t *entity.Token) *entity.RefreshToken {
		newRefreshToken = entity.NewRefreshToken(t, entity.UUIDTokenIDGenerator)
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
	tokenRepository TokenRepository
}

func NewClientCredentialsFlow(r TokenRepository) *ClientCredentialsFlow {
	return &ClientCredentialsFlow{tokenRepository: r}
}

// Generate 클라이언트 자격 증명을 통해 액세스 토큰을 생성한다.
// 클라이언트 자격 증명 흐름은 리프레시 토큰을 발급하지 않는다.
func (f *ClientCredentialsFlow) Generate(c *entity.Client, r *oauth.TokenRequest) (*entity.Token, *entity.RefreshToken, error) {
	// 공개 클라이언트는 클라이언트 자격 증명 흐름 사용 불가
	if c.Type == oauth.ClientTypePublic {
		return nil, nil, oauth.NewErr(oauth.ErrUnauthorizedClient, "client cannot have been granted token")
	}
	scopes, err := c.Scopes.GetAll(oauth.SplitScope(r.Scope))
	if err != nil {
		return nil, nil, err
	}
	newToken := entity.NewToken(entity.UUIDTokenIDGenerator, c)
	newToken.Scopes = scopes
	// 토큰 저장 (리프레시 토큰 없음)
	err = f.tokenRepository.Save(newToken, func(t *entity.Token) *entity.RefreshToken {
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
	// InspectValue 자장되어 있는 토큰 값을 반환한다.
	InspectValue() string

	// InspectActive 현재 토큰이 유효한지 여부를 반환한다.
	InspectActive() bool

	// InspectClientID 이 토큰을 소유하고 있는 문자열로 이루어진 클라이언트의 아이디를 반환한다.
	// 클라이언트 아이디에 관해서는 [RFC 6749] 문서를 참고
	//
	// [RFC 6749]: https://datatracker.ietf.org/doc/html/rfc6749#section-2.2
	InspectClientID() string

	// InspectUsername 이 토큰을 발급한 유저의 아이디를 반환한다.
	InspectUsername() string

	// InspectScope 이 토큰이 부여된 스코프를 반환한다. 스코프가 여러개일 경우 각 스코프는 공백(" ")으로 구분하여 반환한다.
	// 스코프에 관해서는 [RFC 6749] 문서를 참고
	//
	// [RFC 6749]: https://datatracker.ietf.org/doc/html/rfc6749#section-3.3
	InspectScope() string

	// InspectIssuedAt 토큰의 발급일을 유닉스 타임으로 반환한다.
	InspectIssuedAt() uint

	// InspectExpiredAt 만료일 까지 남은 시간을 초로 환산하여 반환한다.
	InspectExpiredAt() uint
}

// TokenService 토큰 서비스
// 토큰 검사(Introspection) 기능을 제공한다.
type TokenService struct {
	repository TokenRepository
}

// NewTokenService 새로운 TokenService 인스턴스를 생성한다.
func NewTokenService(r TokenRepository) *TokenService {
	return &TokenService{repository: r}
}

// Introspection 토큰 검사를 수행한다. [RFC 7662] 참조
//
// [RFC 7662]: https://datatracker.ietf.org/doc/html/rfc7662
func (s *TokenService) Introspection(c *entity.Client, r *oauth.IntrospectionRequest) (*oauth.Introspection, error) {
	var token TokenInspector
	var err error
	switch r.TokenTypeHint {
	case "", oauth.TokenHintAccessToken:
		token, err = s.repository.FindAccessTokenByValue(r.Token)
	case oauth.TokenHintRefreshToken:
		token, err = s.repository.FindRefreshTokenByValue(r.Token)
	default:
		return nil, oauth.NewErr(oauth.ErrInvalidRequest, "token_type_hint must be empty or access_token, refresh_token")
	}
	if errors.Is(err, oauth.ErrTokenNotFound) {
		return nil, oauth.NewErr(oauth.ErrInvalidGrant, "token is not found.")
	}
	if err != nil {
		return nil, err
	}
	if token.InspectClientID() != c.ClientID {
		return nil, oauth.NewErr(oauth.ErrAccessDenied, "token client is different.")
	}
	if !token.InspectActive() {
		return &oauth.Introspection{Active: false}, nil
	}
	intro := &oauth.Introspection{
		Active:    true,
		Scope:     token.InspectScope(),
		ClientID:  token.InspectClientID(),
		Username:  token.InspectUsername(),
		TokenType: oauth.TokenTypeBearer,
		ExpiresIn: token.InspectExpiredAt(),
		IssuedAt:  token.InspectIssuedAt(),
	}

	return intro, nil
}

// TokenManagementRepository OAuth2 토큰 관리용 저장소
// 사용자별 토큰 관리를 위한 기능을 제공한다.
type TokenManagementRepository interface {
	// FindAccessTokenByUsername username으로 발급된 엑세스 토큰을 반환한다.
	FindAccessTokenByUsername(u string) ([]entity.Token, error)

	// FindAccessTokenByValue v와 일치하는 엑세스 토큰을 조회하여 반환한다.
	// 토큰이 존재하지 않을 경우 oauth.ErrTokenNotFound 오류를 반환한다.
	FindAccessTokenByValue(v string) (*entity.Token, error)

	// FindRefreshTokenByTokenID 엑세스 토큰을 리플레시할 수 있는 리플레시 토큰을 검색하여 반환한다.
	// 토큰이 존재하지 않을 경우 oauth.ErrTokenNotFound 오류를 반환한다.
	FindRefreshTokenByTokenID(t uint) (*entity.RefreshToken, error)

	// Delete 입력 받은 토큰들을 모두 삭제한다.
	// 리플레시 토큰(rt)은 nil일 수 있으며 nil일 경우 삭제하지 않는다.
	Delete(t *entity.Token, rt *entity.RefreshToken) error
}

// TokenManagementService 토큰 관리 서비스
// 사용자별 토큰 관리 기능을 제공한다.
type TokenManagementService struct {
	repository TokenManagementRepository
}

func NewTokenManagementService(r TokenManagementRepository) *TokenManagementService {
	return &TokenManagementService{repository: r}
}

// GetGrantedTokens 사용자에게 발급된 모든 액세스 토큰을 조회한다.
func (s *TokenManagementService) GetGrantedTokens(username string) ([]entity.Token, error) {
	return s.repository.FindAccessTokenByUsername(username)
}

// Delete 지정된 액세스 토큰과 연관된 리프레시 토큰을 삭제한다.
func (s *TokenManagementService) Delete(c context.Context, t string) error {
	token, err := s.repository.FindAccessTokenByValue(t)
	if err != nil {
		return err
	}
	owner, ok := c.Value(security.SessionKeyLogin).(*security.SessionLogin)
	if !ok || owner.Username != token.Username {
		return oauth.ErrUnauthorized
	}
	rt, err := s.repository.FindRefreshTokenByTokenID(token.ID)
	if err != nil && !errors.Is(err, oauth.ErrTokenNotFound) {
		return err
	}
	return s.repository.Delete(token, rt)
}
