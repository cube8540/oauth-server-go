package service

import (
	"errors"
	"gorm.io/gorm"
	"oauth-server-go/oauth"
	"oauth-server-go/oauth/entity"
)

// TokenRepository OAuth2 토큰 저장소
type TokenRepository interface {
	// Save 인자로 받은 엑세스 토큰을 저장하고 저장된 토큰을 fn 함수를 통해 저장된 토큰을 재발행 할 수 있는 리플레시 토큰을 생성하여 저장한다.
	// 만약 fn이 nil을 반환 했을 경우 엑세스 토큰은 리플레시 토큰을 가지지 않는다.
	Save(t *entity.Token, fn func(t *entity.Token) *entity.RefreshToken) error

	// FindAccessTokenByValue v와 일치하는 엑세스 토큰을 조회하여 반환한다.
	FindAccessTokenByValue(v string) (*entity.Token, error)

	// FindRefreshTokenByValue v와 일치하는 리플레시 토큰을 조회하여 반환한다.
	FindRefreshTokenByValue(v string) (*entity.RefreshToken, error)
}

// AuthCodeConsume 인자로 인가코드를 받아 그 인가코드의 엔티티 반환하고 저장소에서 삭제한다.
type AuthCodeConsume func(code string) (*entity.AuthorizationCode, error)

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

func (s AuthorizationCodeFlow) Generate(c *entity.Client, r *oauth.TokenRequest) (*entity.Token, *entity.RefreshToken, error) {
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
	verifier, err := code.Verifier(r.CodeVerifier)
	if err != nil {
		return nil, nil, err
	}
	if !verifier {
		return nil, nil, oauth.NewErr(oauth.ErrInvalidRequest, "code_verifier is not matched")
	}
	if to, _ := c.RedirectURL(code.Redirect); to != r.Redirect {
		return nil, nil, oauth.NewErr(oauth.ErrInvalidRequest, "redirect_uri is not matched")
	}
	token := entity.NewTokenWithCode(entity.UUIDTokenIDGenerator, code)
	var refresh *entity.RefreshToken
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

type ImplicitFlow struct {
	tokenRepository TokenRepository
}

func NewImplicitFlow(r TokenRepository) *ImplicitFlow {
	return &ImplicitFlow{tokenRepository: r}
}

func (f ImplicitFlow) Generate(c *entity.Client, r *oauth.AuthorizationRequest) (any, error) {
	if r.State == "" {
		return nil, oauth.NewErr(oauth.ErrInvalidRequest, "implicit flow is required state parameter")
	}

	scopes, err := c.GetScopes(r.SplitScope())
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

// TokenInspector 토큰 상세 정보를 반환하는 인터페이스
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

type TokenService struct {
	repository TokenRepository
}

func NewTokenService(r TokenRepository) *TokenService {
	return &TokenService{repository: r}
}

func (s TokenService) Introspection(c *entity.Client, r *oauth.IntrospectionRequest) (*oauth.Introspection, error) {
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
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return &oauth.Introspection{Active: false}, nil
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
