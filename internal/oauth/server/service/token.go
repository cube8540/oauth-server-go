package service

import (
	"fmt"
	"oauth-server-go/internal/oauth/client"
	oautherr "oauth-server-go/internal/oauth/errors"
	"oauth-server-go/internal/oauth/server/repository"
	"oauth-server-go/internal/oauth/token"
)

// TokenGranter 토큰 부여자 인터페이스
type TokenGranter interface {

	// GenerateToken 주어진 클라이언트와 요청 정보를 이용하여 토큰을 발행한다.
	GenerateToken(c *client.Client, request *token.Request) (*token.AccessToken, *token.RefreshToken, error)
}

var (
	// authorizationCodeGranter OAuth2 인가 코드 승인 방식을 구현한 토큰 부여자
	authorizationCodeGranter TokenGranter

	// resourceOwnerPasswordCredentialsGranter OAuth2 자원 소유자 패스워드 인증 승인 방식을 구현한 토큰 부여자
	resourceOwnerPasswordCredentialsGranter TokenGranter

	// clientCredentialsGranter 클라이언트 승인 방식을 구현한 토큰 부여자
	clientCredentialsGranter TokenGranter

	// refreshTokenGranter 리플레시 토큰 승인 방식을 구현한 토큰 부여자
	refreshTokenGranter TokenGranter
)

func SetGlobalAuthorizationCodeGranter(g TokenGranter) {
	authorizationCodeGranter = g
}

func SetGlobalResourceOwnerPasswordCredentialsGranter(g TokenGranter) {
	resourceOwnerPasswordCredentialsGranter = g
}

func SetGlobalClientCredentialsGranter(g TokenGranter) {
	clientCredentialsGranter = g
}

func SetGlobalRefreshTokenGranter(g TokenGranter) {
	refreshTokenGranter = g
}

// ChooseTokenGranter 주어진 토큰 부여 타입에 따른 적절한 부여자를 반환한다.
func ChooseTokenGranter(t token.GrantType) (TokenGranter, error) {
	switch t {
	case token.GrantTypeAuthorizationCode:
		return authorizationCodeGranter, nil
	case token.GrantTypePassword:
		return resourceOwnerPasswordCredentialsGranter, nil
	case token.GrantTypeClientCredentials:
		return clientCredentialsGranter, nil
	case token.GrantTypeRefreshToken:
		return refreshTokenGranter, nil
	default:
		return nil, fmt.Errorf("%w: undefined grant type", oautherr.ErrInvalidRequest)
	}
}

// TokenIssuer 생성된 토큰을 저장소에 저장하는 서비스 구조체
//
// TokenGranter 를 통해 발급된 토큰을 저장소에 저장한다.
type TokenIssuer struct {
	repo    repository.TokenRepository
	granter TokenGranter
}

func (srv *TokenIssuer) GenerateToken(c *client.Client, request *token.Request) (*token.AccessToken, *token.RefreshToken, error) {
	accessToken, refreshToken, err := srv.granter.GenerateToken(c, request)
	if err != nil {
		return nil, nil, err
	}

	err = srv.repo.Transaction(func(r repository.TokenRepository) error {
		if err = r.SaveAccessToken(accessToken); err != nil {
			return fmt.Errorf("error occurred while saving access token: %w", err)
		}

		if refreshToken != nil {
			if err = r.SaveRefreshToken(refreshToken); err != nil {
				return fmt.Errorf("error occurred while saving refresh token: %w", err)
			}
		}

		if request.Type == token.GrantTypeRefreshToken {
			storedRefreshToken, _ := r.FindRefreshTokenByValue(request.RefreshToken)
			storedAccessToken := storedRefreshToken.Token()

			if err = srv.repo.DeleteRefreshToken(storedRefreshToken); err != nil {
				return fmt.Errorf("error occurred while deleting refresh token: %w", err)
			}

			if err = srv.repo.DeleteAccessToken(storedAccessToken); err != nil {
				return fmt.Errorf("error occurred while deleting access token: %w", err)
			}
		}

		return nil
	})

	return accessToken, refreshToken, err
}

// TokenService 엑세스 토큰 및 리플레시 토큰에 대한 관리 포인트를 제공하는 서비스 구조체
type TokenService struct {
	repo repository.TokenRepository
}

func NewTokenService(repo repository.TokenRepository) *TokenService {
	return &TokenService{repo: repo}
}

// Inspection 요청한 토큰의 상세 정보를 조회한다.
//
// Returns:
//   - *token.Inspection: 조회된 토큰의 상세 정보
//   - bool: 조회 성공 여부
func (srv *TokenService) Inspection(c *client.Client, request *token.InspectionRequest) (*token.Inspection, bool, error) {
	var t any
	if request.TokenTypeHint == token.TypeHintAccessToken {
		t, _ = srv.repo.FindAccessTokenByValue(request.Token)
	} else if request.TokenTypeHint == token.TypeHintRefreshToken {
		t, _ = srv.repo.FindRefreshTokenByValue(request.Token)
	} else {
		return nil, false, fmt.Errorf("%w: undefined token type hint", oautherr.ErrInvalidRequest)
	}

	// 조회된 토큰이 없을 경우 함수 종료
	if t == nil {
		return nil, false, nil
	}

	var inspection *token.Inspection
	if accessToken, ok := t.(*token.AccessToken); ok {
		inspection = token.InspectAccessToken(accessToken)
	} else if refreshToken, ok := t.(*token.RefreshToken); ok {
		inspection = token.InspectRefreshToken(refreshToken)
	} else {
		return nil, false, fmt.Errorf("%w: undefined token type", oautherr.ErrInvalidRequest)
	}

	if inspection.ClientID != c.Id() {
		return nil, false, fmt.Errorf("%w: invalid client", oautherr.ErrInvalidClient)
	}

	return inspection, true, nil
}
