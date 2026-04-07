package service

import (
	"context"
	"fmt"
	"oauth-server-go/internal/config/log"
	"oauth-server-go/internal/oauth/authorization"
	"oauth-server-go/internal/oauth/client"
	oautherr "oauth-server-go/internal/oauth/errors"
	"oauth-server-go/internal/oauth/server/repository"
	"oauth-server-go/internal/oauth/token"
	"oauth-server-go/internal/pkg/auth"
	"oauth-server-go/internal/pkg/web"
)

type RetrieveAuthorizationCode func(ctx context.Context, code string) (*authorization.Code, bool, error)

// GrantToken 신규 토큰을 발행한다.
type GrantToken func(c *client.Client, request *token.Request) (*token.AccessToken, *token.RefreshToken, error)

// TokenIssuer 생성된 토큰을 저장소에 저장하는 서비스 구조체
//
// TokenGranter 를 통해 발급된 토큰을 저장소에 저장한다.
type TokenIssuer struct {
	Repository repository.TokenRepository

	RetrieveAuthorizationCode RetrieveAuthorizationCode
	AuthenticateResourceOwner auth.SimpleAuthenticate

	GenerateAccessToken  token.GenerateToken
	GenerateRefreshToken token.GenerateToken
}

func (srv *TokenIssuer) chooseGranter(ctx context.Context, t token.GrantType) (GrantToken, error) {
	switch t {
	case token.GrantTypeAuthorizationCode:
		return func(c *client.Client, request *token.Request) (*token.AccessToken, *token.RefreshToken, error) {
			authCodeRetriever := func(code string) (*authorization.Code, bool) {
				cd, find, err := srv.RetrieveAuthorizationCode(ctx, code)
				if err != nil {
					log.Sugared().Errorf("error occurred during consume code(%s): %v", code, err)
				}
				return cd, find
			}

			granter := token.AuthorizationCodeGranter{
				AccessTokenGenerator:      srv.GenerateAccessToken,
				RefreshTokenGenerator:     srv.GenerateRefreshToken,
				RetrieveAuthorizationCode: authCodeRetriever,
			}

			return granter.GenerateToken(c, request)
		}, nil
	case token.GrantTypeRefreshToken:
		return func(c *client.Client, request *token.Request) (*token.AccessToken, *token.RefreshToken, error) {
			refreshTokenRetriever := func(refreshToken string) (*token.RefreshToken, bool) {
				return srv.Repository.FindRefreshTokenByValue(ctx, refreshToken)
			}

			granter := token.RefreshTokenGranter{
				AccessTokenGenerator:  srv.GenerateAccessToken,
				RefreshTokenGenerator: srv.GenerateRefreshToken,
				RetrieveRefreshToken:  refreshTokenRetriever,
				Rotation:              true,
			}
			return granter.GenerateToken(c, request)
		}, nil
	case token.GrantTypeClientCredentials:
		return func(c *client.Client, request *token.Request) (*token.AccessToken, *token.RefreshToken, error) {
			granter := token.ClientCredentialsGranter{
				AccessTokenGenerator: srv.GenerateAccessToken,
			}
			act, err := granter.GenerateToken(c, request)
			return act, nil, err
		}, nil
	case token.GrantTypePassword:
		return func(c *client.Client, request *token.Request) (*token.AccessToken, *token.RefreshToken, error) {
			granter := token.ResourceOwnerPasswordCredentialsGranter{
				Authenticate:          srv.AuthenticateResourceOwner,
				AccessTokenGenerator:  srv.GenerateAccessToken,
				RefreshTokenGenerator: srv.GenerateRefreshToken,
			}
			return granter.GenerateToken(c, request)
		}, nil
	default:
		return nil, fmt.Errorf("%w: undefined grant type", oautherr.ErrInvalidRequest)
	}
}

func (srv *TokenIssuer) Issue(ctx context.Context, c *client.Client, request *token.Request) (*token.AccessToken, *token.RefreshToken, error) {
	granter, err := srv.chooseGranter(ctx, request.Type)
	if err != nil {
		return nil, nil, err
	}

	accessToken, refreshToken, err := granter(c, request)
	if err != nil {
		return nil, nil, err
	}

	err = srv.Repository.Transaction(ctx, func(r repository.TokenRepository) error {
		if err = r.SaveAccessToken(ctx, accessToken); err != nil {
			return fmt.Errorf("error occurred while saving access token: %w", err)
		}

		if refreshToken != nil {
			if err = r.SaveRefreshToken(ctx, refreshToken); err != nil {
				return fmt.Errorf("error occurred while saving refresh token: %w", err)
			}
		}

		if request.Type == token.GrantTypeRefreshToken {
			storedRefreshToken, _ := r.FindRefreshTokenByValue(ctx, request.RefreshToken)
			storedAccessToken := storedRefreshToken.Token()

			if err = srv.Repository.DeleteRefreshToken(ctx, storedRefreshToken); err != nil {
				return fmt.Errorf("error occurred while deleting refresh token: %w", err)
			}

			if err = srv.Repository.DeleteAccessToken(ctx, storedAccessToken); err != nil {
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
func (srv *TokenService) Inspection(ctx context.Context, c *client.Client, request *token.InspectionRequest) (*token.Inspection, bool, error) {
	var t any
	if request.TokenTypeHint == token.TypeHintAccessToken {
		t, _ = srv.repo.FindAccessTokenByValue(ctx, request.Token)
	} else if request.TokenTypeHint == token.TypeHintRefreshToken {
		t, _ = srv.repo.FindRefreshTokenByValue(ctx, request.Token)
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

func (srv *TokenService) GetIssuedTokens(ctx context.Context, username string) []token.AccessToken {
	return srv.repo.FindAccessTokenByUsername(ctx, username)
}

func (srv *TokenService) DeleteToken(ctx context.Context, owner *web.Authentication, t string) error {
	accessToken, ok := srv.repo.FindAccessTokenByValue(ctx, t)
	if !ok {
		return fmt.Errorf("%w: access token not found", oautherr.ErrInvalidRequest)
	}
	if owner.Username != accessToken.Username() {
		return fmt.Errorf("%w: invalid user", oautherr.ErrUnauthorized)
	}
	if err := srv.repo.DeleteAccessToken(ctx, accessToken); err != nil {
		return fmt.Errorf("error occurred while deleting access token: %w", err)
	}
	return nil
}
