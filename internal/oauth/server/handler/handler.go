package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"net/http"
	"net/url"
	"oauth-server-go/internal/config/log"
	"oauth-server-go/internal/oauth/authorization"
	"oauth-server-go/internal/oauth/client"
	oautherr "oauth-server-go/internal/oauth/errors"
	"oauth-server-go/internal/oauth/scope"
	"oauth-server-go/internal/oauth/server/pkg/security"
	"oauth-server-go/internal/oauth/server/service"
	"oauth-server-go/internal/oauth/token"
	"oauth-server-go/internal/pkg/web"
	"oauth-server-go/pkg/array"
	"time"
)

// sessionKeyOriginAuthRequest 인가요청을 세션에 저장할 때 사용하는 키
//
// 인가 요청이 완료될 때 해당 요청에 사용했던 요청 정보를 세션에 저장한다.
// 저장된 세션은 실제로 토큰을 발행 할 때 사용되며 발급이 완료되면 세션에서 삭제한다.
const sessionKeyOriginAuthRequest = "sessions/originAuthRequest"

type (
	// GenerateAuthorizationCode 새 인가 코드를 생성한다.
	GenerateAuthorizationCode func(ctx context.Context, c *client.Client, r *authorization.Request) (*authorization.Code, error)

	// RetrieveClient 클라이언트를 조회한다.
	RetrieveClient func(ctx context.Context, id string) (*client.Client, bool)

	// RetrieveScope 스코프를 조회한다.
	RetrieveScope func(ctx context.Context, code ...string) []scope.Scope

	// TokenIssue 새 토큰을 발행하는 함수
	TokenIssue func(ctx context.Context, c *client.Client, r *token.Request) (*token.AccessToken, *token.RefreshToken, error)

	// TokenInspect 토큰의 상세 정보를 조회한다.
	TokenInspect func(ctx context.Context, c *client.Client, r *token.InspectionRequest) (*token.Inspection, bool, error)
)

// AuthorizationApproveHandler 인가 요청 처리에 대한 핸들러 함수를 제공하는 구조체
type AuthorizationApproveHandler struct {
	GenerateAuthorizationCode GenerateAuthorizationCode
	ImplicitGranter           *token.ImplicitGranter
}

// Handler OAuth2의 주요 엔드 포인트를 처리하는 핸들러 함수를 가지고 있는 구조체
type Handler struct {
	TokenIssuer  *service.TokenIssuer
	TokenService *service.TokenService

	ClientService   *service.ClientService
	AuthCodeService *service.AuthCodeService
	ScopeService    *service.ScopeService

	ImplicitGranter *token.ImplicitGranter
}

// Authorize OAuth2 인가 코드 부여와 암시적 승인 부여의 인가 단계를 구현한 헨들러
// 인증에 사용되었던 요청 전문은 세션으로 저장되었다가 실제 토큰을 발행 할 때 유효성 검증으로 사용된다.
//
// 요청 정보를 검증하고 세션에 저장한 뒤 사용자에게 인가 승인 페이지를 반환한다.
// 사용자는 인가 승인 페이지에서 승인/거부를 할 수 있고 승인시 요청하였던 응답 방식(response_type)에 따라 인가 코드나 토큰을 발행한다.
// 발생한 에러는 JSON 형태로 응답 되다가, 리다이렉트 URL 검증이 완료된 이후 부터는 검증된 리다이렉트 URL로 에러 정보를 전송한다.
// 자세한 흐름은 [Authorization Code Grant] 와 [Implicit Grant] 를 확인.
//
// Parameters(application/form-data): authorization.Request
//
// Returns: 인가 승인 페이지
//
//	Note: 이 페이지는 사용자의 로그인이 완료 된 후 접근 해야 한다.
//
// [Authorization Code Grant]: https://datatracker.ietf.org/doc/html/rfc6749#section-4.1
// [Implicit Grant]: https://datatracker.ietf.org/doc/html/rfc6749#section-4.2
func (h *Handler) Authorize(ctx *gin.Context) error {
	var request authorization.Request
	if err := ctx.ShouldBindQuery(&request); err != nil {
		return NewOAuth2Error(oautherr.ErrInvalidRequest, "invalid request")
	}

	if request.Client == "" {
		return NewOAuth2Error(oautherr.ErrInvalidRequest, "client_id is required")
	}

	requestContext := ctx.Request.Context()
	clt, ok := h.ClientService.Retrieve(requestContext, request.Client)
	if !ok {
		return NewOAuth2Error(oautherr.ErrInvalidClient, "invalid client")
	}

	redirect, err := clt.ValidateRedirectURI(request.Redirect)
	if err != nil {
		return NewOAuth2Error(oautherr.ErrInvalidRequest, "invalid redirect_uri")
	}
	// callback 변수 할당 이후 부터 발생한 에러는 이 주소로 리다이렉팅 된다.
	callback, _ := url.Parse(redirect)

	if request.ResponseType == "" {
		return WrapAuthRequest(oautherr.ErrInvalidRequest, "response_type is required", &request, callback)
	}

	if request.ResponseType != authorization.ResponseTypeCode &&
		request.ResponseType != authorization.ResponseTypeToken {
		return WrapAuthRequest(oautherr.ErrInvalidRequest, "undefined response_type", &request, callback)
	}

	requestScopes := scope.Split(request.Scopes)
	if !array.ContainsAll(clt.Scopes(), requestScopes) {
		return WrapAuthRequest(oautherr.ErrInvalidScope, "invalid scope", &request, callback)
	}

	scopes := h.ScopeService.Retrieve(requestContext, requestScopes...)

	authentication, _ := web.RetrieveAuthentication(ctx)
	request.Username = authentication.Username

	ctx.HTML(http.StatusOK, "approval.html", gin.H{
		"scopes": scopes,
		"c":      clt.Name(),
	})

	session := sessions.Default(ctx)
	if err = storeOriginRequest(session, &request); err != nil {
		return WrapAuthRequest(err, "error occurred during store origin request", &request, callback)
	} else {
		return nil
	}
}

// Approve 리소스 소유자가 인가를 승인하여 인가 코드나 토큰을 생성하고 인가 요청에 사용하였던 리다이렉트 URL로 생성된 코드나 토큰을 전송한다.
// 스코프의 경우 기존에 요청했던 스코프 중 자원 소유자가 승인한 스코프만 부여한다.
//
// Parameters(application/form-data):
//   - scope: 사용자가 승인 한 스코프 만약 이 값이 비어 있을 경우 사용자가 승인을 하지 않은 것으로 간주하여 클라이언트에 승인 거부 메시지를 전달한다.
//
// Note: 이 페이지는 사용자의 로그인이 완료 된 후 접근 해야 한다.
func (h *Handler) Approve(ctx *gin.Context) error {
	session := sessions.Default(ctx)
	request, ok, err := getOriginRequest(session)
	if err != nil {
		return NewOAuth2Error(err, "unknown error occurred during get origin request")
	}
	if !ok {
		return NewOAuth2Error(oautherr.ErrInvalidRequest, "authorize request is not found")
	}

	requestContext := ctx.Request.Context()
	clt, _ := h.ClientService.Retrieve(requestContext, request.Client)
	callback, _ := url.Parse(request.Redirect)

	authentication, _ := web.RetrieveAuthentication(ctx)
	if request.Username != authentication.Username {
		log.Sugared().Warnf("user %s is not allowed to approve the request", authentication.Username)
		return WrapAuthRequest(oautherr.ErrUnauthorized, "user is not allowed to approve the request", request, callback)
	}

	approvedScopes := ctx.PostFormArray("scope")
	if len(approvedScopes) == 0 {
		return WrapAuthRequest(oautherr.ErrInvalidScope, "resource owner denied access", request, callback)
	}
	request.Scopes = scope.Join(approvedScopes)

	var src any = nil
	switch request.ResponseType {
	case authorization.ResponseTypeCode:
		src, err = h.AuthCodeService.NewCode(requestContext, clt, request)
	case authorization.ResponseTypeToken:
		tokenRequest := &token.Request{
			Redirect: request.Redirect,
			Username: request.Username,
			Scope:    request.Scopes,
		}
		src, err = h.ImplicitGranter.GenerateToken(clt, tokenRequest)
	default:
		err = fmt.Errorf("%w: invalid response type: %s", oautherr.ErrInvalidRequest, request.ResponseType)
	}

	enhancer := ChainEnhancer(EnhanceAuthorizationCode, EnhanceImplicit)
	if err = enhancer(request, src, callback); err != nil {
		return WrapAuthRequest(err, "error occurred during enhance request", request, callback)
	}

	if err = clearOriginRequest(session); err != nil {
		return WrapAuthRequest(err, "error occurred during clear origin request", request, callback)
	} else {
		ctx.Redirect(http.StatusMovedPermanently, callback.String())
		return nil
	}
}

// IssueToken 새 토큰을 발행한다.
//
// 정해진 부여 방식에 따라 새 토큰을 발행한다. 발행 흐름에 대한 정보는 [RFC 6749] 문서를 확인
//
// Parameter(application/form-data): [token.Request]
//
// Returns: [token.Response]
//
// [RFC 6749]: https://datatracker.ietf.org/doc/html/rfc6749#section-5
func (h *Handler) IssueToken(ctx *gin.Context) error {
	var request token.Request
	if err := ctx.ShouldBind(&request); err != nil {
		return NewOAuth2Error(oautherr.ErrInvalidRequest, "invalid request")
	}

	clt, exists := security.RetrieveClientAuthentication(ctx)
	if !exists {
		return NewOAuth2Error(oautherr.ErrInvalidClient, "invalid client")
	}

	accessToken, refreshToken, err := h.TokenIssuer.Issue(ctx.Request.Context(), clt, &request)
	if err != nil {
		return WrapTokenRequest(err, "error occurred during generate token", &request)
	}

	res := token.Response{
		Token:     accessToken.Value(),
		T:         token.TypeBearer,
		ExpiresIn: accessToken.ExpiresIn(),
		Scope:     scope.Join(accessToken.Scopes()),
	}
	if refreshToken != nil {
		res.Refresh = refreshToken.Value()
	}

	ctx.JSON(http.StatusOK, res)
	return nil
}

// InspectToken 토큰의 상세 정보를 조회한다.
// 토큰 조회에 대한 자세한 사항은 [RFC 7662] 문서를 참고
//
// Parameter: [token.InspectionRequest]
//
// [RFC 7662] https://datatracker.ietf.org/doc/html/rfc7662#section-2
func (h *Handler) InspectToken(ctx *gin.Context) error {
	var request token.InspectionRequest
	if err := ctx.ShouldBind(&request); err != nil {
		return NewOAuth2Error(oautherr.ErrInvalidRequest, "invalid request")
	}

	if request.Token == "" {
		return NewOAuth2Error(oautherr.ErrInvalidRequest, "token is required")
	}

	if request.TokenTypeHint != token.TypeHintAccessToken &&
		request.TokenTypeHint != token.TypeHintRefreshToken {
		return NewOAuth2Error(oautherr.ErrInvalidRequest, "undefined token type hint")
	}

	requestContext := ctx.Request.Context()
	clt, exists := security.RetrieveClientAuthentication(ctx)
	if !exists {
		return NewOAuth2Error(oautherr.ErrInvalidClient, "invalid client")
	}

	inspection, ok, err := h.TokenService.Inspection(requestContext, clt, &request)
	if err != nil {
		log.Sugared().Errorf("error occurred during token inspection: %v", err)
		return NewOAuth2Error(err, "error occurred during token inspection")
	}
	if !ok {
		return NewOAuth2Error(oautherr.ErrInvalidRequest, "invalid token")
	}

	ctx.JSON(http.StatusOK, inspection)
	return nil
}

// TokenView API을 이용한 토큰 조회시 반환할 엑세스 토큰 구조체
type TokenView struct {
	Value      string    `json:"value"`
	ClientName string    `json:"clientName"`
	Active     bool      `json:"active"`
	Scopes     []string  `json:"scopes"`
	IssuedAt   time.Time `json:"issuedAt"`
	ExpiredAt  time.Time `json:"expiredAt"`
}

func NewTokenView(t *token.AccessToken) TokenView {
	return TokenView{
		Value:      t.Value(),
		ClientName: t.Client().Name(),
		Active:     t.Available(),
		Scopes:     t.Scopes(),
		IssuedAt:   t.Start(),
		ExpiredAt:  t.End(),
	}
}

// ManagementHandler 액세스 토큰을 관리하는 핸들러 구조체
// 현재까지 발급된 자신의 토큰을 조회하거나 삭제하는등의 핸들링 함수가 포함된다.
type ManagementHandler struct {
	TokenService *service.TokenService
}

func (h *ManagementHandler) TokenManagement(ctx *gin.Context) error {
	switch ctx.GetHeader("Accept") {
	case "application/json":
		authentication, _ := web.RetrieveAuthentication(ctx)

		tokens := h.TokenService.GetIssuedTokens(ctx.Request.Context(), authentication.Username)

		var view []TokenView
		for _, t := range tokens {
			view = append(view, NewTokenView(&t))
		}
		if len(view) == 0 {
			view = make([]TokenView, 0)
		}
		ctx.JSON(http.StatusOK, web.NewSuccess(view))
	default:
		ctx.HTML(http.StatusOK, "manage-tokens.html", gin.H{})
	}
	return nil
}

func (h *ManagementHandler) DeleteToken(ctx *gin.Context) error {
	t := ctx.Param("tokenValue")
	authentication, _ := web.RetrieveAuthentication(ctx)

	if err := h.TokenService.DeleteToken(ctx.Request.Context(), authentication, t); err != nil {
		if errors.Is(err, oautherr.ErrInvalidRequest) || errors.Is(err, oautherr.ErrUnauthorized) {
			return web.Wrap(err, web.ErrCodeBadRequest, "찾을 수 없는 엑세스 토큰")
		} else {
			return web.Wrap(err, web.ErrCodeUnknown, "알 수 없는 에러")
		}
	}

	ctx.JSON(http.StatusOK, web.NewSuccess("ok"))
	return nil
}

// storeOriginRequest 인가 요청 전문을 세션에 저장한다.
func storeOriginRequest(s sessions.Session, request *authorization.Request) error {
	serial, err := json.Marshal(request)
	if err != nil {
		log.Sugared().Errorf("error occurred during marshal request: %v", err)
		return oautherr.ErrUnknown
	}
	s.Set(sessionKeyOriginAuthRequest, serial)
	if err = s.Save(); err != nil {
		log.Sugared().Errorf("error occurred during save origin request: %v", err)
		return oautherr.ErrUnknown
	} else {
		return nil
	}
}

// getOriginRequest 세션에 저장된 인가 요청을 가져온다.
func getOriginRequest(s sessions.Session) (*authorization.Request, bool, error) {
	if v, ok := s.Get(sessionKeyOriginAuthRequest).([]byte); ok {
		var request authorization.Request
		if err := json.Unmarshal(v, &request); err != nil {
			log.Sugared().Errorf("error occurred during unmarshal request: %v", err)
			return nil, false, oautherr.ErrUnknown
		}
		return &request, true, nil
	} else {
		return nil, false, nil
	}
}

// clearOriginRequest 세션에서 저장된 인가 요청을 삭제한다.
func clearOriginRequest(s sessions.Session) error {
	s.Delete(sessionKeyOriginAuthRequest)

	if err := s.Save(); err != nil {
		log.Sugared().Errorf("error occurred during save origin request: %v", err)
		return oautherr.ErrUnknown
	} else {
		return nil
	}
}
