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
	"oauth-server-go/oauth"
	"oauth-server-go/oauth/entity"
	"oauth-server-go/protocol"
	"oauth-server-go/security"
	"strings"
)

// sessionKeyOriginAuthRequest 인가요청을 세션에 저장할 때 사용하는 키
//
// /authorize 요청이 완료될 때 해당 요청에 사용했던 요청 정보를 세션에 저장한다.
// 저장된 세션은 실제로 토큰을 발행 할 때 사용되며 발급이 완료되면 세션에서 삭제한다.
const sessionKeyOriginAuthRequest = "sessions/originAuthRequest"

// h OAuth 2.0 프로토콜의 주요 엔드포인트를 처리하는 핸들러 구조체
// 이 구조체는 OAuth 서버의 모든 주요 기능(인가 요청, 토큰 발급, 토큰 검증 등)을 처리하는 함수들을 포함하고 있다.
type h struct {
	// clientRetriever OAuth 클라이언트의 아이디를 받아 조회한다.
	clientRetriever func(id string) (*entity.Client, error)

	// requestConsumer response_type에 따라 인가 코드나 토큰을 생성하여 반환한다.
	// 각 응답 처리에 대한 사항은 [RFC 6749] 문단의 [4.1.2], [4.2.2] 를 참고한다.
	//
	// [RFC 6749]: https://datatracker.ietf.org/doc/html/rfc6749#section-4
	// [4.1.2]: https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2
	// [4.2.2]: https://datatracker.ietf.org/doc/html/rfc6749#section-4.2.2
	requestConsumer func(c *entity.Client, request *oauth.AuthorizationRequest) (any, error)

	// tokenIssuer 요청에 따라 토큰을 발행한다.
	// 각 요청에 따른 토큰 발행은 [RFC 6749] 문단의 [4.1.4], [4.3.3], [4.4.3] 을 참고 한다.
	//
	// [RFC 6749]: https://datatracker.ietf.org/doc/html/rfc6749#section-4
	// [4.1.4]: https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.4
	// [4.3.3]: https://datatracker.ietf.org/doc/html/rfc6749#section-4.3.3
	// [4.4.3]: https://datatracker.ietf.org/doc/html/rfc6749#section-4.4.3
	tokenIssuer func(c *entity.Client, r *oauth.TokenRequest) (*entity.Token, *entity.RefreshToken, error)

	// introspector 토큰의 상세 정보를 질의 한다. 요청과 응답 폼은 [RFC 7662] 의 [2.1], [2.2] 문단을 참고
	//
	// [RFC 7662]: https://datatracker.ietf.org/doc/html/rfc7662#section-2
	// [2.1]: https://datatracker.ietf.org/doc/html/rfc7662#section-2.1
	// [2.2]: https://datatracker.ietf.org/doc/html/rfc7662#section-2.2
	introspector func(c *entity.Client, r *oauth.IntrospectionRequest) (*oauth.Introspection, error)
}

// authorize OAuth2의 [Authorization Code Grant] 와 [Implicit Grant] 의 Authorization Request 구현 핸들러
// 인증에 사용된 요청은 세션에 저장되었다가 실제 토큰을 발행할 때 사용한다.
//
// 주요 요청 파라미터:
//   - client_id: 필수, 클라이언트 식별자
//   - response_type: 필수, "code" 또는 "token" 값
//   - redirect_uri: 선택, 인가 완료 후 리다이렉트할 URI
//   - scope: 선택, 요청하는 접근 범위
//   - state: 선택, CSRF 방지 및 상태 유지를 위한 값
//
// 처리 흐름:
//  1. 요청 검증 (필수 파라미터 확인, 클라이언트 존재 확인)
//  2. 리다이렉트 URI 유효성 검증
//  3. 요청 정보를 세션에 저장
//  4. 사용자 승인 페이지 표시
//
// [Authorization Code Grant]: https://datatracker.ietf.org/doc/html/rfc6749#section-4.1
// [Implicit Grant]: https://datatracker.ietf.org/doc/html/rfc6749#section-4.2
func (h h) authorize(c *gin.Context) error {
	var r oauth.AuthorizationRequest
	if err := c.ShouldBindQuery(&r); err != nil {
		return err
	}
	if r.ClientID == "" {
		return oauth.NewErr(oauth.ErrInvalidRequest, "client id is required")
	}

	client, err := h.clientRetriever(r.ClientID)
	if errors.Is(err, oauth.ErrClientNotFound) {
		return oauth.NewErr(oauth.ErrInvalidClient, "client is not found")
	}
	if err != nil {
		return err
	}

	redirect, err := client.RedirectURL(r.Redirect)
	if err != nil {
		return err
	}
	to, _ := url.Parse(redirect)
	if r.ResponseType == "" {
		return routeWrap(oauth.NewErr(oauth.ErrInvalidRequest, "require parameter is missing"), &r, to)
	}
	if r.ResponseType != oauth.ResponseTypeCode && r.ResponseType != oauth.ResponseTypeToken {
		return routeWrap(oauth.NewErr(oauth.ErrUnsupportedResponseType, "unsupported"), &r, to)
	}

	scopes, err := client.Scopes.GetAll(oauth.SplitScope(r.Scopes))
	if err != nil {
		return routeWrap(err, &r, to)
	}
	c.HTML(http.StatusOK, "approval.html", gin.H{
		"scopes": scopes,
		"client": client.Name,
	})
	s := sessions.Default(c)
	return storeOriginRequest(s, &r)
}

// approval 리소스 소유자의 승인이 완료 되어 인가 코드나 토큰을 생성하고 지정된 URL로 리다이렉트 한다.
// 요청값으로 사용자가 허용한 스코프를 리스트로 받으며 그 외의 필요한 값들은 기존에 HTTP GET: /authorize 요청에서 사용한 요청을 세션에서 꺼내어 사용한다.
//
// 처리 흐름:
//  1. 세션에서 원래 인가 요청 정보 복원
//  2. 클라이언트 정보 검증
//  3. 사용자 승인 스코프 수집
//  4. response_type에 따라 인가 코드 또는 토큰 생성
//  5. 리다이렉트 URI로 결과와 함께 리다이렉트
//  6. 세션에서 원래 요청 정보 삭제
//
// [Authorization Code Grant]: https://datatracker.ietf.org/doc/html/rfc6749#section-4.1
// [Implicit Grant]: https://datatracker.ietf.org/doc/html/rfc6749#section-4.2
func (h h) approval(c *gin.Context) error {
	s := sessions.Default(c)
	origin, err := getOriginRequest(s)
	if err != nil {
		return err
	}
	if origin == nil {
		return oauth.NewErr(oauth.ErrInvalidRequest, "origin request is not found")
	}
	client, err := h.clientRetriever(origin.ClientID)
	if errors.Is(err, oauth.ErrClientNotFound) {
		return oauth.NewErr(oauth.ErrInvalidClient, "client is not found")
	}
	if err != nil {
		fmt.Printf("%v", err)
		return oauth.NewErr(oauth.ErrServerError, "unknown error")
	}

	redirect, _ := client.RedirectURL(origin.Redirect)
	to, _ := url.Parse(redirect)

	loginValue, _ := c.Get(security.SessionKeyLogin)
	if login, ok := loginValue.(*security.SessionLogin); ok {
		origin.Username = login.Username
	}

	rs := c.PostFormArray("scope")
	if len(rs) == 0 {
		return routeWrap(oauth.NewErr(oauth.ErrInvalidScope, "resource owner denied access"), origin, to)
	}
	origin.Scopes = strings.Join(rs, " ")

	src, err := h.requestConsumer(client, origin)
	if err != nil {
		return routeWrap(err, origin, to)
	}

	enhancer := chaining(authorizationCodeFlow, implicitFlow)
	if err = enhancer(origin, src, to); err != nil {
		return routeWrap(err, origin, to)
	}

	c.Redirect(http.StatusMovedPermanently, to.String())
	return clearOriginRequest(s)
}

// issueToken 토큰을 생성하고 반환한다. 자세한 사항은 [RFC 6749] 문서를 참고
//
// 지원하는 grant_type:
//   - authorization_code: 인가 코드를 토큰으로 교환
//   - refresh_token: 갱신 토큰으로 새로운 액세스 토큰 발급
//   - password: 리소스 소유자 비밀번호 자격증명
//   - client_credentials: 클라이언트 자격증명
//
// 주요 응답 형식:
//   - access_token: 액세스 토큰
//   - token_type: 토큰 유형 (Bearer)
//   - expires_in: 토큰 만료 시간(초)
//   - refresh_token: 갱신 토큰(선택)
//   - scope: 승인된 스코프
//
// [RFC 6749]: https://datatracker.ietf.org/doc/html/rfc6749#section-5
func (h h) issueToken(c *gin.Context) error {
	var r oauth.TokenRequest
	if err := c.Bind(&r); err != nil {
		return err
	}
	clientValue, _ := c.Get(oauth2ShareKeyAuthClient)
	token, refresh, err := h.tokenIssuer(clientValue.(*entity.Client), &r)
	if err != nil {
		return err
	}
	if token == nil {
		return oauth.NewErr(oauth.ErrServerError, "token cannot issued")
	}
	var scopes []string
	for _, s := range token.Scopes {
		scopes = append(scopes, s.Code)
	}
	res := oauth.TokenResponse{
		Token:     token.Value,
		Type:      oauth.TokenTypeBearer,
		ExpiresIn: token.InspectExpiredAt(),
		Scope:     token.InspectScope(),
	}
	if refresh != nil {
		res.Refresh = refresh.Value
	}
	c.JSON(http.StatusOK, res)
	return nil
}

// introspection 입력 받은 토큰의 상세 정보를 질의 하여 반환한다. 자세한 사항은 [RFC 7662] 참고
//
// 요청 파라미터:
//   - token: 필수, 검증할 토큰 값
//   - token_type_hint: 선택, 토큰 유형 힌트 (access_token 또는 refresh_token)
//
// 응답 필드:
//   - active: 토큰의 활성화 여부
//   - scope: 토큰에 부여된 스코프
//   - client_id: 토큰이 발급된 클라이언트 ID
//   - username: 토큰이 발급된 사용자 이름
//   - exp: 토큰 만료 시간
//
// [RFC 7662]: https://datatracker.ietf.org/doc/html/rfc7662#section-2
func (h h) introspection(c *gin.Context) error {
	var r oauth.IntrospectionRequest
	if err := c.Bind(&r); err != nil {
		return err
	}
	if r.Token == "" {
		return oauth.NewErr(oauth.ErrInvalidRequest, "token is required")
	}
	clientValue, _ := c.Get(oauth2ShareKeyAuthClient)
	intro, err := h.introspector(clientValue.(*entity.Client), &r)
	if err != nil {
		return err
	}
	c.JSON(http.StatusOK, intro)
	return nil
}

// TokenManagementService 사용자에게 발급된 토큰을 관리하기 위한 인터페이스
// 사용자 토큰의 조회 및 삭제 기능을 제공한다.
type TokenManagementService interface {

	// GetGrantedTokens 특정 사용자에게 발급된 모든 토큰을 조회한다.
	GetGrantedTokens(username string) ([]entity.Token, error)

	// Delete 특정 토큰을 삭제한다.
	Delete(c context.Context, t string) error
}

// m 토큰 관리 핸들러 구조체이다.
// 사용자 토큰의 조회 및 관리 기능을 제공한다.
type m struct {
	service TokenManagementService
}

// tokenManagement 사용자에게 발급된 모든 토큰을 조회하여 표시한다.
// Accept 헤더가 "application/json"인 경우 JSON 형식으로 응답하고, 그렇지 않은 경우 HTML 토큰 관리 페이지를 표시한다.
func (m m) tokenManagement(c *gin.Context) error {
	switch c.GetHeader("Accept") {
	case "application/json":
		loginValue, _ := c.Get(security.SessionKeyLogin)
		login, _ := loginValue.(*security.SessionLogin)

		tokens, err := m.service.GetGrantedTokens(login.Username)
		if err != nil {
			return appErrWrap(err)
		}

		var details []TokenDetails
		for _, token := range tokens {
			details = append(details, NewTokenDetails(&token))
		}
		if len(details) == 0 {
			details = make([]TokenDetails, 0)
		}
		c.JSON(http.StatusOK, protocol.NewOK(details))
		return nil
	default:
		c.HTML(http.StatusOK, "manage-tokens.html", gin.H{})
		return nil
	}
}

// deleteToken 특정 토큰을 삭제한다.
// URL 파라미터로 삭제할 토큰 값을 받는다.
func (m m) deleteToken(c *gin.Context) error {
	tokenValue := c.Param("tokenValue")
	if err := m.service.Delete(c, tokenValue); err != nil {
		return appErrWrap(err)
	}
	c.JSON(http.StatusOK, protocol.NewOK("ok"))
	return nil
}

// storeOriginRequest 인가 요청 정보를 세션에 저장한다.
//
//	s: 세션 객체
//	r: 저장할 인가 요청 정보
func storeOriginRequest(s sessions.Session, r *oauth.AuthorizationRequest) error {
	serial, err := json.Marshal(&r)
	if err != nil {
		return err
	}
	s.Set(sessionKeyOriginAuthRequest, serial)
	return s.Save()
}

// getOriginRequest 세션에서 인가 요청 정보를 가져온다.
//
//	s: 세션 객체
func getOriginRequest(s sessions.Session) (*oauth.AuthorizationRequest, error) {
	v := s.Get(sessionKeyOriginAuthRequest)
	if rb, ok := v.([]byte); ok {
		var r oauth.AuthorizationRequest
		err := json.Unmarshal(rb, &r)
		return &r, err
	}
	return nil, nil
}

// clearOriginRequest 세션에서 인가 요청 정보를 삭제한다.
//
//	s: 세션 객체
func clearOriginRequest(s sessions.Session) error {
	s.Delete(sessionKeyOriginAuthRequest)
	return s.Save()
}

// appErrWrap OAuth 관련 오류를 애플리케이션 오류로 변환한다.
// 여러 OAuth 관련 오류를 적절한 HTTP 상태 코드와 메시지로 변환한다.
func appErrWrap(err error) error {
	switch {
	case errors.Is(err, oauth.ErrClientNotFound):
		return protocol.Wrap(err, protocol.ErrCodeBadRequest, "client is not found")
	case errors.Is(err, oauth.ErrTokenNotFound):
		return protocol.Wrap(err, protocol.ErrCodeBadRequest, "token is not found")
	case errors.Is(err, oauth.ErrUnauthorized):
		return protocol.Wrap(err, protocol.ErrCodeUnauthorized, "unauthorized")
	case errors.Is(err, oauth.ErrAuthorizationCodeNotFound):
		return protocol.Wrap(err, protocol.ErrCodeBadRequest, "authorization code is not found")
	default:
		return protocol.Wrap(err, protocol.ErrCodeUnknown, "internal server error")
	}
}
