package handler

import (
	"encoding/json"
	"fmt"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"net/http"
	"net/url"
	"oauth-server-go/oauth"
	"oauth-server-go/oauth/entity"
	"oauth-server-go/security"
	"strings"
)

// sessionKeyOriginAuthRequest 인가요청을 세션에 저장할 때 사용하는 키
//
// /authorize 요청이 완료될 때 해당 요청에 사용했던 요청 정보를 세션에 저장한다.
// 저장된 세션은 실제로 토큰을 발행 할 때 사용되며 발급이 완료되면 세션에서 삭제한다.
const sessionKeyOriginAuthRequest = "sessions/originAuthRequest"

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
// 인증에 사용된 요청은 세선에 저장되었다가 실제 토큰을 발행할 때 사용한다.
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

	scopes, err := client.GetScopes(r.SplitScope())
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

	enhancer := chaining(authorizationCodeFlow)
	if err = enhancer(origin, src, to); err != nil {
		return routeWrap(err, origin, to)
	}

	c.Redirect(http.StatusMovedPermanently, to.String())
	return clearOriginRequest(s)
}

// issueToken 토큰을 생성하고 반환한다. 자세한 사항은 [RFC 6749] 문서를 참고
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

func storeOriginRequest(s sessions.Session, r *oauth.AuthorizationRequest) error {
	serial, err := json.Marshal(&r)
	if err != nil {
		return err
	}
	s.Set(sessionKeyOriginAuthRequest, serial)
	return s.Save()
}

func getOriginRequest(s sessions.Session) (*oauth.AuthorizationRequest, error) {
	v := s.Get(sessionKeyOriginAuthRequest)
	if rb, ok := v.([]byte); ok {
		var r oauth.AuthorizationRequest
		err := json.Unmarshal(rb, &r)
		return &r, err
	}
	return nil, nil
}

func clearOriginRequest(s sessions.Session) error {
	s.Delete(sessionKeyOriginAuthRequest)
	return s.Save()
}
