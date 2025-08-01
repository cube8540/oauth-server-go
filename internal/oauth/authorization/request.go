package authorization

// Request [RFC 6749] 에 정의된 [Authorization Code Grant] 와 [Implicit Grant] 에서 사용할 요청 형태
//
// [RFC 6749]: https://datatracker.ietf.org/doc/html/rfc6749
// [Authorization Code Grant]: https://datatracker.ietf.org/doc/html/rfc6749#section-4.1
// [Implicit Grant]: https://datatracker.ietf.org/doc/html/rfc6749#section-4.2
type Request struct {
	Client              string          `form:"client_id"`
	Username            string          `form:"username"`
	State               string          `form:"state"`
	Redirect            string          `form:"redirect_uri"`
	Scopes              string          `form:"scope"`
	ResponseType        ResponseType    `form:"response_type"`
	CodeChallenge       Challenge       `form:"code_challenge"`
	CodeChallengeMethod ChallengeMethod `form:"code_challenge_method"`
}
