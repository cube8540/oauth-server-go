package authorization

// Challenge OAuth2 인증 코드 사용(교환) 때 인증에 사용될 코드 [RFC 7636]
//
// [RFC 7636]: https://datatracker.ietf.org/doc/html/rfc7636
type Challenge string

// ChallengeMethod [Challenge] 인코딩 방법 [RFC 7636]
//
// [RFC 7636]: https://datatracker.ietf.org/doc/html/rfc7636
type ChallengeMethod string

// [ChallengeMethod] 열거형 정의 "plain"과 "S256"이 있다.
//
// ChallengeMethod가 plain인 경우 code_verifier를 검사 할 때 입력 받은 값을 그대로 사용하여 검사하며,
// S256인 경우 SHA256 인코딩을 하여 검사하게 된다. 자세한 정보는 [RFC 7636] 을 참고
//
// [RFC 7636]: https://datatracker.ietf.org/doc/html/rfc7636#section-4.2
const (
	ChallengePlan ChallengeMethod = "plain"
	ChallengeS256 ChallengeMethod = "S256"
)

// Verifier 인가코드(authorization_code) 발급에 사용된 [Challenge]
type Verifier string

// ResponseType 인가 요청의 응답 방식을 결정할 코드
type ResponseType string

const (
	ResponseTypeCode  ResponseType = "code"
	ResponseTypeToken ResponseType = "token"
)
