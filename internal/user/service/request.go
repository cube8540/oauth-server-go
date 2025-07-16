package service

// AuthenticationRequest 회원의 인증 요청 구조체
type AuthenticationRequest struct {
	Username string `json:"username" form:"username"`
	Password string `json:"password" form:"password"`
}

// Principal 인증된 회원의 정보를 저장하는 구조체
type Principal struct {
	Username string
}

// NewPrincipal 새 인증 인스턴스를 생성한다.
func NewPrincipal(u string) *Principal {
	return &Principal{Username: u}
}
