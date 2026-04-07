package auth

// SimpleAuthenticate 사용자의 아이디와 패스워드를 받아 로그인을 실행한다.
// 로그인이 성공하였을 경우 true를 반환한다.
type SimpleAuthenticate func(id, pw string) (bool, error)
