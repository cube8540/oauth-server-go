package client

import (
	"fmt"
	oautherr "oauth-server-go/internal/oauth/errors"
)

// Retriever OAuth2 클라이언트 검색 인터페이스
type Retriever interface {
	// FindByClientID 인자로 받은 클라이언트 아이디로 OAuth2 클라이언트를 검색하여 반환한다.
	//
	// Returns:
	//	 - *Client: 클라이언트
	//	 - bool: 조회 성공 여부
	FindByClientID(clientID string) (*Client, bool)
}

// CompareSecret 클라이언트 인증을 위한 패스워드 비교 함수
//
// source는 클라이언트에 저장된 해싱된 패스워드이며 input은 외부에서 입력 받은 클라이언트의 패스워드이다.
// input이 source와 일치한지 여부를 반환한다.
type CompareSecret func(source, input string) (bool, error)

// AuthenticationProvider 클라이언트 인증을 제공하는 구조체
type AuthenticationProvider struct {
	retriever Retriever
	compare   CompareSecret
}

func NewAuthenticationProvider(retriever Retriever, compare CompareSecret) *AuthenticationProvider {
	return &AuthenticationProvider{retriever: retriever, compare: compare}
}

// Authenticate 클라이언트의 아이디와 비밀번호를 받아 인증을 진행한다.
// 인증 완료시 인증된 클라이언트의 정보를 반환하며, 인증 실패시 에러를 반환한다.
func (a *AuthenticationProvider) Authenticate(id, secret string) (*Client, error) {
	if id == "" {
		return nil, fmt.Errorf("%w: id", oautherr.ErrMissingParameter)
	}

	c, ok := a.retriever.FindByClientID(id)
	if !ok {
		return nil, fmt.Errorf("%w: client could not find: %s", oautherr.ErrInvalidClient, id)
	}

	if c.T() == TypePublic {
		return c, nil
	}

	if secret == "" {
		return nil, fmt.Errorf("%w: secret", oautherr.ErrMissingParameter)
	}

	if eq, err := a.compare(c.Secret(), secret); !eq || err != nil {
		msg := fmt.Sprintf("client(%s) secret is not matched", id)
		if err != nil {
			msg = fmt.Sprintf("%s: %v", msg, err)
		}
		return nil, fmt.Errorf("%w: %s", oautherr.ErrInvalidClient, msg)
	}

	return c, nil
}
