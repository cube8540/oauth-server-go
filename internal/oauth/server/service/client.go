package service

import "oauth-server-go/internal/oauth/client"

// ClientRepository 클라이언트 저장소
type ClientRepository interface {

	// FindByClientID 저장소에서 클라이언트를 조회 한다.
	//
	// Returns:
	//	 - *client.Client: 조회된 클라이언트
	//	 - bool: 조회 성공 여부
	FindByClientID(clientID string) (*client.Client, bool)
}

// ClientService 클라이언트 서비스
//
// OAuth2 클라이언트에 대한 관리 포인트를 제공한다.
type ClientService struct {
	repo ClientRepository
}

func NewClientService(repo ClientRepository) *ClientService {
	return &ClientService{repo: repo}
}

// Retrieve 저장소에서 클라이언트를 조회하여 반환한다.
//
// Returns:
//   - *client.Client: 조회된 클라이언트
//   - bool: 조회 성공 여부
func (srv *ClientService) Retrieve(clientID string) (*client.Client, bool) {
	return srv.repo.FindByClientID(clientID)
}
