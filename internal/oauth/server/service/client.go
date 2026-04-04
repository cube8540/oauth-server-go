package service

import (
	"oauth-server-go/internal/oauth/client"
	"oauth-server-go/internal/oauth/server/repository"
)

// ClientService 클라이언트 서비스
//
// OAuth2 클라이언트에 대한 관리 포인트를 제공한다.
type ClientService struct {
	repo repository.ClientRepository
}

func NewClientService(repo repository.ClientRepository) *ClientService {
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
