package service

import (
	"oauth-server-go/internal/oauth/authorization"
	"oauth-server-go/internal/oauth/client"
	"oauth-server-go/internal/oauth/server/pkg/gen"
	"oauth-server-go/internal/oauth/server/repository"
)

// AuthCodeService 인가 코드 서비스
//
// OAuth2 인가 코드에 대한 관리 포인트를 제공하여
// 새 인가 코드 생성 및 조회, 삭제 등을 작업한다.
type AuthCodeService struct {
	repo repository.AuthCodeRepository
}

func NewAuthCodeService(repo repository.AuthCodeRepository) *AuthCodeService {
	return &AuthCodeService{repo: repo}
}

// NewCode 새 OAuth2 인가 코드를 생성하여 저장소에 저장한다.
//
// Parameters:
//   - c: 새 인가 코드를 생성을 요청한 클라이언트
//   - request: 인가 코드 요청 전문
func (srv *AuthCodeService) NewCode(c *client.Client, request *authorization.Request) (*authorization.Code, error) {
	newCode := authorization.NewCode(c, gen.GenerateRandomUUID)
	if err := newCode.CopyFrom(request); err != nil {
		return nil, err
	}
	if err := srv.repo.Save(newCode); err != nil {
		return nil, err
	}
	return newCode, nil
}

// Consume 저장소에서 주어진 인가 코드를 조회한다. 조회된 인가코드는 반환 전 삭제한다.
//
// Returns:
//   - *authorization.Code: 조회/삭제된 인가 코드
//   - bool: 조회 성공 여부
//   - error: 삭제 중 발생한 에러
func (srv *AuthCodeService) Consume(cd string) (*authorization.Code, bool, error) {
	code, ok := srv.repo.FindByValue(cd)
	if !ok {
		return nil, false, nil
	}
	if err := srv.repo.Delete(code); err != nil {
		return nil, false, err
	}
	return code, true, nil
}
