package service

import "oauth-server-go/internal/oauth/scope"

// ScopeRepository 스코프 저장소
type ScopeRepository interface {

	// FindByValue 저장소에서 스코프들을 조회한다.
	FindByValue(value ...string) []scope.Scope
}

// ScopeService 스코프 서비스
//
// 스코프의 관리 포인트를 제공한다.
type ScopeService struct {
	repo ScopeRepository
}

func NewScopeService(repo ScopeRepository) *ScopeService {
	return &ScopeService{repo: repo}
}

// Retrieve 스코프들을 조회한다.
func (srv *ScopeService) Retrieve(value ...string) []scope.Scope {
	return srv.repo.FindByValue(value...)
}
