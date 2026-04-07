package service

import (
	"context"
	"oauth-server-go/internal/oauth/scope"
	"oauth-server-go/internal/oauth/server/repository"
)

// ScopeService 스코프 서비스
//
// 스코프의 관리 포인트를 제공한다.
type ScopeService struct {
	repo repository.ScopeRepository
}

func NewScopeService(repo repository.ScopeRepository) *ScopeService {
	return &ScopeService{repo: repo}
}

// Retrieve 스코프들을 조회한다.
func (srv *ScopeService) Retrieve(ctx context.Context, value ...string) []scope.Scope {
	return srv.repo.FindByValue(ctx, value...)
}
