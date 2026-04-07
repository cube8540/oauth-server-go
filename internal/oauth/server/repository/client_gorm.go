package repository

import (
	"context"
	"errors"
	"gorm.io/gorm"
	"oauth-server-go/internal/config/log"
	"oauth-server-go/internal/oauth/client"
)

const clientCacheName = "oauth/server/repository/client_gorm/client"

type clientCache struct {
	client map[string]*Client
}

func WithClientCaching(ctx context.Context) context.Context {
	if _, ok := ctx.Value(clientCacheName).(*clientCache); ok {
		return ctx
	}
	cache := clientCache{client: make(map[string]*Client)}
	return context.WithValue(ctx, clientCacheName, &cache)
}

// FindClientByClientID Gorm을 이용하여 데이터베이스에서 클라이언트를 조회한다.
//
// Returns:
//   - *Client: 조회된 클라이언트 모델
//   - bool: 조회 성공 여부
func FindClientByClientID(ctx context.Context, db *gorm.DB, id string) (*Client, bool) {
	cache, caching := ctx.Value(clientCacheName).(*clientCache)
	if caching {
		if ctl, ok := cache.client[id]; ok {
			return ctl, true
		}
	}
	var c Client
	if err := db.WithContext(ctx).Preload("Scopes").Where(&Client{ClientID: id}).First(&c).Error; err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			log.Sugared().Errorf("error occurred during select client(%s): %v", id, err)
		}
		return nil, false
	}
	if caching {
		cache.client[id] = &c
	}
	return &c, true
}

// ClientGormBridge OAuth2 클라이언트 도메인을 Gorm을 이용해 데이터베이스에 CRUD 할 수 있도록 변환 및 연결 작업을 하는 객체
type ClientGormBridge struct {
	db *gorm.DB
}

func NewClientGormBridge(db *gorm.DB) *ClientGormBridge {
	return &ClientGormBridge{db: db}
}

// FindByClientID Gorm을 이용해 데이터베이스에서 클라이언트를 조회하고 이를 도메인 객체로 변경하여 반환한다.
//
// Returns:
//   - *client.Client: 조회된 클라이언트 도메인 모델
//   - bool: 조회 성공 여부
func (b *ClientGormBridge) FindByClientID(ctx context.Context, id string) (*client.Client, bool) {
	if clientModel, ok := FindClientByClientID(ctx, b.db, id); ok {
		return clientModel.Domain(), true
	} else {
		return nil, false
	}
}
