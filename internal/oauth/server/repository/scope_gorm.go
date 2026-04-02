package repository

import (
	"gorm.io/gorm"
	"oauth-server-go/internal/config/log"
	"oauth-server-go/internal/oauth/scope"
	"oauth-server-go/pkg/array"
)

// dummy 테이블명을 가져오기 위한 더미 데이터
// 테이블명을 얻어오는 작업 외에 다른 용도로 사용해서는 안된다.
var dummy = Scope{}

// FindScopeByValue Gorm을 이용하여 데이터베이스에서 스코프들을 조회해 반환한다.
func FindScopeByValue(db *gorm.DB, value ...string) []Scope {
	var scopes []Scope
	if err := db.Where(dummy.TableName()+".code IN (?)", value).Find(&scopes).Error; err != nil {
		log.Sugared().Errorf("error occurred during select scope(%v): %v", value, err)
	}
	return scopes
}

// ScopeGormBridge Gorm을 이용해 스코프를 데이터베이스에 CRUD 할 수 있도록 변환 및 연결 작업을 하는 객체
type ScopeGormBridge struct {
	db *gorm.DB
}

func NewScopeGormBridge(db *gorm.DB) *ScopeGormBridge {
	return &ScopeGormBridge{db: db}
}

// FindByValue 데이터베이스에서 스코프들을 조회한다.
func (b *ScopeGormBridge) FindByValue(value ...string) []scope.Scope {
	scopes := FindScopeByValue(b.db, value...)
	return array.Map(scopes, func(s Scope) scope.Scope {
		return scope.Scope{
			Code: s.Code,
			Name: s.Name,
			Desc: s.Desc,
		}
	})
}
