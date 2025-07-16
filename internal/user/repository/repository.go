package repository

import (
	"errors"
	"fmt"
	"gorm.io/gorm"
	"oauth-server-go/internal/user/codes"
	"oauth-server-go/internal/user/model"
)

// Gorm gorm을 이용한 저장소
type Gorm struct {
	db *gorm.DB
}

// NewGorm 새 gorm 저장소를 생성한다.
func NewGorm(db *gorm.DB) *Gorm {
	return &Gorm{db: db}
}

// FindByUsername 인자로 받은 유저 아이디를 저장소에서 검색한다.
func (g *Gorm) FindByUsername(u string) (*model.Account, error) {
	var account model.Account
	err := g.db.Where(&model.Account{Username: u}).First(&account).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("%w: %v(%s)", err, codes.ErrAccountNotFound, u)
	}
	return &account, nil
}
