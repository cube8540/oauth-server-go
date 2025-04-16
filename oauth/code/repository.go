package code

import (
	"errors"
	"fmt"
	"gorm.io/gorm"
)

type Repository struct {
	db *gorm.DB
}

func NewRepository(db *gorm.DB) *Repository {
	return &Repository{db: db}
}

func (r *Repository) Save(c *AuthorizationCode) error {
	return r.db.Omit("Scopes.*").Create(c).Error
}

func (r *Repository) FindByCode(code string) (*AuthorizationCode, error) {
	var e AuthorizationCode
	if err := r.db.Preload("Scopes").Where(&AuthorizationCode{Value: code}).First(&e).Error; err != nil {
		switch {
		case errors.Is(err, gorm.ErrRecordNotFound):
			return nil, fmt.Errorf("%w: authroization code(%s)", ErrNotFound, code)
		default:
			return nil, fmt.Errorf("error occurred duraing select authorization code (%s): %w", code, err)
		}
	}
	return &e, nil
}

func (r *Repository) Delete(c *AuthorizationCode) error {
	// GORM 관계 삭제시 연관관계가 끊어지면서 데이터가 삭제된어
	// 그럼으로 스코프를 임시로 저장해놓고 있다가 삭제 완료 후 다시 셋팅한다.
	scopes := c.Scopes
	if err := r.db.Model(c).Association("Scopes").Clear(); err != nil {
		return err
	}
	if err := r.db.Delete(c).Error; err != nil {
		return err
	}
	c.Scopes = scopes
	return nil
}
