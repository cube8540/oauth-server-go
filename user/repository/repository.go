package repository

import (
	"gorm.io/gorm"
	"oauth-server-go/user/entity"
)

type AccountRepository struct {
	db *gorm.DB
}

func NewAccountRepository(db *gorm.DB) *AccountRepository {
	return &AccountRepository{
		db: db,
	}
}

func (r AccountRepository) FindByUsername(u string) (*entity.Account, error) {
	var account entity.Account
	err := r.db.Where(&entity.Account{Username: u}).First(&account).Error
	if err != nil {
		return nil, err
	}
	return &account, nil
}
