package user

import (
	"errors"
	"gorm.io/gorm"
	"oauth-server-go/conf"
)

func FindAccountByUsername(username string) (*Account, error) {
	db := conf.GetDB()

	var entity AccountEntity
	err := db.Where(&AccountEntity{Username: username}).First(&entity).Error

	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}

	if err != nil {
		return nil, err
	}

	return entity.ToDomain(), nil
}
