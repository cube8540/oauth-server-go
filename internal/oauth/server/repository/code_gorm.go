package repository

import (
	"context"
	"errors"
	"fmt"
	"gorm.io/gorm"
	"oauth-server-go/internal/config/log"
	"oauth-server-go/internal/oauth/authorization"
	oautherr "oauth-server-go/internal/oauth/errors"
	"oauth-server-go/pkg/array"
	"slices"
)

// FindAuthCodeByValue Gorm을 이용하여 데이터베이스에서 인가 코드를 조회한다.
//
// Returns:
//   - *AuthorizationCode: 조회된 인가 코드 모델
//   - bool: 조회 성공 여부
func FindAuthCodeByValue(ctx context.Context, db *gorm.DB, value string) (*AuthorizationCode, bool) {
	var cd AuthorizationCode
	if err := db.WithContext(ctx).Preload("Scopes").Where(&AuthorizationCode{Value: value}).First(&cd).Error; err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			log.Sugared().Errorf("error occurred during select code(%s): %v", value, err)
		}
		return nil, false
	}
	return &cd, true
}

// SaveAuthCode Gorm을 이용하여 데이터베이스에 인가 코드를 저장한다.
func SaveAuthCode(ctx context.Context, db *gorm.DB, code *AuthorizationCode) error {
	return db.WithContext(ctx).Omit("Scopes.*").Create(code).Error
}

// DeleteAuthCode Gorm을 이용해 데이터베이스에서 인가 코드를 삭제한다.
func DeleteAuthCode(ctx context.Context, db *gorm.DB, code *AuthorizationCode) error {
	// GORM Many2Many의 관계를 해제시 인스턴스의 연관 데이터가 초기화 되어 빈 슬라이스로 저장된다.
	// 그럼으로 스코프를 임시로 저장하고 있다가 DELETE 쿼리 완료 후 인스턴스에 다시 스코프를 저장하여 인자의 무결성을 유지한다.
	scopes := code.Scopes
	if err := db.WithContext(ctx).Model(code).Association("Scopes").Clear(); err != nil {
		return fmt.Errorf("%w: error occurred during clear scopes(%s): %v", oautherr.ErrUnknown, code.Value, err)
	}
	if err := db.WithContext(ctx).Delete(code).Error; err != nil {
		return fmt.Errorf("%w: error occurred during delete code(%s): %v", oautherr.ErrUnknown, code.Value, err)
	}
	code.Scopes = scopes
	return nil
}

// AuthCodeGormBride OAuth2 인가 코드 도메인을 Gorm을 이용해 데이터베이스에 CRUD 할 수 있도록 변환 및 연결 작업을 하는 객체
type AuthCodeGormBride struct {
	db *gorm.DB
}

func NewAuthCodeGormBride(db *gorm.DB) *AuthCodeGormBride {
	return &AuthCodeGormBride{db: db}
}

// FindByValue Gorm을 이용해 데이터베이스에서 인가 코드를 조회하고 이를 도메인 모델로 변환하여 반환한다.
//
// Returns:
//   - *authorization.Code: 조회된 인가 코드 도메인 모델
//   - bool: 조회 성공 여부
func (b *AuthCodeGormBride) FindByValue(ctx context.Context, value string) (*authorization.Code, bool) {
	if codeModel, ok := FindAuthCodeByValue(ctx, b.db, value); ok {
		return codeModel.Domain(), true
	} else {
		return nil, false
	}
}

// Save Gorm을 이용해 데이터베이스에 인가 코드를 저장한다.
func (b *AuthCodeGormBride) Save(ctx context.Context, cd *authorization.Code) error {
	clientModel, ok := FindClientByClientID(ctx, b.db, cd.Client().Id())
	if !ok {
		return fmt.Errorf("%w: client(%s) not found", oautherr.ErrInvalidClient, cd.Client().Id())
	}

	scopes := array.FilterFunc(clientModel.Scopes, func(s Scope) bool {
		return slices.Contains(cd.Scopes(), s.Code)
	})

	authCodeModel := &AuthorizationCode{
		Value:               cd.Value(),
		ClientID:            clientModel.ID,
		Username:            cd.Username(),
		State:               cd.State(),
		Redirect:            cd.Redirect(),
		Scopes:              scopes,
		CodeChallenge:       cd.CodeChallenge(),
		CodeChallengeMethod: cd.CodeChallengeMethod(),
		IssuedAt:            cd.Start(),
		ExpiredAt:           cd.End(),
	}

	return SaveAuthCode(ctx, b.db, authCodeModel)
}

// Delete Gorm을 이용하여 데이터베이스에서 인가 코드를 삭제한다.
func (b *AuthCodeGormBride) Delete(ctx context.Context, auth *authorization.Code) error {
	if authCodeModel, ok := FindAuthCodeByValue(ctx, b.db, auth.Value()); ok {
		return DeleteAuthCode(ctx, b.db, authCodeModel)
	} else {
		return fmt.Errorf("%w: authoziation code(%s) not found", oautherr.ErrUnknown, auth.Value())
	}
}
