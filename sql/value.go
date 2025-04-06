package sql

import (
	"database/sql/driver"
	"errors"
	"strings"
)

// Strings 1개 이상의 문자열을 가진 데이터 타입
// 각 문자열은 콤마(,)로 구분되며 SQL text 타입 컬럼에 매칭된다.
type Strings []string

func (s *Strings) Scan(src any) error {
	var val string
	switch src.(type) {
	case []byte:
		val = string(src.([]byte))
	case string:
		val = src.(string)
	default:
		return errors.New("val cannot casting")
	}
	*s = strings.Split(val, ",")
	return nil
}

func (s Strings) Value() (driver.Value, error) {
	if len(s) == 0 {
		return nil, nil
	}
	return []byte(strings.Join(s, ",")), nil
}

func (s Strings) GormDataType() string {
	return "text"
}
