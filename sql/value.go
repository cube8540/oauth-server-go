package sql

import (
	"database/sql/driver"
	"strings"
)

type Strings []string

func (s *Strings) Scan(src any) error {
	val, _ := src.([]byte)
	*s = strings.Split(string(val), ",")
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
