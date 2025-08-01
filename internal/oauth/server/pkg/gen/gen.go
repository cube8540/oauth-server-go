package gen

import "github.com/google/uuid"

// GenerateRandomUUID 새 UUID를 생성한다.
func GenerateRandomUUID() string {
	return uuid.New().String()
}
