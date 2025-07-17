package redis

// Config 레디스 연결 설정
type Config struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	MaxIdleSize int    `json:"max_idle_size"`
}
