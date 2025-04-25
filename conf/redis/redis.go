package redis

type Config struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	MaxIdleSize int    `json:"max_idle_size"`
}
