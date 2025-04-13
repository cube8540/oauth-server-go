## OAuth2 권한 서버
기존에 한번 구현했었던 [OAuth2 권한 서버](https://github.com/cube8540/oauth-server)를 Go 언어로 포팅한 프로젝트

### 구조
    ├── conf                    # 프로젝트 설정 패키지
    │   ├── conf.go
    │   └── conf.<env>.json     # 환경별 설정 json
    │
    ├── crypto                  # 암호화/해싱 관련 패키지
    ├── <domain>
    │   ├── entity              # 도메인 엔티티 패키지
    │   ├── handler             # API 엔드 포인트 패키지
    │   ├── repository          # 엔티티 저장소 패키지
    │   ├── service             # 서비스 레이어 패키지
    │   └── .....
    │
    ├── protocol                # 어플리케이션에서 사용할 요청/응답 정의 패키지
    ├── security                # 세션 및 로그인 관련 패키지
    ├── sql                     # GORM 커스텀 데이터 타입 정의 패키지
    └── web                     # HTML/CSS/JS 정적 파일 디렉토리

### 환경
- Go 1.24
- Gin 1.10.0
- GORM 1.25.12
- PostgreSQL 17.4
- Redis 7.4.2

### 설정
/conf/conf.<env>.json에 아래와 같은 형식으로 설정 파일을 생성합니다. 
현재 데이터베이스는 PostgreSQL을 사용하고 있으며, 세션은 Redis를 통해 유지중입니다.
```
{
  "port": ":8080",                                      # 사용하고자 하는 포트
  "session": {                                          # 세션 설정
    "secret": "<secret>",
    "max_age_sec": 3600
  },
  "db": {
    "host": "localhost",
    "port": 5432,
    "username": "postgres",
    "password": "password",
    "dbname": "dbname",
    "max_idle_size": 25,
    "max_open_size": 20
  },
  "redis": {
    "host": "localhost",
    "port": 6379,
    "max_idle_size": 20
  }
}
```

## OAuth2 API
[토큰 부여 API](./OAUTH2.md)