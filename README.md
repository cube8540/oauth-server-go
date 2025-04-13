# 🛡️ OAuth Server (Go)

이 프로젝트는 [RFC 6749 (OAuth 2.0)](https://datatracker.ietf.org/doc/html/rfc6749)에 정의된 인증 프로토콜을 기반으로 구현된 OAuth2 인증 서버입니다.   
Go 언어 학습을 목적으로 제작되었으며, 로그인 및 토큰 발급 기능을 중점으로 다룹니다.

---

## 🚀 Features

- [OAuth2 인증 서버 구현](./OAUTH2.md)
- 액세스 토큰 발급 (RFC 6749 기반)
- 사용자 로그인 기능

---

## 🛠️ Tech Stack

- **Language**: Go 1.24
- **Web Framework**: [Gin](https://github.com/gin-gonic/gin) 1.10.0
- **ORM**: [GORM](https://gorm.io/) 1.25.12

---

## 📦 Getting Started

프로젝트 실행에 필요한 **설정 방법**과 **폴더 구조**는 아래 항목을 참고해주세요:

✅ 설정 방법   
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

📁 폴더 구조

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

기본 실행 방법:

```bash
git clone https://github.com/cube8540/oauth-server-go.git
cd oauth-server-go
go run main.go
```

---

## 📌 TODO (예정 기능)

- 이메일 인증/가입 기능
- API 문서 작성
- 클라이언트 등록 및 관리 기능
- Docker 실행 방법 추가
- 좀 더 Go 스럽게

---

## 📖 참고

- [RFC 6749 - The OAuth 2.0 Authorization Framework](https://datatracker.ietf.org/doc/html/rfc6749)

---

## ⚠️ Disclaimer

이 프로젝트는 학습용 목적으로 제작되었으며, 실제 서비스 환경에서는 보안 및 안정성 측면에서 추가적인 검토가 필요합니다.