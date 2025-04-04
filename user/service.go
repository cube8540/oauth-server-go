package user

type (
	Login struct {
		Username string `json:"username"`
	}

	LoginRequest struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
)

type AuthService interface {
	Login(req *LoginRequest) (*Login, error)
}

type authService struct {
	repo   AccountRepository
	hasher Hasher
}

func NewAuthService(repo AccountRepository, hasher Hasher) AuthService {
	return &authService{
		repo:   repo,
		hasher: hasher,
	}
}

func (s authService) Login(req *LoginRequest) (*Login, error) {
	if req.Username == "" || req.Password == "" {
		return nil, ErrRequireParamsMissing
	}

	account := s.repo.FindByUsername(req.Username)
	if account == nil {
		return nil, ErrAccountNotFound
	}

	if cmp, err := s.hasher.Compare(account.Password, req.Password); err != nil {
		return nil, err
	} else if !cmp {
		return nil, ErrPasswordNotMatch
	} else if !account.Active {
		return nil, ErrAccountLocked
	}

	login := Login{Username: account.Username}
	return &login, nil
}
