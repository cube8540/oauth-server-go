package user

import "oauth-server-go/pkg/hash"

type Store interface {
	FindByUsername(u string) (*Account, error)
}

type Service struct {
	store Store
}

func NewService(store Store) *Service {
	return &Service{
		store: store,
	}
}

func (s *Service) Login(r *Login) (*Account, error) {
	if r.Username == "" || r.Password == "" {
		return nil, ErrRequireParamsMissing
	}

	account, err := s.store.FindByUsername(r.Username)
	if err != nil {
		return nil, err
	}
	if cmp, err := hash.Compare(account.Password, r.Password); err != nil {
		return nil, err
	} else if !cmp {
		return nil, ErrPasswordNotMatch
	} else if !account.Active {
		return nil, ErrAccountLocked
	}

	return account, nil
}
