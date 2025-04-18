package client

func ScopeList(c ...string) []Scope {
	var scopes []Scope
	for _, v := range c {
		scopes = append(scopes, Scope{Code: v})
	}
	return scopes
}
