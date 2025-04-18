package testutils

import "net/url"

func ParseURL(u string) *url.URL {
	res, _ := url.Parse(u)
	return res
}
