package testutils

import (
	"github.com/gin-gonic/gin"
	"net/http"
	"net/http/httptest"
	"net/url"
)

func MockGin(query, post url.Values) (*gin.Context, *httptest.ResponseRecorder) {
	gin.SetMode(gin.TestMode)

	c, _ := gin.CreateTestContext(httptest.NewRecorder())

	req := &http.Request{
		URL:    &url.URL{},
		Header: make(http.Header), // if you need to test headers
	}
	req.PostForm = post
	req.URL.RawQuery = query.Encode()

	c.Request = req
	return c, httptest.NewRecorder()
}
