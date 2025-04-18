package testutils

import (
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/render"
	"net/http"
	"net/http/httptest"
	"net/url"
)

type EmptyRender struct {
}

func (e EmptyRender) Render(writer http.ResponseWriter) error {
	return nil
}

func (e EmptyRender) WriteContentType(w http.ResponseWriter) {
}

type EmptyHTMLRender struct {
}

func (i EmptyHTMLRender) Instance(s string, a any) render.Render {
	return EmptyRender{}
}

func NewHTMLRender() *EmptyHTMLRender {
	return &EmptyHTMLRender{}
}

type TestSessions struct {
	id    string
	store map[interface{}]interface{}
}

func NewSessions(id string) *TestSessions {
	return &TestSessions{id: id, store: make(map[interface{}]interface{})}
}

func (t *TestSessions) ID() string {
	return t.id
}

func (t *TestSessions) Get(key interface{}) interface{} {
	return t.store[key]
}

func (t *TestSessions) Set(key interface{}, val interface{}) {
	t.store[key] = val
}

func (t *TestSessions) Delete(key interface{}) {
	delete(t.store, key)
}

func (t *TestSessions) Clear() {
	for k, _ := range t.store {
		delete(t.store, k)
	}
}

func (t *TestSessions) AddFlash(value interface{}, vars ...string) {
}

func (t *TestSessions) Flashes(vars ...string) []interface{} {
	return nil
}

func (t *TestSessions) Options(options sessions.Options) {
}

func (t *TestSessions) Save() error {
	return nil
}

func MockGin(query, post url.Values) (*gin.Context, *httptest.ResponseRecorder, *gin.Engine) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	c, engine := gin.CreateTestContext(w)

	req := &http.Request{
		URL:    &url.URL{},
		Header: make(http.Header), // if you need to test headers
	}
	req.PostForm = post
	req.URL.RawQuery = query.Encode()

	c.Request = req
	return c, w, engine
}
