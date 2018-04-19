package goshopify

import (
	"net/http"
	"net/url"
)

type HttpRequestInterface interface {
	Post(string, url.Values) (*http.Response, error)
}

type HttpRequestHandler struct {
	Req HttpRequestInterface
}
