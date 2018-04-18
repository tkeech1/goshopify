package goshopify

import (
	"net/http"
)

type HttpRequestInterface interface {
	Get(string) (*http.Response, error)
	Post(string, string, string, string) (*http.Response, error)
}

type HttpRequestHandler struct {
	Req HttpRequestInterface
}
