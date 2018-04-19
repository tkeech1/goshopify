package goshopify

import (
	"net/http"
)

type HttpRequestInterface interface {
	Post(string, string, string, string) (*http.Response, error)
}

type HttpRequestHandler struct {
	Req HttpRequestInterface
}
