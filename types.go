package goshopify

import "net/http"

type AccessToken struct {
	AccessToken string `json:"access_token"`
	Scope       string `json:"scope"`
}

type HttpRequestInterface interface {
	Get(string) (*http.Response, error)
}

type Handler struct {
	Req HttpRequestInterface
}

type ShopifyOauth struct {
	ApiKey     string
	Secret     string
	ShopDomain string
}
