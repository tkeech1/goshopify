package goshopify_test

import (
	"bytes"
	"errors"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/tkeech1/goshopify"
	"github.com/tkeech1/goshopify/mocks"
)

func TestHandlerShopify_ValidateParams(t *testing.T) {

	tests := map[string]struct {
		Secret   string
		ApiKey   string
		Params   map[string]string
		Response bool
		err      error
	}{
		"success_new_timestamp": {
			Secret: "hush",
			ApiKey: "apikey",
			Params: map[string]string{
				"shop":      "some-shop.myshopify.com",
				"code":      "a94a110d86d2452eb3e2af4cfb8a3828",
				"timestamp": strconv.FormatInt(time.Now().Unix(), 10),
				"hmac":      "REPLACE",
			},
			Response: true,
		},
		"success_new_params": {
			Secret: "hush",
			ApiKey: "apikey",
			Params: map[string]string{
				"shop":      "some-shop.myshopify.com",
				"code":      "a94a110d86d2452eb3e2af4cfb8a3828",
				"timestamp": strconv.FormatInt(time.Now().Unix(), 10),
				"hmac":      "REPLACE",
				"a":         "b",
			},
			Response: true,
		},
		"failure_no_timestamp": {
			Secret: "hush",
			ApiKey: "apikey",
			Params: map[string]string{
				"shop": "some-shop.myshopify.com",
				"code": "a94a110d86d2452eb3e2af4cfb8a3828",
				"hmac": "2cb1a277650a659f1b11e92a4a64275b128e037f2c3390e3c8fd2d8721dac9e2",
			},
			Response: false,
		},
		"failure_bad_timestamp": {
			Secret: "hush",
			ApiKey: "apikey",
			Params: map[string]string{
				"shop":      "some-shop.myshopify.com",
				"code":      "a94a110d86d2452eb3e2af4cfb8a3828",
				"timestamp": "13XXX37178173",
				"hmac":      "2cb1a277650a659f1b11e92a4a64275b128e037f2c3390e3c8fd2d8721dac9e2",
			},
			Response: false,
		},
		"success_char_replacements": {
			Secret: "hush",
			ApiKey: "apikey",
			Params: map[string]string{
				"shop":      "some-shop.myshopify.com",
				"code":      "a94a110d86d2452eb3e2af4cfb8a3828",
				"timestamp": strconv.FormatInt(time.Now().Unix(), 10),
				"hmac":      "REPLACE",
				"=a%":       "=b%",
			},
			Response: true,
		},
		"failure_old_timestamp": {
			Secret: "hush",
			ApiKey: "apikey",
			Params: map[string]string{
				"shop":      "some-shop.myshopify.com",
				"code":      "a94a110d86d2452eb3e2af4cfb8a3828",
				"timestamp": "1337178173",
				"hmac":      "2cb1a277650a659f1b11e92a4a64275b128e037f2c3390e3c8fd2d8721dac9e2",
			},
			Response: false,
		},
	}

	for name, test := range tests {
		t.Logf("Running test case: %s", name)
		if test.Params["hmac"] == "REPLACE" {
			test.Params["hmac"], _ = goshopify.CalculateHmac(test.Params, test.Secret)
		}
		response := goshopify.ValidateParams(test.Params, test.Secret)
		assert.Equal(t, test.Response, response)
	}
}

func TestHandlerShopify_ValidateHmac(t *testing.T) {

	tests := map[string]struct {
		Secret   string
		Params   map[string]string
		Response bool
		err      error
	}{
		"success": {
			Secret: "hush",
			Params: map[string]string{
				"shop":      "some-shop.myshopify.com",
				"code":      "a94a110d86d2452eb3e2af4cfb8a3828",
				"timestamp": "1337178173",
				"hmac":      "2cb1a277650a659f1b11e92a4a64275b128e037f2c3390e3c8fd2d8721dac9e2",
			},
			Response: true,
		},
		"failure_bad_secret": {
			Secret: "SECRET",
			Params: map[string]string{
				"shop":      "some-shop.myshopify.com",
				"code":      "a94a110d86d2452eb3e2af4cfb8a3828",
				"timestamp": "1337178173",
				"hmac":      "2cb1a277650a659f1b11e92a4a64275b128e037f2c3390e3c8fd2d8721dac9e2",
			},
			Response: false,
		},
		"failure_no_hmac": {
			Secret: "hush",
			Params: map[string]string{
				"shop":      "some-shop.myshopify.com",
				"code":      "a94a110d86d2452eb3e2af4cfb8a3828",
				"timestamp": "1337178173",
			},
			Response: false,
		},
		"failure_no_timestamp": {
			Secret: "hush",
			Params: map[string]string{
				"shop": "some-shop.myshopify.com",
				"code": "a94a110d86d2452eb3e2af4cfb8a3828",
				"hmac": "2cb1a277650a659f1b11e92a4a64275b128e037f2c3390e3c8fd2d8721dac9e2",
			},
			Response: false,
		},
		"failure_extra_param": {
			Secret: "hush",
			Params: map[string]string{
				"shop":      "some-shop.myshopify.com",
				"code":      "a94a110d86d2452eb3e2af4cfb8a3828",
				"timestamp": "1337178173",
				"hmac":      "2cb1a277650a659f1b11e92a4a64275b128e037f2c3390e3c8fd2d8721dac9e2",
				"a":         "a",
			},
			Response: false,
		},
	}

	for name, test := range tests {
		t.Logf("Running test case: %s", name)
		response := goshopify.ValidateHmac(test.Params, test.Secret)
		assert.Equal(t, test.Response, response)
	}
}

func TestHandlerShopify_RequestToken(t *testing.T) {

	tests := map[string]struct {
		Secret        string
		ApiKey        string
		Params        map[string]string
		ReturnedToken string
		Response      *http.Response
		ResponseError error
		err           error
	}{
		"success": {
			Secret: "hush",
			ApiKey: "someKey",
			Params: map[string]string{
				"shop":      "some-shop.myshopify.com",
				"code":      "a94a110d86d2452eb3e2af4cfb8a3828",
				"timestamp": strconv.FormatInt(time.Now().Unix(), 10),
				"hmac":      "REPLACE",
			},
			Response: &http.Response{
				StatusCode: 200,
				Header: http.Header{
					"Content-Type": {"application/json"},
				},
				Body: ioutil.NopCloser(bytes.NewReader([]byte(
					`{"access_token": "12345","scope": "12345678"}`,
				)))},
			ResponseError: nil,
			ReturnedToken: "12345",
			err:           nil,
		},
		"failure_old_timestamp": {
			Secret: "hush",
			Params: map[string]string{
				"shop":      "some-shop.myshopify.com",
				"code":      "a94a110d86d2452eb3e2af4cfb8a3828",
				"timestamp": "1337178173",
				"hmac":      "2cb1a277650a659f1b11e92a4a64275b128e037f2c3390e3c8fd2d8721dac9e2",
			},
			ResponseError: nil,
			ReturnedToken: "",
			err:           errors.New("Error: Invalid HMAC"),
		},
		"failure_http_error": {
			Secret: "hush",
			ApiKey: "someKey",
			Params: map[string]string{
				"shop":      "some-shop.myshopify.com",
				"code":      "a94a110d86d2452eb3e2af4cfb8a3828",
				"timestamp": strconv.FormatInt(time.Now().Unix(), 10),
				"hmac":      "REPLACE",
			},
			Response: &http.Response{
				StatusCode: 200,
				Header: http.Header{
					"Content-Type": {"application/json"},
				},
				Body: ioutil.NopCloser(bytes.NewReader([]byte(
					`{"access_token": "12345","scope": "12345678"}`,
				)))},
			ResponseError: errors.New("Error: HTTP"),
			ReturnedToken: "",
			err:           errors.New("Error: HTTP"),
		},
	}

	for name, test := range tests {
		t.Logf("Running test case: %s", name)
		mockHttpRequestInterface := &mocks.HttpRequestInterface{}
		mockHttpRequestInterface.
			On("Post", "https://"+test.Params["shop"]+"/admin/oauth/access_token", url.Values{
				"client_id":     {test.ApiKey},
				"client_secret": {test.Secret},
				"code":          {test.Params["code"]},
			}).
			Return(test.Response, test.ResponseError).
			Once()

		h := &goshopify.HttpRequestHandler{
			Req: mockHttpRequestInterface,
		}

		if test.Params["hmac"] == "REPLACE" {
			test.Params["hmac"], _ = goshopify.CalculateHmac(test.Params, test.Secret)
		}
		response, err := h.RequestToken(test.Params, test.Secret, test.ApiKey)
		assert.Equal(t, test.ReturnedToken, response)
		assert.Equal(t, test.err, err)
		//mockHttpRequestInterface.AssertExpectations(t)
	}
}

func TestHandlerShopify_CreatePermissionUrl(t *testing.T) {

	tests := map[string]struct {
		ApiKey        string
		Scope         string
		State         string
		RedirectUrl   string
		ShopifyDomain string
		Response      string
	}{
		"success": {
			ApiKey:        "someKey",
			Scope:         "scope1,scope2,scop3",
			State:         "statestate",
			RedirectUrl:   "https://myredirect",
			ShopifyDomain: "mydomain.myshopify.com",
			Response:      "https://mydomain.myshopify.com/admin/oauth/authorize?client_id=someKey&redirect_uri=https%3A%2F%2Fmyredirect&scope=scope1%2Cscope2%2Cscop3&state=statestate",
		},
		"success_no_state": {
			ApiKey:        "someKey",
			Scope:         "scope1,scope2,scop3",
			State:         "",
			RedirectUrl:   "https://myredirect",
			ShopifyDomain: "mydomain.myshopify.com",
			Response:      "https://mydomain.myshopify.com/admin/oauth/authorize?client_id=someKey&redirect_uri=https%3A%2F%2Fmyredirect&scope=scope1%2Cscope2%2Cscop3",
		},
	}

	for name, test := range tests {
		t.Logf("Running test case: %s", name)

		response := goshopify.CreatePermissionUrl(test.ApiKey, test.Scope, test.RedirectUrl, test.State, test.ShopifyDomain)
		assert.Equal(t, test.Response, response)
	}
}
