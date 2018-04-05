package goshopify_test

import (
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/tkeech1/goshopify"
)

// validate_params
// request_token
// create_permission_url

func TestHandlerShopify_ValidateParams(t *testing.T) {

	tests := map[string]struct {
		Secret   string
		Params   map[string]string
		Response bool
		err      error
	}{
		"success_new_timestamp": {
			Secret: "hush",
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
			Params: map[string]string{
				"shop":      "some-shop.myshopify.com",
				"code":      "a94a110d86d2452eb3e2af4cfb8a3828",
				"timestamp": strconv.FormatInt(time.Now().Unix(), 10),
				"hmac":      "REPLACE",
				"a":         "b",
			},
			Response: true,
		},
		"success_char_replacements": {
			Secret: "hush",
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
			test.Params["hmac"], _ = goshopify.CalculateHmac(test.Params, []byte(test.Secret))
		}
		response := goshopify.ValidateParams(test.Params, []byte(test.Secret))
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
		"failure_bad_timestamp": {
			Secret: "hush",
			Params: map[string]string{
				"shop":      "some-shop.myshopify.com",
				"code":      "a94a110d86d2452eb3e2af4cfb8a3828",
				"timestamp": "13XXX37178173",
				"hmac":      "2cb1a277650a659f1b11e92a4a64275b128e037f2c3390e3c8fd2d8721dac9e2",
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
		response := goshopify.ValidateHmac(test.Params, []byte(test.Secret))
		assert.Equal(t, test.Response, response)
	}
}
