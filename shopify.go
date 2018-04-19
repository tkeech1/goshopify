package goshopify

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

func ValidateParams(params map[string]string, secret string) bool {

	if _, ok := params["timestamp"]; !ok {
		return false
	}
	oneDay := 24 * 60 * 60
	hmacTimeStamp, err := strconv.Atoi(params["timestamp"])
	if err != nil {
		return false
	}
	currentTimeStamp := time.Now().Unix() - int64(oneDay)

	if int64(hmacTimeStamp) < currentTimeStamp {
		return false
	}

	return ValidateHmac(params, secret)
}

func ValidateHmac(params map[string]string, secret string) bool {
	if _, ok := params["hmac"]; !ok {
		return false
	}

	calculatedHmac, err := CalculateHmac(params, secret)
	if err != nil {
		return false
	}

	if params["hmac"] == calculatedHmac {
		return true
	}

	return false
}

func CalculateHmac(params map[string]string, secret string) (string, error) {

	value := encodeParams(params)

	mac := hmac.New(sha256.New, []byte(secret))

	_, err := mac.Write([]byte(value))
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(mac.Sum(nil)), nil
}

func encodeParams(params map[string]string) string {
	var keys []string
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var s string
	for _, k := range keys {
		if k != "hmac" {
			var key string
			var val string
			key = strings.Replace(k, "%", "%25", -1)
			key = strings.Replace(key, "=", "%3D", -1)
			val = strings.Replace(params[k], "%", "%25", -1)
			s = s + key + "=" + val + "&"
		}
	}
	return s[:len(s)-1]
}

func (h *HttpRequestHandler) RequestToken(params map[string]string, secret string, apiKey string) (string, error) {
	if !ValidateParams(params, secret) {
		return "", errors.New("Error: Invalid HMAC")
	}

	resp, err := h.Req.Post("https://"+params["shop"]+"/admin/oauth/access_token", apiKey, secret, params["code"])
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var token AccessToken
	err = json.Unmarshal([]byte(body), &token)
	if err != nil {
		return "", err
	}

	return token.AccessToken, nil
}

func GetOauthUrl(params map[string]string, apiKey string, secret string) string {
	shopifyUrl := params["shop"] + "/admin/oauth/access_token?"

	v := url.Values{}
	v.Set("client_id", apiKey)
	v.Add("client_secret", secret)
	v.Add("code", params["code"])

	url := "https://" + shopifyUrl + v.Encode()

	log.Print("URL: ", url)

	return (url)
}

func CreatePermissionUrl(apiKey string, scope string, redirectUrl string, state string, shopifyDomain string) string {
	v := url.Values{}
	v.Set("client_id", apiKey)
	v.Add("scope", scope)
	v.Add("redirect_uri", redirectUrl)
	if state != "" {
		v.Add("state", state)
	}
	return ("https://" + shopifyDomain + "/admin/oauth/authorize?" + v.Encode())
}

func (h *HttpRequestHandler) Post(urlAddress string, data url.Values) (*http.Response, error) {
	//apiKey string, secret string, code string) (*http.Response, error) {
	/*data := url.Values{
		"client_id":     {apiKey},
		"client_secret": {secret},
		"code":          {code},
	}*/
	bodydata := bytes.NewBufferString(data.Encode())
	return http.Post(urlAddress, "application/x-www-form-urlencoded", bodydata)
}
