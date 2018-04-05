package goshopify

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
	"time"
)

func ValidateParams(params map[string]string, secret []byte) bool {

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

func ValidateHmac(params map[string]string, secret []byte) bool {
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

func CalculateHmac(params map[string]string, secret []byte) (string, error) {

	value := encodeParams(params)

	mac := hmac.New(sha256.New, secret)

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
