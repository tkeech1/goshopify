package goshopify

type AccessToken struct {
	AccessToken string `json:"access_token"`
	Scope       string `json:"scope"`
}

type Oauth struct {
	ShopName         string `json:"shop_name"`
	Code             string `json:"code,omitempty"`
	Hmac             string `json:"hmac,omitempty"`
	InstallState     string `json:"install_state,omitempty"`
	OauthToken       string `json:"oauth_token,omitempty"`
	InstallDateTime  string `json:"installdatetime,omitempty"`
	CallbackDateTime string `json:"callbackdatetime,omitempty"`
}
