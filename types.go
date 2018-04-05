package shopify

type ShopifyInterface interface {
	//Query(*dynamodb.QueryInput) (*dynamodb.QueryOutput, error)
	//PutItem(*dynamodb.PutItemInput) (*dynamodb.PutItemOutput, error)
}

type Handler struct {
	Svc     ShopifyInterface
	Shopify ShopifyOauth
}

type ShopifyOauth struct {
	ApiKey     string
	Secret     string
	ShopDomain string
}
