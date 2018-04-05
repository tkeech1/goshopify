test-local:
	docker build -t shopify:latest . 
	docker run -it --rm -v ${PWD}:/go/src/github.com/tkeech1/shopify -w /go/src/github.com/tkeech1/shopify shopify:latest go test