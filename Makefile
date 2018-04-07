test-local:
	docker build -t goshopify:latest . 
	docker run -it --rm -v ${PWD}:/go/src/github.com/tkeech1/goshopify -w /go/src/github.com/tkeech1/goshopify goshopify:latest go test

build-local:
	docker build -t goshopify:latest . 
	docker run -it --rm -v ${PWD}:/go/src/github.com/tkeech1/goshopify -w /go/src/github.com/tkeech1/goshopify goshopify:latest go build