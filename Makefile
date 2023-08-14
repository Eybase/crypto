PACKAGES=$(shell go list ./...)

########################################
### Formatting, linting, and testing

fmt:
	@go fmt ./...

lint:
	@echo "--> Running linter"
	@golangci-lint run
	
test:
	@echo "--> Running go test"
	@go test -p 1 $(PACKAGES)	
