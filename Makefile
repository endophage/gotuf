# Set an output prefix, which is the local directory if not specified
PREFIX?=$(shell pwd)

vet:
	@echo "+ $@"
	@go vet ./...

fmt:
	@echo "+ $@"
	@test -z "$$(gofmt -s -l . | grep -v Godeps/_workspace/src/ | tee /dev/stderr)" || \
		echo "+ please format Go code with 'gofmt -s'"

lint:
	@echo "+ $@"
	@test -z "$$(golint ./... | grep -v Godeps/_workspace/src/ | tee /dev/stderr)"

build:
	@echo "+ $@"
	@go build -v ${GO_LDFLAGS} ./...

test:
	@echo "+ $@"
	# FIXME: go back to "./..." form when items under "cmd" build properly
	#@go test -test.short ./...
	go test -test.short ./signed
	go test -test.short ./store
	go test -test.short ./utils
	go test -test.short

test-full:
	@echo "+ $@"
	# FIXME: go back to "./..." form when items under "cmd" build properly
	#@go test ./...
	go test ./signed
	go test ./store
	go test ./utils
	go test

binaries: ${PREFIX}/bin/registry ${PREFIX}/bin/registry-api-descriptor-template ${PREFIX}/bin/dist
	@echo "+ $@"

clean:
	@echo "+ $@"
	@rm -rf "${PREFIX}/bin/registry" "${PREFIX}/bin/registry-api-descriptor-template"
