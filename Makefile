TEST_ARGS?=-v

tools:
	bash ./scripts/tools.sh

lint:
	bash ./scripts/lint.sh

fix:
	bash ./scripts/fix.sh

tests:
	gotestsum --no-color=false --format testname -- -timeout 600s -p 8 -parallel 8 -race -coverprofile=/tmp/profile.out ${TEST_ARGS} ./pkg/...

godoc:
	godoc -http=0.0.0.0:6060
