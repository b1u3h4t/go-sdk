# Run unit tests. Code lives in v3; run from v3 so go test finds packages.
# For full integration tests (requires FISCO-BCOS node), use: bash .ci/integration_test.sh -a
# from the repo root (script will cd to v3).
.PHONY: test
test:
	cd v3 && go test -v ./smcrypto/... ./abi/flags/...
