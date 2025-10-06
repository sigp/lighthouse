# To download/extract nightly tests, run:
# CONSENSUS_SPECS_TEST_VERSION=nightly make
CONSENSUS_SPECS_TEST_VERSION ?= v1.6.0-alpha.6
REPO_NAME := consensus-spec-tests
OUTPUT_DIR := ./$(REPO_NAME)

BLS_TEST_REPO_NAME := bls12-381-tests
BLS_TEST_VERSION := v0.1.1
BLS_TEST = bls_tests_yaml
BLS_OUTPUT_DIR := $(OUTPUT_DIR)/$(BLS_TEST_REPO_NAME)
BLS_BASE_URL := https://github.com/ethereum/$(BLS_TEST_REPO_NAME)/releases/download/$(BLS_TEST_VERSION)

.PHONY: all clean

all: clean $(OUTPUT_DIR) $(BLS_OUTPUT_DIR)

clean:
	rm -rf *.tar.gz $(OUTPUT_DIR) $(BLS_OUTPUT_DIR)

$(OUTPUT_DIR):
	mkdir -p $(OUTPUT_DIR)
	./download_test_vectors.sh $(CONSENSUS_SPECS_TEST_VERSION)
	for test_tarball in *.tar.gz; do \
		tar -xzf $$test_tarball -C $(OUTPUT_DIR); \
		rm -f $$test_tarball; \
	done

$(BLS_OUTPUT_DIR):
	mkdir -p $(BLS_OUTPUT_DIR)
	curl --progress-bar --location --remote-name --show-error --retry 3 --retry-all-errors --fail \
		$(BLS_BASE_URL)/$(BLS_TEST).tar.gz
	tar -xzf *.tar.gz -C $(BLS_OUTPUT_DIR)
	rm -f *.tar.gz
