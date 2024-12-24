TESTS_TAG := v1.5.0-alpha.10
TESTS = general minimal mainnet
TARBALLS = $(patsubst %,%-$(TESTS_TAG).tar.gz,$(TESTS))

REPO_NAME := consensus-spec-tests
OUTPUT_DIR := ./$(REPO_NAME)
BASE_URL := https://github.com/ethereum/$(REPO_NAME)/releases/download/$(TESTS_TAG)

BLS_TEST_REPO_NAME := bls12-381-tests
BLS_TEST_TAG := v0.1.1
BLS_TEST = bls_tests_yaml
BLS_TARBALL = $(patsubst %,%-$(BLS_TEST_TAG).tar.gz,$(BLS_TEST))
BLS_OUTPUT_DIR := $(OUTPUT_DIR)/$(BLS_TEST_REPO_NAME)
BLS_BASE_URL := https://github.com/ethereum/$(BLS_TEST_REPO_NAME)/releases/download/$(BLS_TEST_TAG)

CURL := $(if $(LIGHTHOUSE_GITHUB_TOKEN),curl -L --header "Authorization: $(LIGHTHOUSE_GITHUB_TOKEN)",curl -L)

all:
	make $(OUTPUT_DIR)
	make $(BLS_OUTPUT_DIR)

$(OUTPUT_DIR): $(TARBALLS)
	mkdir $(OUTPUT_DIR)
	for test_tarball in $^; do \
		tar -xzf $$test_tarball -C $(OUTPUT_DIR);\
	done

$(BLS_OUTPUT_DIR):
	mkdir $(BLS_OUTPUT_DIR)
	$(CURL) $(BLS_BASE_URL)/$(BLS_TEST).tar.gz -o $(BLS_TARBALL)
	tar -xzf $(BLS_TARBALL) -C $(BLS_OUTPUT_DIR)

%-$(TESTS_TAG).tar.gz:
	$(CURL) $(BASE_URL)/$*.tar.gz -o $@

clean-test-files:
	rm -rf $(OUTPUT_DIR) $(BLS_OUTPUT_DIR)

clean-archives:
	rm -f $(TARBALLS) $(BLS_TARBALL)

clean: clean-test-files clean-archives

.PHONY: clean clean-archives clean-test-files
