TESTS_TAG := v1.3.0-rc.3
TESTS = general minimal mainnet
TARBALLS = $(patsubst %,%-$(TESTS_TAG).tar.gz,$(TESTS))

# Custom fork choice tests from https://github.com/adiasg/consensus-specs
#
# Since these tests are private, we can't download them in this Makefile without
# adding an API key into the process, so we're just downloading the files
# manually and putting them in the root of the `testing/ef_tests` directory.
#
# These files can be obtained from:
# https://github.com/adiasg/consensus-specs/pull/18#issuecomment-1411070772
CUSTOM_FC_TESTS_TAG = fea20be
CUSTOM_FC_TESTS_MAINNET_ARCHIVE = $(CUSTOM_FC_TESTS_TAG)-mainnet.tar.gz
CUSTOM_FC_TESTS_MINIMAL_ARCHIVE = $(CUSTOM_FC_TESTS_TAG)-minimal.tar.gz
CUSTOM_FC_TESTS_REPO_NAME := custom-fc-tests
CUSTOM_FC_TESTS_OUTPUT_DIR := ./$(CUSTOM_FC_TESTS_REPO_NAME)

REPO_NAME := consensus-spec-tests
OUTPUT_DIR := ./$(REPO_NAME)
BASE_URL := https://github.com/ethereum/$(REPO_NAME)/releases/download/$(TESTS_TAG)

BLS_TEST_REPO_NAME := bls12-381-tests
BLS_TEST_TAG := v0.1.1
BLS_TEST = bls_tests_yaml
BLS_TARBALL = $(patsubst %,%-$(BLS_TEST_TAG).tar.gz,$(BLS_TEST))
BLS_OUTPUT_DIR := $(OUTPUT_DIR)/$(BLS_TEST_REPO_NAME)
BLS_BASE_URL := https://github.com/ethereum/$(BLS_TEST_REPO_NAME)/releases/download/$(BLS_TEST_TAG)

WGET := $(if $(LIGHTHOUSE_GITHUB_TOKEN),wget --header="Authorization: $(LIGHTHOUSE_GITHUB_TOKEN)",wget)

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
	$(WGET) $(BLS_BASE_URL)/$(BLS_TEST).tar.gz -O $(BLS_TARBALL)
	tar -xzf $(BLS_TARBALL) -C $(BLS_OUTPUT_DIR)

%-$(TESTS_TAG).tar.gz:
	$(WGET) $(BASE_URL)/$*.tar.gz -O $@

custom-fc-tests:
	mkdir $(CUSTOM_FC_TESTS_OUTPUT_DIR)
	tar -xzf $(CUSTOM_FC_TESTS_MAINNET_ARCHIVE) -C $(CUSTOM_FC_TESTS_OUTPUT_DIR);
	tar -xzf $(CUSTOM_FC_TESTS_MINIMAL_ARCHIVE) -C $(CUSTOM_FC_TESTS_OUTPUT_DIR);

clean-custom-fc-tests:
	rm -rf $(CUSTOM_FC_TESTS_OUTPUT_DIR)

clean-test-files:
	rm -rf $(OUTPUT_DIR) $(BLS_OUTPUT_DIR)

clean-archives:
	rm -f $(TARBALLS) $(BLS_TARBALL)

clean: clean-test-files clean-archives

.PHONY: clean clean-archives clean-test-files
