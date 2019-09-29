TESTS_TAG := v0.8.3
TESTS = general minimal mainnet

TESTS_BASE_DIR := .
REPO_NAME := eth2.0-spec-tests
OUTPUT_DIR := $(TESTS_BASE_DIR)/$(REPO_NAME)

BASE_URL := https://github.com/ethereum/$(REPO_NAME)/releases/download/$(TESTS_TAG)

init_tests: download_tests extract_tests
	mkdir $(OUTPUT_DIR)
	for test in $(TESTS); do \
		tar -C $(OUTPUT_DIR) -xvf $(TESTS_BASE_DIR)/$$test.tar ;\
		rm $(TESTS_BASE_DIR)/$$test.tar ;\
	done

extract_tests:
	for test in $(TESTS); do \
		gzip -df $(TESTS_BASE_DIR)/$$test.tar.gz ;\
	done

download_tests:
	for test in $(TESTS); do \
		wget -P $(TESTS_BASE_DIR) $(BASE_URL)/$$test.tar.gz; \
	done

clean:
	rm -r $(OUTPUT_DIR)
