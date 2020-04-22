# Bump the test tag here and in .gitlab-ci.yml and CI will take care of updating the cached tarballs
TESTS_TAG := v0.11.1
TESTS = general minimal mainnet
TARBALLS = $(patsubst %,%-$(TESTS_TAG).tar.gz,$(TESTS))

REPO_NAME := eth2.0-spec-tests
OUTPUT_DIR := ./$(REPO_NAME)

BASE_URL := https://github.com/ethereum/$(REPO_NAME)/releases/download/$(TESTS_TAG)

$(OUTPUT_DIR): $(TARBALLS)
	mkdir $(OUTPUT_DIR)
	for test_tarball in $^; do \
		tar -xzf $$test_tarball -C $(OUTPUT_DIR);\
	done

%-$(TESTS_TAG).tar.gz:
	wget $(BASE_URL)/$*.tar.gz -O $@

clean-test-files:
	rm -rf $(OUTPUT_DIR)

clean-archives:
	rm -f $(TARBALLS)

clean: clean-test-files clean-archives

.PHONY: clean clean-archives clean-test-files
