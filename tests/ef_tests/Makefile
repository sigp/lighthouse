TESTS_TAG := v0.8.3
TESTS = general minimal mainnet

REPO_NAME := eth2.0-spec-tests
OUTPUT_DIR := ./$(REPO_NAME)

BASE_URL := https://github.com/ethereum/$(REPO_NAME)/releases/download/$(TESTS_TAG)

eth2.0-spec-tests:
	mkdir $(OUTPUT_DIR)
	for test in $(TESTS); do \
		wget $(BASE_URL)/$$test.tar.gz; \
		tar -xzvf $$test.tar.gz -C $(OUTPUT_DIR);\
		rm $$test.tar.gz;\
	done

clean:
	rm -r $(OUTPUT_DIR)
