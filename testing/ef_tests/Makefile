# To download/extract nightly tests, run:
# CONSENSUS_SPECS_TEST_VERSION=nightly make
CONSENSUS_SPECS_TEST_VERSION ?= v1.7.0-alpha.7
REPO_NAME := consensus-spec-tests
OUTPUT_DIR := ./$(REPO_NAME)

BLS_TEST_REPO_NAME := bls12-381-tests
BLS_TEST_VERSION := v0.1.1
BLS_TEST = bls_tests_yaml
BLS_OUTPUT_DIR := $(OUTPUT_DIR)/$(BLS_TEST_REPO_NAME)
BLS_BASE_URL := https://github.com/ethereum/$(BLS_TEST_REPO_NAME)/releases/download/$(BLS_TEST_VERSION)

# Fork-choice compliance tests from consensus-specs CI.
# Pin to a specific workflow run ID for reproducibility. Update to pull newer vectors.
COMPLIANCE_RUN_ID ?= 25410712895
COMPLIANCE_PRESET ?= minimal
COMPLIANCE_OUTPUT_DIR := $(OUTPUT_DIR)/tests/$(COMPLIANCE_PRESET)/fulu/fork_choice_compliance

.PHONY: all clean

all: clean $(OUTPUT_DIR) $(BLS_OUTPUT_DIR) $(COMPLIANCE_OUTPUT_DIR)

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

$(COMPLIANCE_OUTPUT_DIR):
	@echo "Fetching fork-choice compliance tests (run $(COMPLIANCE_RUN_ID))..."
	@curl -L -f -H "Authorization: token $(GITHUB_TOKEN)" \
		"https://api.github.com/repos/ethereum/consensus-specs/actions/runs/$(COMPLIANCE_RUN_ID)/artifacts" \
		| python3 -c "import sys,json; arts=json.load(sys.stdin)['artifacts']; url=next(a['archive_download_url'] for a in arts if a['name']=='small.tar.gz'); print(url)" \
		| xargs curl -L -f --output compliance.tar.gz -H "Authorization: token $(GITHUB_TOKEN)"
	tar -xzf compliance.tar.gz -C $(OUTPUT_DIR)
	rm -f compliance.tar.gz
