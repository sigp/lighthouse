TESTS_TAG := v1.5.0-beta.4
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

# Can be changed to Mainnet
NIGHTLY_ARTIFACT := Mainnet Test Configuration
SAFE_ARTIFACT := Mainnet_Test_Configuration
CURL_JSON := curl -sSL -H "Accept: application/vnd.github+json" \
             $(if $(LIGHTHOUSE_GITHUB_TOKEN),-H "Authorization: Bearer $(LIGHTHOUSE_GITHUB_TOKEN)")

define GH_LAST_ARTIFACT_URL
$(shell \
  $(CURL_JSON) \
    "https://api.github.com/repos/ethereum/consensus-specs/actions/workflows/generate_vectors.yml/runs?branch=dev&status=success&per_page=1" \
    | jq -r '.workflow_runs[0].id' \
    | xargs -I{} \
      $(CURL_JSON) "https://api.github.com/repos/ethereum/consensus-specs/actions/runs/{}/artifacts" \
    | jq -r --arg name "$(1)" \
        '.artifacts[] | select(.name==$$name).archive_download_url' \
)
endef

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

nightly:
	@echo "Downloading $(NIGHTLY_ARTIFACT)…"
	@url="$(call GH_LAST_ARTIFACT_URL,$(NIGHTLY_ARTIFACT))"; \
	echo "URL = $$url"; \
	mkdir -p nightly-vectors; \
	$(CURL_JSON) -L "$$url" -o nightly-vectors/$(SAFE_ARTIFACT).zip; \
	unzip -q -o nightly-vectors/$(SAFE_ARTIFACT).zip \
	      -d nightly-vectors/$(SAFE_ARTIFACT)

	cd nightly-vectors/$(SAFE_ARTIFACT) && \
	for f in *; do \
	  if file "$$f" | grep -q 'Zstandard compressed data'; then \
	    echo "Decompressing $$f…"; \
	    mv "$$f" "$$f.tar.zst"; \
	    unzstd "$$f.tar.zst"; \
	    tar -xf "$${f}.tar"; \
	    rm "$${f}.tar"; \
	  fi; \
	done
	@tar_file=nightly-vectors/$(SAFE_ARTIFACT)/Mainnet.tar.gz; \
	echo "Extracting $$tar_file …"; \
	tar -xzf "$$tar_file" -C "$$(dirname $$tar_file)"
	rm -f "$$tar_file"

clean-test-files:
	rm -rf $(OUTPUT_DIR) $(BLS_OUTPUT_DIR)

clean-archives:
	rm -f $(TARBALLS) $(BLS_TARBALL)

clean: clean-test-files clean-archives

.PHONY: clean clean-archives clean-test-files
