ARTIFACTS_FOLDER := consensus-spec-tests
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

nightly:
	rm -rf $(ARTIFACTS_FOLDER)
	@echo "Downloading $(NIGHTLY_ARTIFACT)…"
	@url="$(call GH_LAST_ARTIFACT_URL,$(NIGHTLY_ARTIFACT))"; \
	echo "URL = $$url"; \
	$(CURL_JSON) -L "$$url" -o $(SAFE_ARTIFACT).zip; \
	unzip -q -o $(SAFE_ARTIFACT).zip \
	      -d $(ARTIFACTS_FOLDER)
	rm Mainnet_Test_Configuration.zip
	cd $(ARTIFACTS_FOLDER) && \
	for f in *; do \
	  if file "$$f" | grep -q 'Zstandard compressed data'; then \
	    echo "Decompressing $$f…"; \
	    mv "$$f" "$$f.tar.zst"; \
	    unzstd "$$f.tar.zst"; \
	    tar -xf "$${f}.tar"; \
	    rm "$${f}.tar"; \
	  fi; \
	done
	@tar_file=$(ARTIFACTS_FOLDER)/Mainnet.tar.gz; \
	tar -xzf "$$tar_file" -C "$$(dirname $$tar_file)"
	rm -f $(ARTIFACTS_FOLDER)/mainnet.tar.gz

.PHONY: nighlty
