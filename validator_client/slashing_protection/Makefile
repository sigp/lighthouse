TESTS_TAG := ac393b815b356c95569c028c215232b512df583d
GENERATE_DIR := generated-tests
OUTPUT_DIR := interchange-tests
TARBALL := $(OUTPUT_DIR)-$(TESTS_TAG).tar.gz
ARCHIVE_URL := https://github.com/eth2-clients/slashing-protection-interchange-tests/tarball/$(TESTS_TAG)

$(OUTPUT_DIR): $(TARBALL)
	rm -rf $@
	mkdir $@
	tar --strip-components=1 -xzf $^ -C $@

$(TARBALL):
	curl -L -o $@ $(ARCHIVE_URL)

clean-test-files:
	rm -rf $(OUTPUT_DIR)

clean-archives:
	rm -f $(TARBALL)

generate:
	rm -rf $(GENERATE_DIR)
	cargo run --release --bin test_generator -- $(GENERATE_DIR)

clean: clean-test-files clean-archives

.PHONY: clean clean-archives clean-test-files generate

