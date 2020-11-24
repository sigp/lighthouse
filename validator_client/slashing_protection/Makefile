TESTS_TAG := b8413ca42dc92308019d0d4db52c87e9e125c4e9
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

