TESTS_TAG := f495032df9c26c678536cd2b7854e836ea94c217
GENERATE_DIR := generated-tests
OUTPUT_DIR := interchange-tests
TARBALL := $(OUTPUT_DIR)-$(TESTS_TAG).tar.gz
ARCHIVE_URL := https://github.com/eth2-clients/slashing-protection-interchange-tests/tarball/$(TESTS_TAG)

ifeq ($(OS),Windows_NT)
ifeq (, $(shell where rm))
	rmfile = if exist $(1) (del /F /Q $(1))
	rmdir  = if exist $(1) (rmdir /Q /S $(1))
else
	rmfile = rm -f $(1)
	rmdir  = rm -rf $(1)
endif
else
	rmfile = rm -f $(1)
	rmdir  = rm -rf $(1)
endif

$(OUTPUT_DIR): $(TARBALL)
	$(call rmdir,$@)
	mkdir $@
	tar --strip-components=1 -xzf $^ -C $@

$(TARBALL):
	curl --fail -L -o $@ $(ARCHIVE_URL)

clean-test-files:
	$(call rmdir,$(OUTPUT_DIR))

clean-archives:
	$(call rmfile,$(TARBALL))

generate:
	$(call rmdir,$(GENERATE_DIR))
	cargo run --release --bin test_generator -- $(GENERATE_DIR)

clean: clean-test-files clean-archives

.PHONY: clean clean-archives clean-test-files generate

