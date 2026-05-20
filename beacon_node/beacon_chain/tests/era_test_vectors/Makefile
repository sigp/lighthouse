VECTORS_TAG := 52eb9dd94a09153b8b07c9bba4b08adca0d6e219
OUTPUT_DIR := vectors
TARBALL := $(OUTPUT_DIR)-$(VECTORS_TAG).tar.gz
ARCHIVE_URL := https://github.com/dapplion/era-test-vectors/tarball/$(VECTORS_TAG)

$(OUTPUT_DIR): $(TARBALL)
	rm -rf $@
	mkdir -p $@
	tar --strip-components=1 -xzf $^ -C $@

$(TARBALL):
	curl --fail -L -o $@ $(ARCHIVE_URL)

clean:
	rm -rf $(OUTPUT_DIR) $(TARBALL)

.PHONY: clean
