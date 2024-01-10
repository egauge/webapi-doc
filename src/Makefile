BUILD_OPENAPI = ../bin/build_openapi.py
BUNDLE = redocly bundle
FW_SRC = /home/davidm/egauge/dev/alpha
PRINT_URL_DOMAINS = $(FW_SRC)/build/host/webapi --print-url-domains

SRC_FILES = openapi.yaml params.yaml paths.yaml schemas.yaml tags.yaml \
	url-domains.json

BUILT_FILES = schemas params paths tags
BUILT_PATHS = $(foreach f,$(BUILT_FILES),built/$f.yaml)

TARGET = built/openapi.yaml

# Use "make LINK_FORMAT=redocly-preview" for previewing
LINK_FORMAT := redocly-hosted

all: $(TARGET)

lint:
	redocly lint

built:
	mkdir $@

built/params.yaml: built/tags.yaml
	@test -f $@ || rm -f built/tags.yaml
	@test -f $@ || $(MAKE) built/tags.yaml

built/paths.yaml: built/tags.yaml
	@test -f $@ || rm -f built/tags.yaml
	@test -f $@ || $(MAKE) built/tags.yaml

built/schemas.yaml: built/tags.yaml
	@test -f $@ || rm -f built/tags.yaml
	@test -f $@ || $(MAKE) built/tags.yaml

built/tags.yaml: $(SRC_FILES) ../bin/build_openapi.py
	$(BUILD_OPENAPI) -l $(LINK_FORMAT) -o built

$(TARGET): built $(BUILT_PATHS) $(SRC_FILES)
	$(BUNDLE) > $(TARGET) && cp $(TARGET) ..

url-domains.json: ALWAYS
	-@tmp=$$(mktemp);			\
	$(PRINT_URL_DOMAINS) | jq > $$tmp &&	\
	( cmp -s $@ $$tmp || cp $$tmp $@ );	\
	rm -f $$tmp

.PHONY: ALWAYS
