BUILD_OPENAPI = ../bin/build_openapi.py
BUNDLE = redocly bundle

SRC_FILES = openapi.yaml params.yaml tags.yaml url-domains.json

BUILT_FILES = schemas params paths tags
BUILT_PATHS = $(foreach f,$(BUILT_FILES),built/$f.yaml)

TARGET = ../output/openapi.yaml

# Use "make LINK_FORMAT=redocly-preview" for previewing
LINK_FORMAT := redocly-reunite

all: $(TARGET)

lint:
	redocly lint

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

$(TARGET): $(BUILT_PATHS)
	$(BUNDLE) > $(TARGET)
