BUILD_OPENAPI = ../bin/build_openapi.py
BUNDLE = redocly bundle

SRC_FILES = openapi.yaml params.yaml tags.yaml url-domains.json

BUILT_FILES = schemas params paths tags
BUILT_PATHS = $(foreach f,$(BUILT_FILES),built/$f.yaml)

TARGET = built/openapi.yaml

LINK_FORMAT = redocly-hosted

all: $(TARGET)

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
	$(BUNDLE) > $(TARGET) && cp $(TARGET) ..
