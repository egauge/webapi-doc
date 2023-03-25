# Introduction

If you just want to get a copy of the latest OpenAPI 3.1 spec of the eGauge WebAPI, simply 
use the file called `openapi.yaml` in the root directory of this repository.

## Prerequisites

This repository requires:

 * `python` v3.10 or newer
 * `make` command (GNU make or compatible)
 * `redocly` command (install with `npm i -g @redocly/cli@latest`)

# Rebuilding openapi.yaml

This file can be rebuilt from the sources with the following steps:

```
cd src
make
```

# Checking the spec for errors

To check for OpenAPI 3.1 warnings and errors, use these commands:

```
cd src
make lint
```

# Updating the documentation

The source files used to generate the root `openapi.yaml` can be found in the `src` directory.
The Python script `bin/build_openapi.py` is used to build the spec from the source files.  There
are two reasons a helper script is needed:

 1. There doesn't appear to be a standard way to have intra-specification hyperlinks in
    OpenAPI.  For this reason, the source files use a special syntax to refer to other
    parts of the documentation and then the Python script translates that syntax to
    actual link targets based on the selected link-format.

 1. Parts of WebAPI map complex objects to a URL tree with lots of endpoints.  These parts are
    called _URL domains_.  _URL domains_ make it possible to access just those portions of an
    object that you need.  It also provides a systematic way of reading and updating the
    information in those complex objects.  Writing the OpenAPI specification for URL domains would
    be tedious since they result in a large number of paths (endpoints) with repeated info.
    Thus, the Python script takes care of automatically generating the specification for
    URL domains.

The main file driving the the OpenAPI specification is `tags.yaml`.  Every path (endpoint) of the WebAPI
needs to appear in this file in the order in which it is to appear in the documentation.  It is possible
to add additional entries that are not tied to a path.  For example, we have an **Introduction** section at
the starts of this file and a **Glossary** section at the end of it.  Within the descriptions of these sections,
you can use normal Markdown headings to provide subsections and/or glossary entries.

OpenAPI 3.1 limits the entries in `tags.yaml` to contain a `name` and a `description`, for example:

```yaml
- name: /auth
  description: |
    The authentication service.  ...

- name: /capture
  description: |
    The capture service allows collecting waveform data.
```

However, `build_openapi.py` recognizes several special keys to help document the paths generated for
the URL domains.  Specifically, the following additional keys are supported:

 * **x-meta-types**: This key restricts the parent key to apply only to paths whose JSON type
   is listed in the value of this key.  For example, `x-meta-types: [object, array]` would
   restrict the key it is contained in so that it applies only to paths that represent JSON
   objects or arrays.

 * **x-path-methods**: This defines the list of HTTP methods that are supported for the path
   this key appears in and its subtree rooted at this path.  The method names must be in lower
   case (e.g., `get` or `post`).
 
 * **x-path**: This defines path-specific information for the path this key appears in.
   Any parameters and response headers defined within this key will also be inherited by
   the subtree rooted at this path.

 * **x-path-method-_method_**: This is like **x-path** but applies only to the method named
   *method*.  That is, this key provides method-specific information.
 
 * **x-path-var**: This key defines the path parameter that is used to access
   the members of an object or the items in an array.  This key must be present
   for each path that represents an object or an array and it must contain a
   `name` key to define the name of the path parameter.  For example, if
   path **/api/obj** represents a JSON object and the `x-path-var` key
   for this path defines the variable name as `member`, then the specification
   would represent the members within this object with path **/api/obj/_{member}_**.
 
 * **x-schema**: This defines schema-specific information for the object (or array)
   represented by the path that this key appear in.  This is typicall used to supply additional
   type information and examples.  For example, if the path represents an integer value,
   the schema information could provide the minimum and maximum values of the integer value.
 
 * **x-schema-ref**: This key can be used to reference shared schema information from
   the `schema.yaml` file.  For example, if two distinct paths represent JSON values
   of the same type, then this key can be used to reference a common entry in
   the `schema.yaml` so that the relevant information has be written only once.
   For example, this can be used to supply `example` values.
   Also, if the path within which this key appears doesn't have a description, then
   the description from the referenced schema is used to document this path.
 
Note that the above keys only appear in the source YAML files.  They do not appear in the generated `openapi.yaml`.

While `tags.yaml` is the primary driver of the specification, there are several other source
files:

 * `openapi.yaml`: This is the template that defines the WebAPI version, license, and what
   other files are to be included to generate the final spec.

 * `paths.yaml`: This documents the WebAPI paths that are not part of a URL domain.
 
 * `schema.yaml`: This documents any schemas referenced from `paths.yaml` and also schemas
   referenced by the **x-schema-ref** key.
   
 * `params.yaml`: This defines query parameters that are referenced from the `parameters` section
   of paths.
 
 * `url_domains.json`: This is a JSON-representation of the paths that are handled by URL domains.
   This file is supplied by eGauge and updated as the WebAPI evolves over time.
 