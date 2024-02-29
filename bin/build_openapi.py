#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2023 eGauge Systems LLC
# 	1644 Conestoga St, Suite 2
# 	Boulder, CO 80301
# 	voice: 720-545-9767
#
#  All rights reserved.
#
# MIT License
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#
"""Build the OpenAPI 3.1 spec of eGauge WebAPI.

Reads the following input files from the current working directory:

  params.yaml (the OpenAPI components/parameters section),
  paths.yaml (the OpenAPI paths section),
  schemas.yaml (the OpenAPI schemas section),
  tags.yaml (the OpenAPI tags section), and
  url-domains.json (paths handled by url_domains).

The program generates the following output files in the output directory:

  params.yaml, tags.yaml
	(same as the respective input file, except that relative links
	have been remapped according to the output format),

  paths.yaml, schemas.yaml:
	(updated with paths and schemas generated from url-domains.json
	and relative links are also remapped according to the output format).
"""
import argparse
import json
import re
import sys

from copy import copy
from enum import Enum
from pathlib import Path
from typing import Union


from ruamel.yaml.main import (
    round_trip_load as yaml_load,
    round_trip_dump as yaml_dump,
)


URLDomain = Union[str, dict, list]


class StrEnum(str, Enum):
    """Needed for Python 3.10 and older only."""

    def __str__(self):
        return self.value


class Key(StrEnum):
    DESCRIPTION = "description"
    OPERATION_ID = "operationId"
    SUMMARY = "summary"
    TAGS = "tags"
    X_META_TYPES = "x-meta-types"
    X_PATH = "x-path"
    X_PATH_METHOD = "x-path-method-"
    X_PATH_METHODS = "x-path-methods"
    X_PATH_VAR = "x-path-var"
    X_SCHEMA = "x-schema"
    X_SCHEMA_REF = "x-schema-ref"


class LinkFormat(StrEnum):
    REDOCLY_PREVIEW = "redocly-preview"
    REDOCLY_HOSTED = "redocly-hosted"


class Method(StrEnum):
    GET = "get"
    PUT = "put"
    POST = "post"
    DELETE = "delete"


METHOD_NAME = {
    str(Method.GET): "Get",
    str(Method.PUT): "Replace",
    str(Method.POST): "Update",
    str(Method.DELETE): "Delete",
}


class Error(Exception):
    """Base-class for errors raised by this program."""


class Logger:
    """Helper class for formatting warning and error messages."""

    error_count = 0

    def __init__(self, prog_name):
        self.prog_name = prog_name

    def message(self, severity, msg, filename=None, line=None, col=None):
        prefix = self.prog_name + ": " + severity + ": "
        if filename is not None:
            prefix += filename
            if line is not None:
                prefix += f":{line + 1}"
                if col is not None:
                    prefix += ":{col + 1}"
            prefix += ": "
        print(prefix + msg, file=sys.stderr)

    def warning(self, msg, filename=None, line=None, col=None):
        self.message("warning", msg, filename=filename, line=line, col=col)

    def error(self, msg, filename=None, line=None, col=None):
        self.error_count += 1
        self.message("error", msg, filename=filename, line=line, col=col)


def key_is_internal(key: str) -> bool:
    """Return True if the YAML key is used only by this program."""
    return key.startswith("x-")


def domain_to_json_type(domain: URLDomain):
    """Determine the JSON type of DOMAIN.  Returns one of "object",
    "array", "integer", "number", or "boolean".

    """
    if isinstance(domain, dict):
        return "object"
    if isinstance(domain, list):
        return "array"
    return domain


def delete_desc(json_type: str) -> str:
    """Return the default description for the DELETE method on URL
    domains.  This can be overridden with:

        x-path-method-delete:
          description: Custom description.

    """
    if json_type == "object":
        return ("Reset to default. See the descriptions of the individual "
                "endpoints for their default values.  Commonly, arrays "
                "and strings are cleared to empty, numbers are cleared "
                "to 0, and booleans are cleared to `false`.  ")
    if json_type == "array":
        return "Reset to empty array."
    if json_type == "string":
        return "Reset to empty string."
    if json_type == "integer":
        return "Reset to 0."
    if json_type == "number":
        return "Reset to 0."
    if json_type == "boolean":
        return "Reset to `false`."
    raise Error("Unknown type", json_type)


def camel_case(s):
    """Convert string s to Camel-case."""
    if s[0] == "{" and s[-1] == "}":
        return s[1:-1].title()
    s = re.sub(r"(_|-)+", " ", s).title().replace(" ", "")
    first = s[0].upper()
    return "".join([first, s[1:]])


def is_scalar(val) -> bool:
    """Return True of val is a scalar value (number, string, boolean)."""
    return not isinstance(val, (dict, list))


def update(entry, info, json_type=None, update_all=False):
    """Recursively merge info into entry.  If update_all is True, all info
    is merged .  If it is False, ignore any info that doesn't apply to
    the given json_type.  This filtering is based on the optional
    `x-meta-types` key.

    """
    assert update_all or json_type is not None

    if isinstance(info, dict):
        allowed_types = info.get(Key.X_META_TYPES)
        if not update_all and allowed_types is not None:
            if json_type not in allowed_types:
                return

        for key, value in info.items():
            if not update_all and key_is_internal(key):
                continue
            if is_scalar(value):
                entry[key] = value
            else:
                if key in entry:
                    new = entry[key]
                else:
                    new = {} if isinstance(value, dict) else []
                update(new, value, json_type, update_all)
                entry[key] = new
    elif isinstance(info, list):
        for item in info:
            if not update_all and isinstance(item, dict):
                allowed_types = item.get(Key.X_META_TYPES)
                if not update_all and allowed_types is not None:
                    if json_type not in allowed_types:
                        return
            entry.append(item)
    else:
        raise Error("info has unexpected type", info)


class YAMLFile:
    def __init__(self, basename):
        """Read BASENAME.yaml into memory, patching relative Markdown link
        targets in `description:' tags using MAP_LINK().

        """
        self.filename = basename + ".yaml"
        with open(self.filename, encoding="utf-8") as f:
            self.content = yaml_load(f, preserve_quotes=True)

    def patch_relative_links(self, map_link):
        """Patch the link target of relative links in descriptions so that
        they are correct for the selected link-format.

        """
        self._patch(map_link, self.content)

    def strip_and_write(self, output_dir: Path):
        """Strip extension keys from the file content and store the resulting
        file in the output directory.

        """
        self._strip_extension_keys(self.content)

        with open(output_dir / self.filename, "w", encoding="utf-8") as f:
            yaml_dump(self.content, f)

    def _patch(self, map_link, content):
        """Recurse through contents and patch all relative links found in
        descriptions.

        """
        if isinstance(content, list):
            for item in content:
                self._patch(map_link, item)
        elif isinstance(content, dict):
            for key, val in content.items():
                if key == Key.DESCRIPTION:
                    desc = ""
                    end = 0
                    for m in re.finditer(r"\[[^]]*]\(([^)]+)\)", val):
                        target = m.group(1)
                        if re.match(r"https?://", target):
                            continue
                        mapped = map_link(
                            target,
                            self.filename,
                            content.lc.line,
                            content.lc.col,
                        )
                        desc += val[end : m.start(1)] + mapped
                        end = m.end(1)
                    if end:
                        desc += val[end:]
                        content[key] = desc
                self._patch(map_link, val)

    def _strip_extension_keys(self, content):
        """Recurse through the content and remove all extension keys (keys
        starting with `x-').

        """
        if isinstance(content, list):
            for item in content:
                self._strip_extension_keys(item)
        elif isinstance(content, dict):
            to_delete = []
            for key, val in content.items():
                if key_is_internal(key):
                    to_delete.append(key)
                else:
                    self._strip_extension_keys(val)
            for key in to_delete:
                del content[key]


class InheritedContext:
    """This is used to track information that was inherited from the
    parent of a url_domain.

    """

    def __init__(
        self, path_vars=None, path_info=None, methods=None, method_info=None
    ):
        # path-variables:
        self.path_vars = path_vars or {}
        # supported methods:
        self.methods = methods or []

        # query parameters and extra headers that apply to all methods:
        self.path_info = path_info or {}
        # query parameters and extra headers that apply to a particular method:
        self.method_info = method_info or {}  # indexed by Method

    def dup(self):
        """Return a copy of the inherited context."""
        return InheritedContext(
            copy(self.path_vars),
            copy(self.path_info),
            copy(self.methods),
            copy(self.method_info),
        )


class URLDomainGenerator:
    """Helper class to translate URL domains to OpenAPI 3.1."""

    context_stack = []

    def __init__(
        self,
        log: Logger,
        tags: dict,
        paths: YAMLFile = None,
        schemas: YAMLFile = None,
    ):
        self.log = log
        self.tags = tags
        self.paths = paths or []
        self.schemas = schemas or []
        self.context_stack = [InheritedContext()]

    def push_context(self):
        """Push a copy of the current inherited context onto the context
        stack.

        """
        self.context_stack.append(self.context_stack[-1].dup())

    def pop_context(self):
        """Drop the inherited context at the top of the context stack thereby
        restoring the previous context.

        """
        return self.context_stack.pop()

    @property
    def context(self):
        """Return the current inherited context."""
        return self.context_stack[-1]

    def translate(self, url_domains: dict):
        """Translate the URL domains to OpenAPI."""
        for domain_name, domain in url_domains.items():
            path = "/" + domain_name
            schema_name = domain_name
            self._translate_url_domain(domain, path, schema_name)

    def inherit(self, dst: dict, info: dict):
        """Inherit path or method info to the dst dictionary.  Only parameters
        and response headers are inherited.

        """
        # parameters are inherited to the children:
        if "parameters" in info:
            if "parameters" not in dst:
                dst["parameters"] = []
            for param in info["parameters"]:
                dst["parameters"].append(param)

        # response headers are inherited to the children:
        if "responses" in info:
            for code in info["responses"]:
                if "headers" in info["responses"][code]:
                    headers = info["responses"][code]["headers"]
                    for key, value in headers.items():
                        if "responses" not in dst:
                            dst["responses"] = {}
                        if code not in dst["responses"]:
                            dst["responses"][code] = {}
                        if "headers" not in dst["responses"][code]:
                            dst["responses"][code]["headers"] = {}
                        dst["responses"][code]["headers"][key] = value

    def path_info(self, tag_info: dict):
        """Return the path info for the current URL domain.  If the tags file
        has inheritable info for this domain, then the context is
        updated accordingly.

        """
        info = tag_info.get(Key.X_PATH, {})
        if info:
            parent_info = copy(self.context.path_info)
            self.inherit(self.context.path_info, info)
        else:
            parent_info = self.context.path_info
        if parent_info:
            update(info, parent_info, update_all=True)
        return info

    def method_info(self, tag_info: dict, method: str):
        """Return the method info for the current URL domain and the specified
        method.  If the tags file has inheritable info, then the
        context is updated accordingly.

        """
        info = tag_info.get(Key.X_PATH_METHOD + method, {})
        if info:
            if method not in self.context.method_info:
                self.context.method_info[method] = {}
            parent_info = copy(self.context.method_info[method])
            self.inherit(self.context.method_info[method], info)
        else:
            parent_info = self.context.method_info.get(method)
        if parent_info:
            update(info, parent_info, update_all=True)
        return info

    def _translate_url_domain(
        self, domain: URLDomain, path: str, schema_name: str
    ):
        """Translate a domain to is OpenAPI equivalent."""
        tag_info = self.tags.get(path, {})
        if not tag_info:
            self.log.error(f"path {path} missing", filename="tags.yaml")
            return

        xref = tag_info.get(Key.X_SCHEMA_REF)
        if xref:
            parts = xref.split("#")
            xref_filename = parts[0]
            xref_name = parts[1][1:]  # strip off leading '/'
            if xref_filename != "./schemas.yaml":
                self.log.error("x-schema-ref file must be schemas.yaml")
                return
            xref_value = self.schemas.content.get(xref_name)
            if not xref_value:
                self.log.error(
                    "x-schema-ref name `%s' does not exist",
                    filename="schemas.yaml",
                    line=xref.lc.line,
                )
                return

            if Key.X_SCHEMA in tag_info:
                update(
                    tag_info[str(Key.X_SCHEMA)], xref_value, update_all=True
                )
            else:
                tag_info[str(Key.X_SCHEMA)] = xref_value

            if (
                Key.DESCRIPTION in xref_value
                and Key.DESCRIPTION not in tag_info
            ):
                tag_info[str(Key.DESCRIPTION)] = xref_value[Key.DESCRIPTION]

        json_type = domain_to_json_type(domain)

        self.push_context()

        methods = tag_info.get(Key.X_PATH_METHODS, [])
        if methods:
            self.context.methods = methods

        self._add_path(path, schema_name, json_type, tag_info)
        try:
            path_var_name = self._update_path_vars(tag_info)
        except Error:
            return

        self._add_schema(
            domain, schema_name, json_type, tag_info, path_var_name
        )

        # generate the subdomains:

        if json_type == "object":
            for key, subdomain in domain.items():
                if key == "{}":
                    if not path_var_name:
                        self.log.error(
                            "object is missing x-path-var",
                            filename="tags.yaml",
                            line=tag_info.lc.line,
                        )
                        return
                    path_comp = "{" + path_var_name + "}"
                else:
                    path_comp = key
                subdomain_path = path + "/" + path_comp
                subdomain_schema_name = schema_name + camel_case(path_comp)
                self._translate_url_domain(
                    subdomain, subdomain_path, subdomain_schema_name
                )
        elif json_type == "array":
            if not path_var_name:
                self.log.error(
                    "array is missing x-path-var",
                    filename="tags.yaml",
                    line=tag_info.lc.line,
                )
                return
            path_comp = "{" + path_var_name + "}"
            subdomain_path = path + "/" + path_comp
            subdomain_schema_name = schema_name + "Item"
            self._translate_url_domain(
                domain[0], subdomain_path, subdomain_schema_name
            )

        self.pop_context()

    def _add_path(
        self, path: str, schema_name: str, json_type: str, tag_info: dict
    ):
        path_entry = self.paths.content.get(path, {})

        if self.context.path_vars:
            if "parameters" not in path_entry:
                path_entry["parameters"] = []
            parameters = path_entry["parameters"]
            for path_var_definition in self.context.path_vars.values():
                parameters.append(path_var_definition)

        path_info = self.path_info(tag_info)
        if path_info:
            update(path_entry, path_info, json_type)

        for method in self.context.methods:
            summary = METHOD_NAME[method] + " " + path
            op_id = schema_name + method.capitalize()

            method_entry = path_entry.get(method, {})
            method_entry[str(Key.TAGS)] = [path]
            method_entry[str(Key.SUMMARY)] = summary
            method_entry[str(Key.OPERATION_ID)] = op_id

            if method in (Method.PUT, Method.POST):
                method_entry["requestBody"] = {
                    "content": {
                        "application/json": {
                            "schema": {
                                "$ref": f"./schemas.yaml#/{schema_name}"
                            }
                        }
                    }
                }
            if method == Method.GET:
                response_schema = {
                    "type": "object",
                    "properties": {
                        "result": {"$ref": "./schemas.yaml#/" + schema_name},
                        "error": {"$ref": "./schemas.yaml#/ErrorString"},
                    },
                }
            else:
                response_schema = {"$ref": "./schemas.yaml#/StatusObject"}
            method_entry["responses"] = {
                "200": {
                    "description": "Normal response.",
                    "content": {
                        "application/json": {"schema": response_schema}
                    },
                },
                "401": {
                    "description": "Unauthorized response.",
                    "content": {
                        "application/json": {
                            "schema": {
                                "$ref": "./schemas.yaml#/UnauthorizedObject"
                            }
                        }
                    },
                },
            }

            method_info = self.method_info(tag_info, method)
            if method_info:
                update(method_entry, method_info, json_type)

            if method == Method.DELETE and Key.DESCRIPTION not in method_entry:
                method_entry[str(Key.DESCRIPTION)] = delete_desc(json_type)

            if method_entry:
                path_entry[method] = method_entry

        if path_entry:
            self.paths.content[path] = path_entry

    def _update_path_vars(self, tag_info: dict):
        path_var_def = tag_info.get(Key.X_PATH_VAR)
        if not path_var_def:
            return None

        var_name = path_var_def.get("name")
        if not var_name:
            self.log.error(
                "name missing from x-path-var",
                filename="tags.yaml",
                line=path_var_def.lc.line,
            )
            raise Error("name missing")
        if var_name in self.context.path_vars:
            self.log.error(
                f"duplicate parameter name `{var_name}'",
                filename="tags.yaml",
                line=path_var_def.lc.line,
            )
            raise Error("duplicate name")
        self.context.path_vars[var_name] = path_var_def
        return var_name

    def _add_schema(
        self,
        domain: URLDomain,
        schema_name: str,
        json_type: str,
        tag_info: dict,
        path_var_name: str,
    ):
        schema_entry = {}

        # For flat objects (type "unknown"), provide the type via an
        # x-schema tag in paths.yaml or tags.yaml.  See
        # /sys/status/{token}/result, for example.
        if json_type != "unknown":
            schema_entry["type"] = json_type

        if json_type == "object":
            if path_var_name:
                subdomain_schema_name = schema_name + camel_case(path_var_name)
                schema_entry["additionalProperties"] = {
                    "$ref": f"#/{subdomain_schema_name}"
                }
            else:
                props = {}
                for key in domain.keys():
                    subdomain_schema_name = schema_name + camel_case(key)
                    props[key] = {"$ref": f"#/{subdomain_schema_name}"}
                schema_entry["properties"] = props
        elif json_type == "array":
            item_name = schema_name + "Item"
            schema_entry["items"] = {"$ref": f"#/{item_name}"}

        schema_info = tag_info.get(Key.X_SCHEMA)
        if schema_info:
            # merge additional info from x-schema:
            update(schema_entry, schema_info, json_type)

        if Key.DESCRIPTION not in schema_entry:
            desc = tag_info.get(Key.DESCRIPTION)
            if desc:
                schema_entry[str(Key.DESCRIPTION)] = desc

        self.schemas.content[schema_name] = schema_entry


class OpenAPIBuilder:
    """Class to build an OpenAPI 3.1 spec.  It has two tasks: (1) remap
    relative links based on the chosen link-format and (2) translate
    URL domain info to OpenAPI.

    """

    def __init__(self, prog_name: str, link_format: LinkFormat):
        self.log = Logger(prog_name)
        self.link_format = link_format
        self.tags = None
        self.webapi_version = ""

    def build(self, output_dir: Path):
        """Build the OpenAPI 3.1 spec."""

        # read input files, patching intra-document links:
        openapi = YAMLFile("openapi")
        tag_list = YAMLFile("tags")
        params = YAMLFile("params")
        paths = YAMLFile("paths")
        schemas = YAMLFile("schemas")

        webapi_version = openapi.content["info"]["version"]
        self.webapi_version = f"/v{webapi_version}"

        # first, just create a dict of all tag names so map_link can check it:
        self.tags = {}
        for tag in tag_list.content:
            path = tag["name"]
            self.tags[path] = True

        tag_list.patch_relative_links(self.map_link)

        # now create actual tags info dictionary:
        for tag in tag_list.content:
            item = copy(tag)
            path = item["name"]
            del item["name"]
            self.tags[path] = item

        params.patch_relative_links(self.map_link)
        paths.patch_relative_links(self.map_link)
        schemas.patch_relative_links(self.map_link)

        with open("url-domains.json", encoding="utf-8") as f:
            url_domains = json.load(f)
        gen = URLDomainGenerator(self.log, self.tags, paths, schemas)
        gen.translate(url_domains)

        # pick up additional tag descriptions from x-schema-ref:

        for tag in tag_list.content:
            path = tag["name"]
            if Key.DESCRIPTION not in tag:
                desc = self.tags[path].get(Key.DESCRIPTION)
                if desc:
                    tag[str(Key.DESCRIPTION)] = desc

        # write out the patched file, removing any extension tags:

        params.strip_and_write(output_dir)
        paths.strip_and_write(output_dir)
        schemas.strip_and_write(output_dir)
        tag_list.strip_and_write(output_dir)

        if self.log.error_count:
            print(f"{self.log.prog_name}: {self.log.error_count} errors found")
            return 1
        return 0

    def map_link(self, target: str, filename: str, line: int, _) -> str:
        """Map the relative link target based on the selected link-format.
        The target must have one of the following formats:

          * `glossary:TERM`: Refers to glossary term `TERM`.
          * `path:PATH`: Refers to the description of path (endpoint) `PATH`.
          * `op:PATH:OPID`: refers to the operation with id `OPID` (as
              specified by key `operationId` which must be an operation for
              path `PATH`.

        """
        parts = target.split(":")

        if parts[0] == "glossary":
            section = parts[1].replace(" ", "-")
            if self.link_format == LinkFormat.REDOCLY_PREVIEW:
                return "/tag/Glossary#tag/Glossary/" + section
            return self.webapi_version + "/tag/Glossary#section/" + section

        if parts[0] == "path" or parts[0] == "op":
            path = parts[1]
            if path not in self.tags:
                self.log.error(
                    f"link target {path} does not exist in tags.yaml!",
                    filename=filename,
                    line=line,
                )
            slug = re.sub(r"[^a-z]", "", path, flags=re.IGNORECASE)
            if self.link_format == LinkFormat.REDOCLY_PREVIEW:
                uri = "#tag/" + slug
            else:
                uri = self.webapi_version + "/tag/" + slug
            if parts[0][0] == "p":
                return uri

            operation_id = parts[2]
            if self.link_format == LinkFormat.REDOCLY_PREVIEW:
                uri += "/operation/" + operation_id
            else:
                uri += self.webapi_version + "#operation/" + operation_id
            return uri

        self.log.error(
            f"invalid link target `{target}'", filename=filename, line=line
        )
        return target


def run():
    own_module = sys.modules[__name__]

    parser = argparse.ArgumentParser(
        description=own_module.__doc__,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "-o",
        "--output-directory",
        type=Path,
        default="built",
        help="The directory in which to store the output files.",
    )
    parser.add_argument(
        "-l",
        "--link-format",
        choices=list(LinkFormat),
        default=LinkFormat.REDOCLY_PREVIEW,
    )
    args = parser.parse_args()
    builder = OpenAPIBuilder(parser.prog, args.link_format)
    return builder.build(args.output_directory)


if __name__ == "__main__":
    sys.exit(run())
