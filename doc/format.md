# Vulnerability Report Format

The Go vulnerability report format is used to generate JSON files
served to the the vulnerability database.

This file format is meant for internal use only, and is subject to
change without warning. See [golang.org/x/vuln](https://golang.org/x/vuln)
for information on the Go Vulnerability database API.

This page documents the internal YAML file format.

## `packages`

type [Package[]](#type-package)

**required** 

Information on each package affected by the vulnerability.

## Type **Package**

### `module`

type `string`

**required** 

The module path of the vulnerable module.

### `package`

type `string`

**required (if different from `module`)**

The import path of the vulnerable module.

### `symbols`

type `string[]`

The symbols affected by this vulnerability.

If included, only programs which use these symbols will be marked as
vulnerable. If omitted, any program which imports this module will be
marked vulnerable.

These should be the symbols initially detected or identified in the CVE
or other source.

### `derived_symbols`

type `string[]`

Derived symbols that are calculated from `symbols`,
such as by static analysis tools like `govulncheck`.

Potentially, the set of derived symbols can differ with the module
version. We don't attempt to capture that level of detail. Most of the
values of `derived_symbols` as of this writing were obtained from a
module version that was just prior to the version that the report
listed as fixed.

### `versions`

type [`VersionRange[]`](#type-versionrange)

The version ranges in which the package is vulnerable.

If the vulnerability is fixed in multiple major versions, then there
should be multiple `versions` entries.

If omitted, it is assumed that _every_ version of the module is
vulnerable.

Versions must be SemVer 2.0.0 versions, with no "v" or "go" prefix.
Version ranges must not overlap.

### Type **VersionRange**

#### `introduced`

type `string`

The version at which the vulnerability was introduced.

If this field is omitted, it is assumed that every version, from the
initial commit, up to the `fixed` version is vulnerable.

#### `fixed`

type `string`

The version at which the vulnerability was fixed.

If this field is omitted, it is assumed that every version since the
`introduced` version is vulnerable.

## `description`

type `string`

**required**

A textual description of the vulnerability and its impact. Should be
wrapped to 80 columns.

## `cves`

type `string[]`

The Common Vulnerabilities and Exposures (CVE) ID(s) for the
 vulnerability.

## `ghsas`

type `string[]`

The GitHub Security Advisory (GHSA) IDs for the vulnerability.

## `credit`

The name of the person/organization that discovered/reported the
 vulnerability.

## `links`

type [`Links`](#type-links)

Links to further information about the vulnerability.

## Type **Links**

### `commit`

type `string`

A link to the commit which fixes the vulnerability.

### `pr`

type `string`

A link to the PR/CL which fixes the vulnerability.

### `context`

type `string[]`

Additional links which provide more context about the vulnerability,
i.e. GitHub issues, vulnerability reports, etc.

## Example Reports

### Third-party example report

```yaml
packages:
  - module: github.com/example/module
    package: github.com/example/module/package
    symbols:
      - Type.MethodA
      - MethodB
    versions:
      # The vulnerability is present in all versions since version v0.2.0.
      - introduced: 0.2.0
      # The vulnerability is present in all versions up to version v0.2.5.
      - fixed: 0.2.5
    # Major versions must be explicitly specified
  - module: github.com/example/module/v2
    symbols:
      - MethodB
    versions:
      - fixed: 2.5.0
  - module: github.com/example/module/v3
    symbols:
      - MethodB
    versions:
      - introduced: 3.0.1
description: |
  A description of the vulnerability present in this module.

  The description can contain newlines, and a limited set of markup.
cves:
  - CVE-2021-3185
ghsas:
  - GHSA-1234-5678-9101
credit:
  - John Smith
links:
  - commit: https://github.com/example/module/commit/aabbccdd
  - pr: https://github.com/example/module/pull/10
  - context:
      - https://www.openwall.com/lists/oss-security/2016/11/03/1
      - https://github.com/example/module/advisories/1
```

### Standard library example report

```yaml
packages:
  - module: std
    package: a/package
    symbols:
      - pkg.ASymbol
    versions:
      - introduced: 1.14
        fixed: 1.14.12
      - introduced: 1.15
        fixed: 1.15.5
description: |
    A description.
cves:
  - CVE-2020-12345
links:
    pr: https://go.dev/cl/12345
    commit: https://go.googlesource.com/go/+/12345678
    context:
      - https://go.dev/issue/01010
      - https://groups.google.com/g/golang-announce/c/123456
```
