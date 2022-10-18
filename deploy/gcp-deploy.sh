#!/bin/bash
# Copyright 2021 The Go Authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

set -e

gsutil -m cp -r /workspace/db/* gs://go-vulndb
gsutil cp webconfig/*.html webconfig/*.ico gs://go-vulndb
