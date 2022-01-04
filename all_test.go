// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.17 && !windows
// +build go1.17,!windows

package main

import (
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/vulndb/internal/report"
)

func TestChecksBash(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skipf("skipping: %v", err)
	}

	cmd := exec.Command(bash, "./checks.bash")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
}

const reportsDir = "reports"

func TestLintReports(t *testing.T) {
	if runtime.GOOS == "js" {
		t.Skipf("wasm builder does not have network access")
	}
	if runtime.GOOS == "android" {
		t.Skipf("android builder does not have access to reports/")
	}
	reports, err := ioutil.ReadDir(reportsDir)
	if err != nil {
		t.Fatalf("unable to read reports/: %s", err)
	}
	for _, rf := range reports {
		if rf.IsDir() {
			continue
		}
		t.Run(rf.Name(), func(t *testing.T) {
			fn := filepath.Join(reportsDir, rf.Name())
			lints, err := report.LintFile(fn)
			if err != nil {
				t.Fatal(err)
			}
			if len(lints) > 0 {
				t.Errorf(strings.Join(lints, "\n"))
			}
		})
	}
}
