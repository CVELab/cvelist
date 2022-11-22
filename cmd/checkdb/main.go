// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Command checkdb validates Go vulnerability databases.
package main

import (
	"flag"
	"log"

	"golang.org/x/vulndb/internal/database"
)

var (
	path = flag.String("path", "", "path to database")
)

func main() {
	flag.Parse()
	if *path == "" {
		log.Fatalf("flag -path must be set")
	}
	if err := database.Validate(*path); err != nil {
		log.Fatal(err)
	}
}
