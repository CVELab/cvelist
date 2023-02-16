// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package report

import (
	"errors"
	"regexp"
	"strings"

	"encoding/json"

	"golang.org/x/vulndb/internal/cveschema"
	"golang.org/x/vulndb/internal/derrors"
	"golang.org/x/vulndb/internal/stdlib"
)

// ToCVE creates a CVE from a reports/GO-YYYY-NNNN.yaml file.
func ToCVE(reportPath string) (_ *cveschema.CVE, err error) {
	defer derrors.Wrap(&err, "report.ToCVE(%q)", reportPath)

	r, err := ReadAndLint(reportPath)
	if err != nil {
		return nil, err
	}
	if r.CVEMetadata == nil {
		return nil, errors.New("cve_metadata must be present to convert a report to a CVE")
	}

	description := r.CVEMetadata.Description
	if description == "" {
		description = r.Description
	}

	c := &cveschema.CVE{
		DataType:    "CVE",
		DataFormat:  "MITRE",
		DataVersion: "4.0",
		Metadata: cveschema.Metadata{
			ID:       r.CVEMetadata.ID,
			Assigner: "security@golang.org",
			State:    cveschema.StatePublic,
		},

		Description: cveschema.Description{
			Data: []cveschema.LangString{
				{
					Lang:  "eng",
					Value: removeNewlines(description),
				},
			},
		},

		ProblemType: cveschema.ProblemType{
			Data: []cveschema.ProblemTypeDataItem{
				{
					Description: []cveschema.LangString{
						{
							Lang:  "eng",
							Value: r.CVEMetadata.CWE,
						},
					},
				},
			},
		},
	}

	for _, m := range r.Modules {
		var pkgData []cveschema.ProductDataItem
		for _, p := range m.Packages {
			pkgData = append(pkgData,
				cveschema.ProductDataItem{
					ProductName: p.Package,
					Version:     versionToVersion(m.Versions),
				})
		}
		c.Affects.Vendor.Data = append(c.Affects.Vendor.Data, cveschema.VendorDataItem{
			VendorName: getVendor(m.Module),
			Product: cveschema.Product{
				Data: pkgData,
			},
		})
	}

	for _, ref := range r.References {
		c.References.Data = append(c.References.Data, cveschema.Reference{URL: ref.URL})
	}

	goAdvisory := GetGoAdvisoryLink(GetGoIDFromFilename(reportPath))
	c.References.Data = append(c.References.Data, cveschema.Reference{URL: goAdvisory})

	c.RawCredit, err = json.Marshal([]cveschema.LangString{{
		Lang:  "eng",
		Value: removeNewlines(r.Credit),
	}})
	if err != nil {
		return nil, err
	}

	return c, nil
}

func getVendor(modulePath string) string {
	switch modulePath {
	case stdlib.ModulePath:
		return "Go standard library"
	case stdlib.ToolchainModulePath:
		return "Go toolchain"
	default:
		return modulePath
	}
}

// removeNewlines removes leading and trailing space characters and
// replaces inner newlines with spaces.
func removeNewlines(s string) string {
	newlines := regexp.MustCompile(`\n+`)
	return newlines.ReplaceAllString(strings.TrimSpace(s), " ")
}

func versionToVersion(versions []VersionRange) cveschema.VersionData {
	vd := cveschema.VersionData{}
	for _, vr := range versions {
		if vr.Introduced != "" {
			vd.Data = append(vd.Data, cveschema.VersionDataItem{
				VersionValue:    string(vr.Introduced),
				VersionAffected: ">=",
			})
		}
		if vr.Fixed != "" {
			vd.Data = append(vd.Data, cveschema.VersionDataItem{
				VersionValue:    string(vr.Fixed),
				VersionAffected: "<",
			})
		}
	}
	return vd
}

// CVEToReport creates a Report struct from a given CVE and modulePath.
func CVEToReport(c *cveschema.CVE, modulePath string) *Report {
	var description string
	for _, d := range c.Description.Data {
		description += d.Value + "\n"
	}
	var refs []*Reference
	for _, r := range c.References.Data {
		refs = append(refs, referenceFromUrl(r.URL))
	}
	var credits []string
	for _, v := range c.Credit.Data.Description.Data {
		credits = append(credits, v.Value)
	}
	credit := strings.Join(credits, "\t")

	var pkgPath string
	if data := c.Affects.Vendor.Data; len(data) > 0 {
		if data2 := data[0].Product.Data; len(data2) > 0 {
			pkgPath = data2[0].ProductName
		}
	}
	if stdlib.Contains(modulePath) {
		pkgPath = modulePath
		modulePath = stdlib.ModulePath
	}
	if modulePath == "" {
		modulePath = "TODO"
	}
	if pkgPath == "" {
		pkgPath = modulePath
	}
	r := &Report{
		Modules: []*Module{{
			Module: modulePath,
			Packages: []*Package{{
				Package: pkgPath,
			}},
		}},
		Description: description,
		Credit:      credit,
		References:  refs,
	}
	// New standard library and x/ repo CVEs are likely maintained by
	// the Go CNA.
	if stdlib.IsStdModule(modulePath) || stdlib.IsCmdModule(modulePath) ||
		stdlib.IsXModule(modulePath) {
		r.CVEMetadata = &CVEMeta{
			ID:  c.Metadata.ID,
			CWE: "TODO",
		}
	} else {
		r.CVEs = []string{c.Metadata.ID}
	}
	r.Fix()
	return r
}
