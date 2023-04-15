import os
import sys
from github import Github

# Get GitHub API token from environment variable
api_token = os.environ.get("GITHUB_TOKEN")

if not api_token:
    sys.exit("Error: Missing GITHUB_TOKEN environment variable")

# Authenticate with the GitHub API
g = Github(api_token)

# Get all advisories
advisories = g.get_advisories()

# Convert advisories to Markdown format
for advisory in advisories:
    cve_id = advisory.identifiers.get("CVE", {}).get("id", "N/A")
    product = advisory.affected_package_ranges[0].package_name if advisory.affected_package_ranges else "N/A"
    description = advisory.summary
    pocs = advisory.references.get("poc", [])
    pocs_md = "\n".join([f"- {poc}" for poc in pocs])
    github_link = advisory.html_url

    # Write output to STDOUT
    print(f"### [{cve_id}]({github_link})")
    print(f"![](https://img.shields.io/static/v1?label=Product&message={product}&color=blue)")
    print("![](https://img.shields.io/static/v1?label=Version&message=n%2Fa&color=blue)")
    print("![](https://img.shields.io/static/v1?label=Vulnerability&message=n%2Fa&color=brighgreen)\n")
    print(f"### Description\n\n{description}\n")
    if pocs_md:
        print("### POC\n")
        print(f"#### Reference\n{pocs_md}\n")
    print(f"#### GitHub\n{github_link}\n")
