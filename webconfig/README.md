# Go Vulnerability Database Web Configuration

These files control what users see when they visit https://vuln.go.dev, and
when they get a 404 on that site.

## Deployment

After these files are modified and the CL has been submitted, copy them to the
vuln DB bucket:
```
gsutil cp index.html 404.html gs://go-vulndb
```

## Initial Setup

The go-vulndb bucket must be configured to display these pages. That can be done
with
```
gsutil web set -m index.html -e 404.html gs://go-vulndb
```
Use `gsutil web get gs://go-vulndb` to display the configuration.
