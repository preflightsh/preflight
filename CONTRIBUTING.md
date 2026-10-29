# Contributing

Thanks for helping with Preflight. Bug reports, false-positive reports,
and pull requests are all welcome.

## Build, test, and lint

You need the Go version named in `go.mod`.

```sh
go build ./...
go vet ./...
go test ./... -race
golangci-lint run
gofmt -l cmd internal main.go   # should print nothing
```

CI runs the same steps on Linux, macOS, and Windows, plus govulncheck,
ShellCheck on `install.sh`, short fuzz runs, and a container smoke test.

## The JSON output is a contract

`preflight scan --format json` is ingested by the dashboard at
app.preflight.sh, which lives in a different repository. The golden test
in `internal/output/output_test.go` pins the exact bytes of that output.

If the golden test fails, do not just update the expected string. A
golden failure means the dashboard has to change too: a renamed key, a
dropped field, or a new check ID needs a matching change there (and a
`schema_version` bump if existing consumers would misread the output).
Say so in the pull request.

## Pull requests

- Keep changes focused, and add a test for any bug you fix.
- For a new check or a change to what a check flags, include a small
  fixture that shows the case.
- Security problems go through private reporting, not issues or pull
  requests. See [SECURITY.md](SECURITY.md).
