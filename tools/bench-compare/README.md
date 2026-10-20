# Benchmark comparator

Joins `go test -bench -benchmem` text with criterion's
`target/criterion/**/new/{benchmark,estimates}.json` into one markdown table.
Names pair case-insensitively: criterion `group/case` matches Go
`BenchmarkGroup/case`. Go repeats (`-count`) use the median; criterion uses its
slope estimate, else the mean.

Run the Go benchmarks with an explicit `-cpu N` and pass the same `--go-procs N`;
the comparator strips exactly `-N` when N > 1 and rejects any name without it.

```sh
go test -run '^$' -bench . -benchmem -cpu 4 ./... > go-bench.txt
cargo bench --bench <name>
go run github.com/cinnabar-mc/bedrock-net/tools/bench-compare@<commit> \
  --go-procs 4 --go go-bench.txt --criterion target/criterion >> "$GITHUB_STEP_SUMMARY"
```

Until this module is on `dev`, `go run module@commit` fails its `latest`
deprecation lookup; pin it from a module instead with
`go get -tool github.com/cinnabar-mc/bedrock-net/tools/bench-compare@<commit>`
and run `go tool bench-compare`.

Inputs are validated before timings are compared. Exit status 2 means unreadable
or malformed input; 3 means a missing measurement: either side read no results,
a path has no counterpart and is not declared with `--one-sided PATH`
(repeatable), or a declaration is unknown or now has both sides; 1 means Rust is
slower than Go by more than `--margin` percent (default 5) on a validated set.
