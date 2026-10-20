# Benchmark comparator

Joins `go test -bench -benchmem` text with criterion's
`target/criterion/**/new/{benchmark,estimates}.json` into one markdown table and
exits 1 when a Rust benchmark is slower than its Go counterpart by more than
`--margin` percent (default 5), or 3 when a measurement is missing. Names pair
case-insensitively: criterion `group/case` matches Go `BenchmarkGroup/case`, with
the shared `-N` GOMAXPROCS suffix removed. Go repeats (`-count`) use the median; criterion uses its slope
estimate, else the mean.

```sh
go test -run '^$' -bench . -benchmem ./... > go-bench.txt
cargo bench --bench <name>
go run github.com/cinnabar-mc/bedrock-net/tools/bench-compare@<commit> \
  --go go-bench.txt --criterion target/criterion >> "$GITHUB_STEP_SUMMARY"
```

Until this module is on `dev`, `go run module@commit` fails its `latest`
deprecation lookup; pin it from a module instead with
`go get -tool github.com/cinnabar-mc/bedrock-net/tools/bench-compare@<commit>`
and run `go tool bench-compare`.

Exit 3 means either side read no results, a path has no counterpart and is
not declared with `--one-sided PATH` (repeatable), or a declared one-sided path
is missing or now has both sides. Exit status 2 means unreadable input.
