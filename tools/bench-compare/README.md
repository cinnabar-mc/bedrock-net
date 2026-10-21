# Benchmark comparator

Joins `go test -bench -benchmem` text with criterion's
`target/criterion/**/new/{benchmark,estimates}.json` into one markdown table.
Names pair case-insensitively: criterion `group/case` matches Go
`BenchmarkGroup/case`. Go repeats (`-count`) use the median; criterion uses its
slope estimate, else the mean.

Flate and Snappy compression and decompression rows also compare complete wire
bytes, including batch headers. Rust may use at most 0.5% more bytes than Go;
this fixed allowance is independent of `--margin`. The Go benches report
`wire-B/op` after resetting the timer. The Rust batch bench records sizes outside
the timed loop in `new/wire-size.json`, alongside Criterion's estimates. Each
sidecar contains `full_id`, `wire_bytes`, and the SHA-256 of `estimates.json`.
Missing, invalid, inconsistent, or stale sizes fail validation. Every Go repeat
must report the same positive integer size; encoder and decoder rows for the
same input must also agree within each implementation. A separate size table
keeps wire bytes distinct from allocation `B/op`.

The batch benchmark explicitly uses `CRITERION_HOME`, then
`CARGO_TARGET_DIR/criterion`, then `target/criterion` as its output root. The
comparator uses the same defaults when `--criterion` is omitted. Use fresh
compression benchmark results: filtered, list-only and test-mode runs clear old
size records without replacing them unless new estimates were written. The
comparator never substitutes an older baseline or Go size for a missing record.

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
slower than Go by more than `--margin` percent (default 5), or a compression row
exceeds the fixed 0.5% wire-size allowance, on a validated set.
