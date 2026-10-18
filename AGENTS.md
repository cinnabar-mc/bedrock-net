# Repository guidance

Keep the workspace independent of Cinnabar and rendering engines. The
`bedrock-net` foundation accepts encoded packet bytes; `bedrock-client` owns
client negotiation using protocolgen's generated packet models and codecs.
`bedrock-packs` owns reusable pack text and archive handoff, independently of
packet models or runtimes. Do not define replacement gameplay packet schemas.
Introduce crate boundaries only when components have meaningful independent
consumers.

Preserve observed compatibility fixes from the pinned behavior baseline. Read
the relevant implementation before changing wire behavior. Do not claim vanilla
compatibility without version-matched evidence and real connection validation.
Keep private research and agent reports outside this public checkout. Preserve
accurate license notices when adapting external code.

Use focused tests for framing, limits, state transitions and regressions. Tests
use synthetic or redistributable data, require no credentials, and never sleep.
Run `cargo fmt --all --check`, `cargo test --locked -p bedrock-net`, and
`cargo clippy --locked -p bedrock-net --all-targets -- -D warnings` before review.
Use the installed shared build limiter where available.

The Go oracle is a small independent test helper; its module pin identifies the
compatibility baseline. Generated fixtures are updated through that helper.
Never add gameplay packet definitions or Go runtime networking to this library.
