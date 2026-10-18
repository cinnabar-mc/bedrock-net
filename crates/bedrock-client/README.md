# bedrock-client

Caller-driven Bedrock client negotiation over protocolgen's generated packet
types. The first owner, `packs::PackNegotiation`, accepts an offer, optional
caller-validated cache/CDN archives, and received packets. It produces bounded
chunk requests and completion responses, verifies in-band SHA-256, and returns
an owned archive handoff in the final server-selected stack order.

Call `start` after supplying preloaded archives, then pass received packets to
`receive`. Send each returned packet in order. Unrelated packets are returned to
the caller, so Disconnect, Transfer and other client phases retain one owner.
Cache workers must release shared archive references before the final stack.
Dropping the negotiation releases retained transfer state. No runtime, socket,
HTTP client, task, thread or clock is created by this crate.

This initial extraction does not yet own Login, encryption transitions, spawn
or play. Those client phases remain to be moved out of Cinnabar. Packet schemas
and codecs remain in protocolgen; this crate does not define replacement
packets. The extracted Cinnabar implementation retains its
[PolyForm Noncommercial license](../../LICENSE-CINNABAR).
