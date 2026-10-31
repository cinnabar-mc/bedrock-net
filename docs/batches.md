# Batch framing and compression

`bedrock-net` accepts encoded packets and returns transport batches. Decode packet
headers and bodies with the matching generated protocol crate.

## Encode and decode

Each encoded input includes its packet header and omits the batch entry's length
prefix. One transport message carries one unprefixed batch.

Start with `BatchCodec<Plain>`. `encode` splits packets under the configured byte
and packet limits. `decode` validates every entry length before exposing packets:

| Result | Action |
| --- | --- |
| `DecodeOutcome::Packets` | Process entries in order; count `skipped_empty_packets`. |
| `DecodeOutcome::Dropped` | Count and log the compression failure, then continue. |
| `BatchError` | Handle the framing or limit failure; no partial packet list was returned. |

`BatchPackets` is an iterator whose `Bytes` entries share the decoded allocation.
Keep its cursor between reads instead of collecting unread entries. A small
retained slice can keep the whole allocation alive. Preserve unread entries ahead
of later network input when negotiation changes state.

## Install compression

After network settings arrive, consume the plain codec with `negotiate` to obtain
`BatchCodec<Negotiated>`. Compression cannot be reset or negotiated again on that
codec. Outgoing batches use the selected algorithm and threshold; incoming
batches use their declared algorithm. The protocol's Zlib name selects raw DEFLATE.

Use `BatchLimits::max_decoded_bytes` for the incoming decoded-byte ceiling.
Outgoing batches split at `max_packets`; set `max_outgoing_decoded_bytes` to
`Some(bytes)` for an additional outgoing byte ceiling. Its default is `None`,
so an incoming allowance does not split outgoing data. `max_encoded_bytes`
applies to both directions. Set `max_incoming_packets` for a separate incoming
packet-count ceiling. Empty incoming entries are skipped and counted.

You can give negotiated incoming batches a different decoded-byte ceiling:

```rust
use bedrock_net::{BatchCodec, CompressionSettings, Negotiated};

fn install_settings(
    plain: BatchCodec,
    settings: CompressionSettings,
    incoming_decoded_bytes: usize,
) -> BatchCodec<Negotiated> {
    plain.negotiate(settings)
        .with_incoming_decoded_limit(incoming_decoded_bytes)
}
```

This preserves outgoing, encoded-wire and packet-count limits. Plain decoding
continues to use `BatchLimits::max_decoded_bytes`. Packet-field limits, transport
receive budgets and the application's deferred queue need their own bounds.

## Reuse buffers

Keep one codec per connection to reuse scratch storage. `decode_with` validates
the full batch, then visits borrowed packet bytes through a callback. Use `decode`
when packets must outlive the call. `encode_into` can reuse uncompressed buffers
after a batch group has been sent; shared batches retain their bytes. Keep unsent
batches until emission completes before recycling it.

Native DEFLATE encoding uses libdeflate at level 6 and requires a C compiler.
Decoding uses zlib-rs; WebAssembly also uses zlib-rs level 6 for encoding. DEFLATE
engines are temporary per call. Snappy uses the `snap` crate, reusing its tables
and, for batches up to 64 KiB, its output for each independent block. Compatible
encoders may produce different compressed bytes.
