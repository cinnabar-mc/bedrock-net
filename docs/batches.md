# Batch framing and encryption

`bedrock-net` accepts encoded packets and returns transport batches. Decode packet
headers and bodies with the matching generated protocol crate.

## Encode and decode

Each encoded input includes its packet header and omits the batch entry's length
prefix. `BatchHeader::Prefixed` includes the transport marker;
`BatchHeader::NetherNet` has no marker. One transport message carries one batch.

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

Use `BatchLimits` to set an encoded-wire ceiling, decoded-byte limit and outgoing
packet count. Incoming packets use the byte bounds by default; set
`max_incoming_packets` for a separate nonempty packet-count ceiling. Empty
incoming entries are skipped and counted.

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

## Install ciphers

`BatchEncryptor` and `BatchDecryptor` each retain a continuous AES-256-CTR stream
and checksum counter. Keep both for the connection. Their `encrypt_batch` and
`decrypt_batch` methods accept complete batches and preserve the clear transport
marker. Check the encoded-byte ceiling before decryption, then decrypt before
decompressing. Owned `Bytes` can be changed in place; shared inputs are copied.

For a client, `ClientKeyExchange::into_parts` returns the next negotiation state,
optional ciphers and acknowledgment. Install both cipher directions before
sending that acknowledgment. On the server, flush the token in plaintext before
installing its ciphers and reading the acknowledgment. A DTLS transport can
disable the additional batch cipher while still verifying the handshake token.

Never restart a cipher or discard output after advancing its stream. Retain
ciphertext until local emission completes; re-encoding its plaintext would
advance the stream again. An integrity failure invalidates that cipher direction.
A compression drop still consumes the received encrypted batch's stream position.
The [Tokio connection](../crates/bedrock-client-tokio/src/connection.rs) handles
these operations on one codec and cipher pair.

## Reuse buffers

Keep one codec per connection to reuse scratch storage. `decode_with` validates
the full batch, then visits borrowed packet bytes through a callback. Use `decode`
when packets must outlive the call. `encode_into` can reuse uncompressed buffers
after a batch group has been sent; shared batches retain their bytes. Keep unsent
ciphertext until emission completes before recycling it.

Native DEFLATE encoding uses libdeflate at level 6 and requires a C compiler.
Decoding uses zlib-rs; WebAssembly also uses zlib-rs level 6 for encoding. DEFLATE
engines are temporary per call. Snappy uses the `snap` crate, reusing its tables
and, for batches up to 64 KiB, its output for each independent block. Compatible
encoders may produce different compressed bytes.
