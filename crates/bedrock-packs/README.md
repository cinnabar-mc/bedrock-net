# bedrock-packs

Runtime-independent resource-pack text decoding and archive ownership. JSONC
parsing preserves the existing client's UTF-8/Latin-1 text handling, comments
and trailing-comma rules. Archive handoffs retain server stack order, subpack
selection and required status; content keys are zeroized on drop and omitted
from diagnostic formatting.

This crate performs no filesystem, HTTP, rendering or packet I/O. Archive
validation and application remain caller responsibilities. The extracted
Cinnabar implementation retains its [PolyForm Noncommercial license](../../LICENSE-CINNABAR).
