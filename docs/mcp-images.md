# Original PNGs over MCP

`a11y_audit_request` accepts optional top-level `imageOutput: "path" | "inline"`.
Omission and `"path"` preserve existing responses for all requests. `"inline"`
is allowed only with `request.tool: "view"`. Other modes or combinations are
rejected before calling the agent. Clients without image support use path mode
and a local image viewer.

```json
{"runId":"<session run ID>","imageOutput":"inline","request":{"tool":"view","evidenceId":"ev-0001"}}
```

Opting in sends the original page pixels to the requesting MCP client. Those
pixels can contain sensitive content. The client must actually read the image
before making visual claims; delivery is not proof of inspection, currentness,
accessibility conformance, or independent review. No upload service, model call,
recapture, resize, automatic screenshot, or confirmation step is involved.

A successful reply contains the same bounded text/structured metadata (at most
20,000 bytes of UTF-8 text over MCP), including evidence ID, state ID, document ID, original
path, byte length and SHA-256, plus `imageOutput` delivery status, dimensions and
limits. There is exactly one additional standard MCP content block:
`{type:"image", mimeType:"image/png", data:"<base64>"}`. Base64 is confined to
that block, never text, structured JSON, logs, or persisted artifacts. The shared
agent and CLI/direct JSONL protocol are unchanged. The view costs one existing
agent request and zero additional browser actions.

Inline transmission accepts at most 2 MiB (2,097,152 bytes) of raw PNG and
16,000,000 pixels, inclusive. The implementation supports Chromium's
non-interlaced 8-bit RGB/RGBA originals; other encodings refuse explicitly.
Invalid PNG signature/chunks/checksums/raster, unsupported encoding, missing
original, size violations or file verification failures produce an error and
no image block. `imageOutput.delivered:false` reports an inline refusal after
agent dispatch; it must not be treated as successful visual inspection.
The image limits bound the inline payload, **not the whole agent process**:
agent.view's unchanged original verification may read up to 256 MiB first.
Raster validation also transiently decompresses the PNG within its pixel bound.

After agent verification, the MCP adapter reads only the registered original in
the canonical same-session directory. It rejects symlinks and nonregular files,
uses a bounded file-descriptor read, checks descriptor/path stability and exact
registered length/SHA-256, and validates the very buffer emitted. Paths from
caller input are never accepted. These checks preserve the existing same-UID
trust boundary; they are not OS attestation against a hostile process able to
modify the running tool or its memory. No review, privacy, currentness or budget
rules are relaxed. Refused images can be opened separately through unchanged
path mode when a local viewer is available.

Tests distinguish actual MCP stdio + first-party Chromium screenshots from
synthetic unit boundary fixtures. Actual image-capable host visual benefit
remains untested.
