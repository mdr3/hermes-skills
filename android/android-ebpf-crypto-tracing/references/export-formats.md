# Traffic export formats (HAR 1.2, Burp/ZAP/Caido XML)

When a capture tool must hand traffic to another tool, render from ONE parsed
transaction struct and give it two renderers — never parse the stream twice.
Both formats are import-only artifacts: nothing is negotiated at export time.

## HAR 1.2 with HTTP/2

H2 entries follow RFC 9113 fields, not h1 conventions:

- `request.httpVersion` and `response.httpVersion` = `"h2"`.
- All header names lowercased (RFC 9113 §8.2).
- Pseudo-headers first, in order — request `:method`, `:authority`, `:scheme`,
  `:path`; response `:status`.
- `response.statusText` = `""` (no reason phrase on the wire).
- `headersSize: -1` when HPACK-framed header bytes are not measurable; keep
  `bodySize` real.
- Custom keys underscore-prefixed (`_streamId`) per HAR extensibility rules.

h1 path stays untouched: reason phrases, original header casing, real sizes.
Branch on the captured version; do not "normalize" h1 into the h2 shape.

## Burp bulk XML

Root `<items burpVersion="<ver>" exportTime="…">`, one `<item>` per exchange,
children in this order: `time`, `url`, `host ip="…"`, `port`, `protocol`,
`method`, `path`, `extension`, `request base64="true"`, `status`,
`responselength`, `mimetype`, `response base64="true"`, `comment`.

- `time`/`exportTime` format `Mon Jan _2 15:04:05 UTC 2006` in UTC.
- Put `url`, `method`, `path` and both base64 payloads in CDATA; escape host
  text and attributes.
- `host ip=""` when unresolved; `extension` literal `null` when absent;
  `port` defaults 443/80 from the scheme; `mimetype` maps content-type to
  `JSON|HTML|script|CSS|XML|Other`.
- No response captured: still emit the item with `status 0`, empty response,
  length 0, mimetype `Other`.

## h2 → h1 inside the base64 payload

Burp only accepts CRLF raw HTTP in the payload and re-negotiates h2 on replay,
so the encoded request must read `METHOD PATH HTTP/1.1\r\nHost: <:authority>\r\n`
+ remaining headers + `\r\n` + body, and the response `HTTP/1.1 <code> <reason>`.
Drop every `:`-prefixed header, take path/status from `:path`/`:status`, decode
base64 bodies before embedding (never base64-of-base64).

## Gates

- Decode the exported payload in a test and compare it byte-for-byte with the
  expected CRLF text; parse the whole document (JSON/XML unmarshal) so malformed
  escaping and child order fail loudly.
- An empty result set must still produce a valid empty document.
- Filtering belongs to the caller: export reuses the same query/filter layer as
  the list view, just without paging, and streams with an attachment filename.
