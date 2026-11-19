# Local agent session

Copy `audit-agent-manifest.json`, set the canonical project root and already-running URL, and keep it under the site's `evidence/`. Do not include an `actions` array. Start one persistent process:

```sh
node /absolute/tool/src/cli.js audit-agent /absolute/site/evidence/agent-manifest.json
```

Write one operation per stdin line. Read each response before choosing dependent actions:

```json
{"tool":"step","actions":[{"action":"snapshot"}]}
{"tool":"read","evidenceId":"ev-0001","options":{"view":"nodes","fields":["tag","attributes","text","rect"]}}
```

Every page identifies the original evidence/document/state and original truncation. Follow `pagination.next` exactly. Read a deferred field using its returned handle; concatenate field-page `data`, then parse the resulting JSON. Cursors belong to this process. Every attempt, page and saved draft consumes the60-call allowance; actions have a separate180 limit.

Choose further actions from actual page evidence and the complete selected WCAG rubric (default 2.2 AA; 2.1/2.2 and A/AA supported). For an image, first perform a screenshot and use its actual returned evidence ID:

```json
{"tool":"step","actions":[{"action":"screenshot"}]}
{"tool":"view","evidenceId":"ev-0002"}
```

`view` returns the verified original PNG path/hash. Open that file using the host's own image viewer. PNG bytes are not inserted into text responses. A64KiB text limit does not change original file bytes or imply complete observation.

Save candidate findings early with `checkpoint`. The proposal shape is `{"auditor":{"name":"Your auditor"},"findings":[...]}` with actual node/evidence references and the ordinary finding fields in the [audit skill](../skills/a11y-audit/SKILL.md). An empty draft is legal but says nothing about accessibility. The ACK contains immutable version, path and digest; continue exploring and save revised versions as needed. It is not a confirmed finding or a completed audit.

Explicitly submit an acknowledged version using its exact digest:

```json
{"tool":"submit","checkpointDigest":"sha256:REPLACE_WITH_THE_ACKNOWLEDGED_DIGEST"}
```

Alternatively, send `submit` with an explicit `proposal`. Submission seals the collection and stays `needs_review`; independent reviewer evidence and the [v2 prerequisites](../skills/a11y-audit/references/evidence-policy-v2.md) are required for confirmation. `inspect` records the target's ancestor semantics for a status-message claim; inspect both sides of its real triggering operation.

`{"command":"finish"}` or EOF closes without creating a proposal. SIGINT/SIGTERM or deadline also preserve an incomplete outcome. Acknowledged drafts remain recoverable; neither a draft nor a late proposal becomes timely completed delivery automatically.

```sh
node /absolute/tool/src/cli.js audit-checkpoint-read /absolute/site/evidence/audit-UUID/audit-checkpoint-00000002.json
node /absolute/tool/src/cli.js audit-submit-checkpoint /absolute/site/evidence/audit-UUID/audit-ID.json /absolute/site/evidence/audit-UUID/audit-checkpoint-00000002.json
```

The second command is a new explicit submission with persisted recovery provenance, followed by normal independent review. The original timeout and its incomplete result remain in the collection. Draft/needs-review commands use exit1 intentionally; inspect their JSON rather than discarding it. Whole-page/whole-site conformance and real screen-reader behavior remain unassessed.
