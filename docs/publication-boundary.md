# Source verification and test scope

a11y-agent-kit is supplied as source. [Install from the extracted directory](../README.md#install) with Node.js 22.12 or later and npm. The lockfile pins the dependencies and Playwright version. Install the matching Chromium separately. Platform support has yet to be established.

The source includes a local plugin entry. Source installation is the documented distribution method. The hosting destination and the location for independently obtaining checksums are undecided.

## Verify the source files

Obtain the archive and the source manifest SHA-256 digests independently of the archive before relying on them. Compute the archive digest with `shasum -a 256 a11y-agent-kit-source.tar.gz` and compare it with the separately supplied archive digest. Extract the archive and run this from the extracted directory:

```sh
node scripts/verify-source.mjs
```

Compare the reported `manifestSha256` with the independently obtained digest for [scripts/source-sha256.json](../scripts/source-sha256.json). The read-only verifier detects missing or changed files listed in that manifest using byte counts and SHA-256. Unlisted files are outside its scope. Git and installed dependencies are unnecessary for this check.

The project can rebuild the archive using pinned local build inputs. Those inputs are kept separately. Recipients can verify the supplied archive and extracted source and run the included quickstart.

## Exercise the toolkit locally

- With the locked dependencies and matching Chromium installed, run `node scripts/quickstart.mjs`. It exercises CLI and stdio MCP on a synthetic loopback application, uses a synthetic review decision and writes fresh results under `evidence/byoa-quickstart/`.
- Run `npm test` for the included test suite. See [test coverage and omissions](test-coverage.md) for the exact coverage gaps.

The earlier source archive (SHA-256 `ef2963cbdadd588df274a8dda7fc16f3e7ba703de237219bf997f453396e4cc6`) passed source integrity checks. On those bytes, a clean install with matching Chromium completed, all 529 tests across 44 test files passed, and the synthetic quickstart completed. The suite and quickstart used an instrumented environment. Supplemental checks on the same archive verified nonempty CLI checkpoint recovery and submission, nonempty SDK checkpoint and submission, HTML reports and paginated inventory.

The revised archive will undergo separate engineering verification on its own bytes, including a clean install, the full suite and the quickstart.

Historical site inputs, screenshots, responses, labels and results are outside this archive and its verifier's scope. Both the axe-reference calibration suite and the public-site calibration suite, including its template and patches, are omitted.

Source paths in the archive are relative to the extracted directory. Audit artifacts created by the toolkit use absolute, source-bound paths. Keep each audit with the project and evidence directory where it was produced.

## Accessibility claims

The default audit target is WCAG 2.2 AA. Audits describe the explored states and their evidence limits. SC 1.4.11 requires reproducible pixel measurements and review of the relevant graphic, adjacent colors and exceptions. SC 4.1.3 requires the ordered evidence chain for the same status result and review of its applicability. See the [evidence policy](../skills/a11y-audit/references/evidence-policy-v2.md).

On the earlier archive, the CLI workflow on an owned loopback fixture recovered a checkpoint and explicitly submitted the recovered draft for independent review. Review confirmed one non-text contrast finding (SC 1.4.11) and one status-message finding (SC 4.1.3). A missing-evidence example for each stayed queued. The separate SDK stdio run used an explicitly supplied environment and left its proposal queued for review. Default SDK environment inheritance and cache discovery remain unverified.

No real third-party sites were tested in this round, and that verification remains open. The toolkit makes no whole-page or whole-site conformance, actual screen-reader announcement or comparative detection claim.

See the [license](../LICENSE) and [third-party notices](../THIRD_PARTY_NOTICES.md).
