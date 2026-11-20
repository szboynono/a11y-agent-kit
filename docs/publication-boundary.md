# Source verification and test scope

a11y-agent-kit 0.1.2 is available from npm. Use Node.js 22.12+ and install matching Playwright Chromium as shown in the [npm quickstart](../README.md#run-your-first-audit-from-npm). The source tree also includes the local plugin, test suite, and verification scripts.

## Verify the source files

Run the verifier from the source directory.

```sh
node scripts/verify-source.mjs
```

The read-only verifier checks the byte counts and SHA-256 of files listed in [scripts/source-sha256.json](../scripts/source-sha256.json). Unlisted files are outside its scope. Git and installed dependencies are unnecessary for this check.

The [v0.1.1 tag](https://github.com/szboynono/a11y-agent-kit/tree/v0.1.1) pins the released source. Its manifest SHA-256 is `46af074c67c0f6ec9d5fa0b6568dd6e8db0aa5914e1456993c9227db4f084266`. If you received a source archive, compare its SHA-256 and the verifier's `manifestSha256` with digests you obtained separately. Compute the archive digest with `shasum -a 256 a11y-agent-kit-source.tar.gz`.

## Exercise the toolkit locally

- From the source tree, run `npm ci` and install matching Chromium. Then run `node scripts/quickstart.mjs`. It exercises CLI and stdio MCP on a synthetic loopback application, uses a synthetic review decision and writes fresh results under `evidence/byoa-quickstart/`.
- Run `npm test` for the included test suite. See [test coverage and omissions](test-coverage.md) for the exact coverage gaps.

## Recorded verification

The v0.1.1 verification record for source commit `20630208337fa1a0a4dd11a6edecfbfe73f612aa` covers all 116 listed files and a locked dependency install. The published npm tarball has SHA-256 `126858f997fe86598bd735ee62ed8d8e7cc6a39f1d25f8417d42da9d1d33c04c` and its 60 files match that commit. With the installed package and matching Chromium, the source quickstart passed all 13 checks on a synthetic loopback fixture in the recorded SDK and browser configuration.

The v0.1.0 source archive (SHA-256 `e29d21e4507d7b52812b17d701f909379c60740469b4baed804976b8550270c4`) matches the file contents of the [v0.1.0 tag](https://github.com/szboynono/a11y-agent-kit/tree/v0.1.0). On that archive, all 529 tests across 44 files passed and the synthetic quickstart completed in an instrumented environment.

The earlier source archive (SHA-256 `ef2963cbdadd588df274a8dda7fc16f3e7ba703de237219bf997f453396e4cc6`) passed source integrity checks. On those bytes, a clean install with matching Chromium completed, all 529 tests across 44 test files passed, and the synthetic quickstart completed. The suite and quickstart used an instrumented environment. Supplemental checks on the same archive verified nonempty CLI checkpoint recovery and submission, nonempty SDK checkpoint and submission, HTML reports and paginated inventory.

Historical site inputs, screenshots, responses, labels and results are outside this archive and its verifier's scope. Both the axe-reference calibration suite and the public-site calibration suite, including its template and patches, are omitted.

Source paths in the archive are relative to the extracted directory. Audit artifacts created by the toolkit use absolute, source-bound paths. Keep each audit with the project and evidence directory where it was produced.

## Accessibility claims

The default audit target is WCAG 2.2 AA. Audits describe the explored states and their evidence limits. SC 1.4.11 requires reproducible pixel measurements and review of the relevant graphic, adjacent colors and exceptions. SC 4.1.3 requires the ordered evidence chain for the same status result and review of its applicability. See the [evidence policy](../skills/a11y-audit/references/evidence-policy-v2.md).

On the earlier `ef2963cb` archive identified above, the CLI workflow on an owned loopback fixture recovered a checkpoint and explicitly submitted the recovered draft for independent review. Review confirmed one non-text contrast finding (SC 1.4.11) and one status-message finding (SC 4.1.3). A missing-evidence example for each stayed queued. The separate SDK stdio run used an explicitly supplied environment and left its proposal queued for review. Default SDK environment inheritance and cache discovery remain unverified.

The recorded workflow checks used owned loopback fixtures. Real third-party site validation remains open. The toolkit makes no whole-page or whole-site conformance, actual screen-reader announcement or comparative detection claim.

See the [license](../LICENSE) and [third-party notices](../THIRD_PARTY_NOTICES.md).
