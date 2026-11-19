# Test coverage and omissions

From the source tree, `npm test` selects the 44 included test files. The 529-test results apply to the two exact source archives listed in [recorded verification](publication-boundary.md#recorded-verification). The v0.1.1 record covers source integrity, installation, and the synthetic quickstart. Omitted files and cases are coverage gaps.

Multibyte stress tests use non-CJK samples.

## Test files omitted in full

| File | Coverage absent from this suite |
| --- | --- |
| `test/codex-host.test.js` | Codex-host integration and calibration backed by the host harness and public-site inputs. |
| `test/natural-delivery.test.js` | Delivery validation for the retained natural-site records and inputs. |
| `test/natural-pack.test.js` | Historical Git, manifest and natural-site verification closure. |
| `test/audit-step-accounting.test.js` | Mixed default-product and alternate-profile accounting. This includes failed or unperformed operations, dispatch rejection and full-batch reservation, and charging one inspect-many action for several returned nodes. |
| `test/audit-v2-transport.test.js` | Mixed default and alternate-profile transport. This includes the default budget/schema and proposal-size comparisons, post-seal unsubmitted correction behavior and default next-step guidance. |

## Thin-icon fixtures and cases omitted

The seven HTML files under `test/fixtures/nontext-icons/` are omitted while their source and distribution rights remain unconfirmed. The included [test/audit-nontext.test.js](../test/audit-nontext.test.js) retains its independent inline cases. Eleven cases that read these files are excluded from the source suite.

| Omitted fixture | Page-specific scenarios excluded |
| --- | --- |
| `thin-icons-a.html` | a1–a10 |
| `thin-icons-b.html` | b1–b6 |
| `thin-icons-c.html` | c1 |
| `thin-icons-d1.html` | d1–d13 |
| `thin-icons-d2.html` | d14–d18 |
| `thin-icons-e.html` | e1–e10, e4b and e8c |
| `thin-icons-f.html` | p0–p5 and t1 |

The seven page regressions checked exact contrast pairs, ordering, ratios, warning sets, painted-color matching, fallback refusal and replay of contrast requests when applicable. Four additional cases checked reviewer-observed wrong-ratio refusals, the warning set on the original measurement path, exact warning and explanation behavior around fallback and faded or touching colors (a10, e3, e7), and glyph paint accounting for empty geometry versus horizontal lines (e8, e8c, e9, e10).

## Calibration and retained-record cases omitted

- [test/audit-axe-passthrough.test.js](../test/audit-axe-passthrough.test.js) omits the portion that used the upstream axe-reference label fixture to check five-row pages, unique and complete candidate enumeration, invalid cursor and unsupported option errors, and rejection on a snapshot record. It retains the separate pre-existing 400-button portion of that test for bounded responses and continuation paging. The upstream button-name fixture case for direct submit mixing axe adoption with a hand-authored finding is also omitted. Both upstream inputs are outside the bundle.
- [test/audit-projection.test.js](../test/audit-projection.test.js) omits two optional cases that require retained natural-site records. These checked original-byte preservation, complete node paging of a multi-megabyte SVG record and bounded reads that preserve snapshot text, inspected nodes and spacing from three original records. The pre-existing generated projection cases remain in the suite.
