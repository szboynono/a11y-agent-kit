import * as fs from 'node:fs/promises';
import path from 'node:path';
import { reviewPolicyOf } from './review-policy.js';
import { reviewPlacement, findingGaps, GAP_STATES, GAP_ITEMS } from './gaps.js';
import { suspectedDuplicateGroups } from './precheck.js';
import { createHash, randomUUID } from 'node:crypto';
import { deriveAuditInventory } from './inventory.js';
import { ToolError } from '../evidence.js';
import { stableSelectorIndex, STABLE_SELECTOR_CONFIDENCE } from './stable-selector.js';

// Pure rendering: reads only local report/evidence files, never the network or a model. Output is built from a
// fixed whitelist of report fields, so retained-record fields (node values, attributes, axe HTML) cannot leak in.
export const REPORT_LIMITS = Object.freeze({
  text: 2000, selector: 500, findings: 2000, missing: 20,
  imageBytes: 1024 * 1024, imagesTotalBytes: 6 * 1024 * 1024, images: 24, evidenceFileBytes: 32 * 1024 * 1024,
});
const KINDS = { 'audit-review': 'reviewed', 'audit-proposal': 'proposal', 'audit-checkpoint-1': 'checkpoint' };
const EVIDENCE_ID = /^ev-\d{4,12}$/;
const PNG_SIGNATURE = Buffer.from('89504e470d0a1a0a', 'hex');
const STATUS_LABEL = { confirmed: 'Confirmed', needs_review: 'Needs review', rejected: 'Rejected by reviewer' };

const esc = value => String(value ?? '').replace(/[&<>"']/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[ch]);
const clipDefault = (value, limit = REPORT_LIMITS.text) => {
  const text = typeof value === 'string' ? value : value === undefined || value === null ? '' : JSON.stringify(value);
  const chars = [...text.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '�')];
  return chars.length > limit ? `${chars.slice(0, limit).join('')}… [truncated]` : chars.join('');
};
const clip = clipDefault;
// Bounded delivery preserves all whitelisted text; only unsafe control characters are replaced.
const fullText = value => (typeof value === 'string' ? value : value == null ? '' : JSON.stringify(value)).replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '�');
const array = value => Array.isArray(value) ? value : [];
const criterionKey = id => String(id ?? '').split('.').map(part => part.padStart(3, '0')).join('.');
const safeW3cUrl = url => typeof url === 'string' && /^https:\/\/www\.w3\.org\/[\w\-./#?=%]*$/.test(url) ? url : null;

// Design tokens: the single source for the report's CSS custom properties and for the contrast unit test.
export const REPORT_TOKENS = Object.freeze({
  light: Object.freeze({
    bg: '#f4f5f7', surface: '#ffffff', 'surface-2': '#eff1f4', text: '#14171c', 'text-2': '#4a515d', border: '#d6dae1', 'border-strong': '#7a8291',
    accent: '#2747b0', 'on-accent': '#ffffff', pending: '#7a4100', 'pending-bg': '#fff3dc', 'pending-mark': '#a86200', ok: '#16653a', 'ok-bg': '#e5f4ea',
    reject: '#555b66', 'reject-bg': '#eceef1', 'notice-bg': '#fff8e8', 'notice-border': '#a86200', focus: '#2747b0', 'bar-agent': '#4a515d',
  }),
  dark: Object.freeze({
    bg: '#0f1114', surface: '#171a1f', 'surface-2': '#1f232a', text: '#e7e9ed', 'text-2': '#a9b0bc', border: '#2c313a', 'border-strong': '#6f7786',
    accent: '#9db3ff', 'on-accent': '#0f1114', pending: '#f3c46e', 'pending-bg': '#2a2010', 'pending-mark': '#d29a32', ok: '#7fd6a2', 'ok-bg': '#11261a',
    reject: '#b3b9c4', 'reject-bg': '#23262c', 'notice-bg': '#221b0e', 'notice-border': '#d29a32', focus: '#9db3ff', 'bar-agent': '#a9b0bc',
  }),
});

/** Foreground/background token pairs the report actually draws, with the WCAG ratio each must meet (text 4.5, graphics 3). */
export const REPORT_CONTRAST_PAIRS = Object.freeze([
  ['text', 'bg', 'body text on page', 4.5], ['text', 'surface', 'body text on card', 4.5], ['text', 'surface-2', 'code and hover row text', 4.5],
  ['text-2', 'bg', 'secondary text on page', 4.5], ['text-2', 'surface', 'secondary text on card', 4.5], ['text-2', 'surface-2', 'secondary text on subtle fill', 4.5],
  ['accent', 'surface', 'link text on card', 4.5], ['accent', 'bg', 'link text on page', 4.5], ['on-accent', 'accent', 'skip link text', 4.5],
  ['pending', 'pending-bg', 'needs-review badge text', 4.5], ['pending', 'surface', 'pending text on card', 4.5], ['pending', 'notice-bg', 'notice icon glyph', 4.5],
  ['text', 'notice-bg', 'notice body text', 4.5], ['ok', 'ok-bg', 'confirmed badge text', 4.5], ['reject', 'reject-bg', 'rejected badge text', 4.5],
  ['pending-mark', 'surface', 'needs-review mark and dashed border', 3], ['pending-mark', 'pending-bg', 'needs-review dot inside badge', 3],
  ['border-strong', 'surface', 'bar outline, tag borders and swatches', 3], ['border-strong', 'bg', 'outlines on page', 3],
  ['border-strong', 'surface-2', 'empty-state frame on subtle fill', 3], ['notice-border', 'notice-bg', 'notice border', 3],
  ['notice-border', 'surface', 'notice border against masthead', 3], ['accent', 'surface-2', 'axe-adopted bar segment against track', 3],
  ['bar-agent', 'surface', 'agent-found hatched swatch', 3], ['ok', 'surface', 'confirmed bar segment', 3], ['reject', 'surface', 'rejected bar segment', 3],
  ['ok', 'ok-bg', 'confirmed dot inside badge', 3], ['reject', 'reject-bg', 'rejected square inside badge', 3],
  ['focus', 'surface', 'focus ring on card', 3], ['focus', 'bg', 'focus ring on page', 3], ['focus', 'surface-2', 'focus ring on hovered summary', 3],
  ['text', 'bg', 'criterion group rule', 3],
  ['ok', 'surface-2', 'confirmed bar segment against track', 3], ['pending-mark', 'surface-2', 'needs-review bar segment against track', 3],
  ['reject', 'surface-2', 'rejected bar segment against track', 3], ['bar-agent', 'surface-2', 'agent-found bar segment against track', 3],
]);

const tokenVars = theme => Object.entries(REPORT_TOKENS[theme]).map(([name, value]) => `--${name}:${value}`).join(';');

// Self-contained styles: no external fonts or images, no viewport-height units, print forces the light tokens.
export const REPORT_CSS = `:root{color-scheme:light dark;${tokenVars('light')};--fs-xs:.8125rem;--fs-sm:.875rem;--fs-base:1rem;--fs-md:1.125rem;--fs-lg:1.375rem;--fs-xl:1.75rem;--fs-kpi:2rem;--lh-tight:1.25;--lh:1.5;--s1:.25rem;--s2:.5rem;--s3:.75rem;--s4:1rem;--s5:1.5rem;--s6:2rem;--s7:3rem;--r1:3px;--r2:6px;--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;--sans:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
@media (prefers-color-scheme:dark){:root{${tokenVars('dark')}}}
*,*::before,*::after{box-sizing:border-box}
html{-webkit-text-size-adjust:100%;scroll-padding-top:var(--s4)}
body{margin:0;font:var(--fs-base)/var(--lh) var(--sans);color:var(--text);background:var(--bg);overflow-wrap:break-word}
h1,h2,h3,h4{line-height:var(--lh-tight);margin:0;font-weight:650}
p,ul,ol,dl,figure{margin:0}
a{color:var(--accent);text-underline-offset:.18em;text-decoration-thickness:1px}
a:hover{text-decoration-thickness:2px}
code{font-family:var(--mono);font-size:.875em;overflow-wrap:anywhere;word-break:break-word}
:focus-visible{outline:3px solid var(--focus);outline-offset:2px;border-radius:var(--r1)}
.sr-only{position:absolute!important;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap;border:0}
.skip{position:absolute;left:var(--s4);top:-10rem;z-index:10;background:var(--accent);color:var(--on-accent);padding:var(--s2) var(--s4);border-radius:var(--r2);font-weight:600;text-decoration:none}
.skip:focus{top:var(--s4)}
.wrap{max-width:76rem;margin:0 auto;padding:0 var(--s4)}
@media (min-width:44rem){.wrap{padding:0 var(--s5)}}
.masthead{background:var(--surface);border-bottom:1px solid var(--border);padding:var(--s3) 0 var(--s4)}
.eyebrow{font-size:var(--fs-xs);font-weight:600;letter-spacing:.06em;text-transform:uppercase;color:var(--text-2)}
.title-row{display:flex;flex-wrap:wrap;align-items:center;gap:var(--s2) var(--s3);margin:var(--s1) 0 var(--s3)}
h1{font-size:var(--fs-xl)}
.state{display:inline-flex;align-items:center;gap:var(--s2);font-size:var(--fs-sm);font-weight:600;padding:.125rem var(--s3);border:1px dashed var(--pending-mark);border-radius:999px;color:var(--pending);background:var(--pending-bg)}
.state-reviewed{border:1px solid var(--ok);color:var(--ok);background:var(--ok-bg)}
.meta{display:grid;grid-template-columns:minmax(0,1fr);gap:var(--s3) var(--s4);margin-bottom:var(--s3)}
.meta div{min-width:0}.meta .wide{grid-column:1/-1}
@media (min-width:44rem){.meta{grid-template-columns:repeat(2,minmax(0,1fr));gap:var(--s1) var(--s5)}.meta div{display:grid;grid-template-columns:7.5rem minmax(0,1fr);gap:var(--s3);align-items:baseline}.meta dt{font-size:var(--fs-sm);font-weight:500}}
.meta dt{font-size:var(--fs-xs);color:var(--text-2);font-weight:600}
.meta dd{margin:0;font-size:var(--fs-sm);overflow-wrap:anywhere}
.notice{display:grid;grid-template-columns:auto minmax(0,1fr);gap:var(--s3);align-items:start;background:var(--notice-bg);border:1px solid var(--notice-border);border-left-width:4px;border-radius:var(--r2);padding:var(--s3) var(--s4);font-size:var(--fs-sm)}
.notice-icon{width:1.25rem;height:1.25rem;border:2px solid var(--notice-border);border-radius:50%;display:grid;place-items:center;font-weight:700;font-size:.75rem;color:var(--pending);margin-top:.0625rem}
.layout{display:grid;gap:var(--s4);padding-top:var(--s4);padding-bottom:var(--s5)}
.layout>*{min-width:0}
@media (min-width:64rem){.layout{grid-template-columns:13.5rem minmax(0,1fr);gap:var(--s6)}.toc{position:sticky;top:var(--s4);align-self:start;max-height:42rem;overflow:auto}}
main{display:grid;gap:var(--s5)}
main:focus{outline:none}
main>section{min-width:0}
section>h2{font-size:var(--fs-lg);margin-bottom:var(--s2)}
.lede{color:var(--text-2);font-size:var(--fs-sm);max-width:44rem;margin-bottom:var(--s3)}
.toc{font-size:var(--fs-sm);background:var(--surface);border:1px solid var(--border);border-radius:var(--r2);padding:var(--s3) var(--s4)}
.toc h2{font-size:var(--fs-xs);text-transform:uppercase;letter-spacing:.06em;color:var(--text-2);margin-bottom:var(--s2)}
.toc ol{list-style:none;padding:0;display:grid;gap:2px}
.toc ol ol{margin:2px 0 var(--s1) var(--s3);padding-left:var(--s3);border-left:1px solid var(--border)}
.toc a{display:flex;justify-content:space-between;gap:var(--s2);padding:.3125rem var(--s2);border-radius:var(--r1);color:var(--text);text-decoration:none}
.toc a:hover{background:var(--surface-2);text-decoration:underline}
.toc .n{font-variant-numeric:tabular-nums;color:var(--text-2)}
@media (max-width:63.99rem){.toc{display:flex;flex-wrap:wrap;align-items:baseline;gap:var(--s1) var(--s3);padding:var(--s2) var(--s3)}.toc h2{margin:0}.toc ol{display:flex;flex-wrap:wrap;gap:2px var(--s1)}.toc li{display:flex;flex-wrap:wrap;align-items:baseline}.toc ol ol{margin:0;padding-left:var(--s1);border-left:0}.toc a{gap:var(--s1);padding:.25rem .4375rem}.toc ol ol a{color:var(--text-2)}}
.pager{display:flex;flex-wrap:wrap;align-items:baseline;gap:var(--s1) var(--s4);font-size:var(--fs-sm);background:var(--surface);border:1px solid var(--border);border-radius:var(--r2);padding:var(--s2) var(--s4);margin-bottom:var(--s3)}
.pager p{color:var(--text-2)}
.pages{padding-left:1.25rem;display:grid;gap:var(--s1);margin-top:var(--s2)}
.dash{display:grid;gap:var(--s3);grid-template-columns:minmax(0,1fr)}
@media (min-width:44rem){.dash{grid-template-columns:minmax(0,1fr) minmax(0,1.2fr)}}
.panel{background:var(--surface);border:1px solid var(--border);border-radius:var(--r2);padding:var(--s3) var(--s4);display:grid;gap:var(--s2);align-content:start;min-width:0}
.panel h3{font-size:var(--fs-sm);font-weight:600;color:var(--text-2)}
.metric{display:grid;gap:var(--s2)}.metric h4{font-size:var(--fs-xs);font-weight:600;color:var(--text-2)}
.big{display:flex;align-items:baseline;gap:var(--s2);flex-wrap:wrap}
.big b{font-size:var(--fs-kpi);line-height:1;font-weight:700;font-variant-numeric:tabular-nums}
.big span{color:var(--text-2);font-size:var(--fs-sm)}
.bar{display:flex;height:.75rem;border-radius:var(--r1);overflow:hidden;background:var(--surface-2);border:1px solid var(--border-strong)}
.bar i{display:block;height:100%}
.sw{display:inline-block;width:.75rem;height:.75rem;border-radius:2px;flex:none;border:1px solid var(--border-strong)}
.sw-axe{background:var(--accent);border-color:var(--accent)}
.sw-agent{background:repeating-linear-gradient(135deg,var(--bar-agent) 0 2px,transparent 2px 5px);border-color:var(--bar-agent)}
.sw-pending{background:repeating-linear-gradient(135deg,var(--pending-mark) 0 3px,var(--pending-bg) 3px 6px);border-color:var(--pending-mark)}
.sw-ok{background:var(--ok);border-color:var(--ok)}.sw-reject{background:var(--reject);border-color:var(--reject)}
.legend{display:flex;flex-wrap:wrap;gap:var(--s1) var(--s4);font-size:var(--fs-sm)}
.legend div{display:flex;align-items:center;gap:var(--s2)}
.legend dt{display:flex;align-items:center;gap:var(--s2)}
.legend dd{margin:0;font-weight:650;font-variant-numeric:tabular-nums}
.legend .zero dd,.legend .zero dt{color:var(--text-2);font-weight:400}
table{border-collapse:collapse;width:100%;font-size:var(--fs-sm)}
caption{text-align:left;font-size:var(--fs-xs);color:var(--text-2);padding-bottom:var(--s2);caption-side:top}
th,td{text-align:left;padding:var(--s2) var(--s2) var(--s2) 0;border-bottom:1px solid var(--border);vertical-align:top}
thead th{font-size:var(--fs-xs);color:var(--text-2);font-weight:600;border-bottom-color:var(--border-strong)}
td.num,th.num{text-align:right;font-variant-numeric:tabular-nums;padding-right:0}
.sc-cell{display:flex;align-items:center;justify-content:flex-end;gap:var(--s2)}.sc-track{flex:1;max-width:7rem;display:block}.sc-bar{display:block;height:.5rem;background:var(--accent);border-radius:1px;min-width:2px}
.callout{display:flex;flex-wrap:wrap;gap:var(--s1) var(--s2);align-items:baseline;font-size:var(--fs-sm);border:1px solid var(--border-strong);border-left:4px solid var(--pending-mark);border-radius:var(--r2);background:var(--surface);padding:var(--s2) var(--s4);margin-top:var(--s2)}
.callout strong{white-space:nowrap}
.sc-group{display:grid;gap:var(--s2);min-width:0}
.sc-group+.sc-group{margin-top:var(--s3)}
.sc-h{display:flex;flex-wrap:wrap;align-items:baseline;gap:var(--s1) var(--s3);padding-bottom:var(--s2);border-bottom:2px solid var(--text)}
.sc-h h3{font-size:var(--fs-md)}
.sc-h h3 a{color:var(--text)}
.sc-id,.sc-h h3>a{font-family:var(--mono);font-weight:600}
.sc-meta{font-size:var(--fs-sm);color:var(--text-2)}
.finding{overflow-wrap:anywhere;background:var(--surface);border:1px solid var(--border);border-radius:var(--r2);padding:var(--s3) var(--s4);display:grid;gap:var(--s2);scroll-margin-top:var(--s4);min-width:0}
.finding:target{border-color:var(--accent);box-shadow:0 0 0 2px var(--accent)}
.f-head{display:grid;gap:var(--s2)}
.f-title{font-size:var(--fs-base);font-weight:650}
.tags{list-style:none;padding:0;display:flex;flex-wrap:wrap;gap:var(--s1) var(--s2);font-size:var(--fs-xs)}
.tags li{display:inline-flex;align-items:center;gap:.375rem;padding:.0625rem var(--s2);border:1px solid var(--border-strong);border-radius:var(--r1);color:var(--text);background:var(--surface);line-height:1.5;min-width:0}
.tags .k{color:var(--text-2)}
.status{font-weight:650}
.status::before{content:"";width:.625rem;height:.625rem;border-radius:50%;flex:none}
.tags .s-needs_review{color:var(--pending);background:var(--pending-bg);border:1px dashed var(--pending-mark)}
.s-needs_review::before{border:2px solid var(--pending-mark);background:linear-gradient(90deg,var(--pending-mark) 50%,transparent 50%)}
.tags .s-confirmed{color:var(--ok);background:var(--ok-bg);border-color:var(--ok)}
.s-confirmed::before{background:var(--ok);border:2px solid var(--ok)}
.tags .s-rejected{color:var(--reject);background:var(--reject-bg)}
.s-rejected::before{border:2px solid var(--reject);border-radius:1px}
.facts{display:grid;gap:var(--s2) var(--s4);grid-template-columns:minmax(0,1fr);font-size:var(--fs-sm)}
@media (min-width:44rem){.facts{grid-template-columns:minmax(0,.8fr) minmax(0,1.3fr) minmax(0,1.2fr)}.facts .wide{grid-column:1/-1}}
.facts div{min-width:0}
.facts dt{font-size:var(--fs-xs);color:var(--text-2);font-weight:600}
.facts dd{margin:0;overflow-wrap:anywhere}
.facts .target code{font-size:.9375rem;font-weight:600;background:var(--surface-2);padding:.0625rem .375rem;border-radius:var(--r1)}
.obs{line-height:1.55}
.disc{display:flex;flex-wrap:wrap;gap:var(--s2)}
.disc details{border:1px solid var(--border-strong);border-radius:var(--r2);background:var(--surface);min-width:0;max-width:100%}
.disc details[open]{flex-basis:100%;border-color:var(--border)}
.disc summary{list-style:none;cursor:pointer;display:flex;flex-wrap:wrap;align-items:center;gap:var(--s1) var(--s2);padding:.375rem var(--s3) .375rem var(--s2);font-size:var(--fs-sm);font-weight:600;min-height:2.25rem;border-radius:var(--r2)}
.disc summary::-webkit-details-marker{display:none}
.box>summary::-webkit-details-marker{display:none}
.disc summary::before,.box>summary::before{content:"";width:.4375rem;height:.4375rem;border-right:2px solid currentColor;border-bottom:2px solid currentColor;transform:rotate(-45deg);margin:0 .25rem 0 .125rem;flex:none;transition:transform .12s}
.disc details[open]>summary::before,.box[open]>summary::before{transform:rotate(45deg)}
.disc summary:hover{background:var(--surface-2)}
.disc summary:focus-visible{outline-offset:1px}
.dm{font-weight:400;color:var(--text-2);font-size:var(--fs-xs)}
.disc details[open] .dm{margin-left:auto}
.db{min-width:0;padding:0 var(--s3) var(--s3) 2.125rem;font-size:var(--fs-sm);display:grid;gap:var(--s2)}
.db ol,.db ul{padding-left:1.25rem;display:grid;gap:var(--s1)}
.db .ids{display:flex;flex-wrap:wrap;gap:var(--s1) var(--s2);list-style:none;padding:0}
.ids code{background:var(--surface-2);padding:.0625rem .375rem;border-radius:var(--r1)}
.hint{font-size:var(--fs-xs);color:var(--text-2)}
.db h5{font-size:var(--fs-xs);font-weight:600;color:var(--text-2);line-height:var(--lh-tight);margin:0}
.gaps{list-style:none;padding:0;display:grid;gap:var(--s1)}
.shots{display:grid;grid-template-columns:repeat(auto-fill,minmax(min(100%,9rem),1fr));gap:var(--s2)}
.shot img{display:block;max-width:100%;height:auto;border:1px solid var(--border-strong);border-radius:var(--r1)}
.shot figcaption{font-size:var(--fs-xs);color:var(--text-2);margin-top:var(--s1)}
.empty{display:flex;gap:var(--s3);align-items:center;border:1px dashed var(--border-strong);border-radius:var(--r2);padding:var(--s2) var(--s3);color:var(--text-2);font-size:var(--fs-xs);background:var(--surface-2)}
.empty-frame{flex:none;width:2.5rem;height:1.75rem;border:2px solid var(--border-strong);border-radius:2px;background:linear-gradient(to top right,transparent calc(50% - 1px),var(--border-strong) calc(50% - 1px) calc(50% + 1px),transparent calc(50% + 1px))}
.f-foot{display:flex;flex-wrap:wrap;gap:var(--s1) var(--s3);font-size:var(--fs-xs);color:var(--text-2);align-items:baseline}
.f-foot a{color:var(--text-2)}
.inv-stats{display:flex;flex-wrap:wrap;gap:var(--s2);list-style:none;padding:0;margin-bottom:var(--s3);font-size:var(--fs-sm)}
.inv-stats li{background:var(--surface);border:1px solid var(--border);border-radius:var(--r1);padding:.125rem var(--s2)}
.inv-stats b{font-variant-numeric:tabular-nums}
.box{background:var(--surface);border:1px solid var(--border);border-radius:var(--r2)}
.box>summary{list-style:none;cursor:pointer;padding:var(--s3) var(--s4);font-weight:600;font-size:var(--fs-sm);display:flex;align-items:center;gap:var(--s2)}
.box>summary:focus-visible{outline-offset:-3px}
.inv-list{display:grid;gap:var(--s3);padding:0 var(--s4) var(--s4);grid-template-columns:minmax(0,1fr)}
@media (min-width:64rem){.inv-list{grid-template-columns:repeat(2,minmax(0,1fr))}}
.inventory-row{border:1px solid var(--border);border-radius:var(--r2);padding:var(--s3);display:grid;gap:var(--s2);background:var(--bg);min-width:0}
.inventory-row h3{font-size:var(--fs-xs);font-weight:600;overflow-wrap:anywhere}
.inventory-row h3 code{font-size:var(--fs-xs)}
.kv{display:grid;grid-template-columns:max-content minmax(0,1fr);gap:.125rem var(--s3);font-size:var(--fs-xs)}
.kv dt{color:var(--text-2)}.kv dd{margin:0;overflow-wrap:anywhere}
.tablewrap{background:var(--surface);border:1px solid var(--border);border-radius:var(--r2);padding:var(--s3) var(--s4);overflow-wrap:anywhere}
.tablewrap td code{font-size:var(--fs-xs)}
.na{color:var(--text-2)}
.base{display:block;margin-top:var(--s1)}
.scope{background:var(--surface);border:1px solid var(--border-strong);border-radius:var(--r2);padding:var(--s4)}
.scope ul{padding-left:1.25rem;display:grid;gap:var(--s2)}
.scope .note{margin-top:var(--s3);font-size:var(--fs-sm);color:var(--text-2)}
.colophon{border-top:1px solid var(--border);background:var(--surface);padding:var(--s3) 0 var(--s4);font-size:var(--fs-xs);color:var(--text-2)}
.colophon p+p{margin-top:var(--s2)}
.colophon code{color:var(--text)}
@media (prefers-reduced-motion:reduce){*,*::before,*::after{transition:none!important}}
@media (forced-colors:active){.bar i,.sw,.sc-bar{forced-color-adjust:none}.status::before,.disc summary::before,.box>summary::before{border-color:CanvasText}}
@media print{:root{${tokenVars('light')}}
@page{margin:16mm 14mm}
body{background:#fff;font-size:10.5pt}
.skip,.toc,.pager{display:none!important}
.layout{display:block;padding:0}
main{display:block}main>section{margin-top:8mm}
.masthead{border-bottom:2px solid #000;padding-top:0}
.wrap{max-width:none;padding:0}
.finding,.inventory-row,.panel,.callout,.notice,tr{break-inside:avoid;page-break-inside:avoid}
.finding{margin-top:3mm;border-color:#999}
.sc-h,h2,h3,h4{break-after:avoid}
details>summary::before{display:none}
.disc details{flex-basis:100%;border-color:#bbb}
.disc summary{min-height:0;padding-bottom:0}
.sc-h h3 a::after{content:" (" attr(href) ")";font-size:8pt;font-weight:400;font-family:var(--mono);word-break:break-all}
.finding:target{box-shadow:none}
.bar,.sw,.sc-bar,.status::before{-webkit-print-color-adjust:exact;print-color-adjust:exact}
a{color:inherit}}
@media print{details::details-content{content-visibility:visible;display:block}}`;

// Read-only WCAG 2.2 success criterion names (plus 4.1.1 from WCAG 2.1). Used only when the coverage catalog supplies no name.
const SC_NAMES = Object.freeze({
  '1.1.1': 'Non-text Content', '1.2.1': 'Audio-only and Video-only (Prerecorded)', '1.2.2': 'Captions (Prerecorded)',
  '1.2.3': 'Audio Description or Media Alternative (Prerecorded)', '1.2.4': 'Captions (Live)', '1.2.5': 'Audio Description (Prerecorded)',
  '1.2.6': 'Sign Language (Prerecorded)', '1.2.7': 'Extended Audio Description (Prerecorded)', '1.2.8': 'Media Alternative (Prerecorded)',
  '1.2.9': 'Audio-only (Live)', '1.3.1': 'Info and Relationships', '1.3.2': 'Meaningful Sequence', '1.3.3': 'Sensory Characteristics',
  '1.3.4': 'Orientation', '1.3.5': 'Identify Input Purpose', '1.3.6': 'Identify Purpose', '1.4.1': 'Use of Color', '1.4.2': 'Audio Control',
  '1.4.3': 'Contrast (Minimum)', '1.4.4': 'Resize Text', '1.4.5': 'Images of Text', '1.4.6': 'Contrast (Enhanced)',
  '1.4.7': 'Low or No Background Audio', '1.4.8': 'Visual Presentation', '1.4.9': 'Images of Text (No Exception)', '1.4.10': 'Reflow',
  '1.4.11': 'Non-text Contrast', '1.4.12': 'Text Spacing', '1.4.13': 'Content on Hover or Focus', '2.1.1': 'Keyboard',
  '2.1.2': 'No Keyboard Trap', '2.1.3': 'Keyboard (No Exception)', '2.1.4': 'Character Key Shortcuts', '2.2.1': 'Timing Adjustable',
  '2.2.2': 'Pause, Stop, Hide', '2.2.3': 'No Timing', '2.2.4': 'Interruptions', '2.2.5': 'Re-authenticating', '2.2.6': 'Timeouts',
  '2.3.1': 'Three Flashes or Below Threshold', '2.3.2': 'Three Flashes', '2.3.3': 'Animation from Interactions', '2.4.1': 'Bypass Blocks',
  '2.4.2': 'Page Titled', '2.4.3': 'Focus Order', '2.4.4': 'Link Purpose (In Context)', '2.4.5': 'Multiple Ways',
  '2.4.6': 'Headings and Labels', '2.4.7': 'Focus Visible', '2.4.8': 'Location', '2.4.9': 'Link Purpose (Link Only)',
  '2.4.10': 'Section Headings', '2.4.11': 'Focus Not Obscured (Minimum)', '2.4.12': 'Focus Not Obscured (Enhanced)',
  '2.4.13': 'Focus Appearance', '2.5.1': 'Pointer Gestures', '2.5.2': 'Pointer Cancellation', '2.5.3': 'Label in Name',
  '2.5.4': 'Motion Actuation', '2.5.5': 'Target Size (Enhanced)', '2.5.6': 'Concurrent Input Mechanisms', '2.5.7': 'Dragging Movements',
  '2.5.8': 'Target Size (Minimum)', '3.1.1': 'Language of Page', '3.1.2': 'Language of Parts', '3.1.3': 'Unusual Words',
  '3.1.4': 'Abbreviations', '3.1.5': 'Reading Level', '3.1.6': 'Pronunciation', '3.2.1': 'On Focus', '3.2.2': 'On Input',
  '3.2.3': 'Consistent Navigation', '3.2.4': 'Consistent Identification', '3.2.5': 'Change on Request', '3.2.6': 'Consistent Help',
  '3.3.1': 'Error Identification', '3.3.2': 'Labels or Instructions', '3.3.3': 'Error Suggestion',
  '3.3.4': 'Error Prevention (Legal, Financial, Data)', '3.3.5': 'Help', '3.3.6': 'Error Prevention (All)', '3.3.7': 'Redundant Entry',
  '3.3.8': 'Accessible Authentication (Minimum)', '3.3.9': 'Accessible Authentication (Enhanced)', '4.1.1': 'Parsing',
  '4.1.2': 'Name, Role, Value', '4.1.3': 'Status Messages',
});
/** Catalog-supplied name first, then the static WCAG table; null means show only "SC x.y.z". */
export const criterionName = (id, catalogRow) => (typeof catalogRow?.title === 'string' && catalogRow.title.trim() ? catalogRow.title
  : Object.hasOwn(SC_NAMES, id) ? SC_NAMES[id] : null);

function fail(message) { throw new ToolError('INVALID_AUDIT_REPORT', message); }

// Optional maker notes are read only when present and nonempty; absence renders nothing, never "none".
const NOTE_ITEMS = 10;
function findingNotes(finding) {
  const items = array(finding?.counterevidence).filter(item => typeof item === 'string' && item.trim());
  const rationale = typeof finding?.confidenceRationale === 'string' && finding.confidenceRationale.trim() ? finding.confidenceRationale : undefined;
  return { ...(items.length ? { counterevidence: items } : {}), ...(rationale ? { confidenceRationale: rationale } : {}) };
}

/** Normalize a checkpoint, needs-review proposal or reviewed report into one finding list. */
export function normalizeAuditReport(report) {
  const mode = report && typeof report === 'object' ? KINDS[report.kind] : undefined;
  if (!mode) fail('Expected an audit-review, audit-proposal or audit-checkpoint-1 JSON file.');
  const source = mode === 'checkpoint' ? report.proposal : report;
  if (!source || !Array.isArray(source.findings)) fail('The report has no findings array.');
  // Shared with the JSON summary (gaps.js), so both views place and label a finding the same way.
  const placement = reviewPlacement(report), { decisions, placed, reReview } = placement;
  const findings = source.findings.map(finding => {
    const hit = placed.get(finding?.id), row = hit?.row ?? finding;
    const status = placement.statusOf(finding?.id);
    const decision = row.decision ?? decisions.get(finding.id);
    return {
      id: finding.id, title: finding.title, criterionId: finding.criterionId,
      source: finding.source === 'axe' ? 'axe' : 'agent', status,
      method: finding.method, target: finding.target ?? {}, selector: row.targetObservation?.selector,
      ...(typeof row.targetObservation?.stableSelector === 'string' && STABLE_SELECTOR_CONFIDENCE.includes(row.targetObservation.stableSelectorConfidence)
        ? { stableSelector: row.targetObservation.stableSelector, stableSelectorConfidence: row.targetObservation.stableSelectorConfidence, stableSelectorCheck: row.targetObservation.stableSelectorCheck } : {}),
      observation: finding.observation, reason: finding.reason, scope: finding.scope,
      ...findingNotes(finding), decisionRecorded: placement.decisionRecorded(finding?.id),
      evidenceIds: array(finding.evidenceIds), reviewerReason: decision?.reason, reviewerVerdict: decision?.verdict,
      missing: status === 'confirmed' ? [] : [...array(row.missingEvidence).filter(item => typeof item === 'string'),
        ...(hit?.status === 'confirmed' && reReview ? ['Legacy or citation-only confirmation requires re-review under the current semantic predicates.'] : [])],
    };
  });
  const coverage = array(report.coverage).map(row => ({ id: row.id, level: row.level, status: row.status, url: row.url,
    ...(typeof row.title === 'string' ? { title: row.title } : typeof row.name === 'string' ? { title: row.name } : {}) }));
  return {
    mode, kind: report.kind, findings, coverage, standard: report.standard ?? report.context?.standard ?? null,
    ...(mode === 'reviewed' ? { reviewPolicy: reviewPolicyOf(report), requiresReReview: reReview } : {}),
    auditor: source.auditor?.name, reviewer: report.reviewer?.name, createdAt: report.createdAt, runId: report.runId,
    reportDigest: report.reportDigest ?? report.checkpointDigest,
    errors: array(report.errors),
    ...pageUrls(report),
  };
}

const sameHref = (a, b) => { try { return new URL(a).href === new URL(b).href; } catch { return a === b; } };

/** Page = the landed URL when a navigation record exists; the declared URL is kept beside it when they differ. */
function pageUrls(report) {
  const declared = typeof report.manifest?.url === 'string' ? report.manifest.url : undefined;
  const navigation = report.navigation && typeof report.navigation === 'object' ? report.navigation : null;
  if (!navigation) return { url: declared };
  const final = typeof navigation.finalUrl === 'string' ? navigation.finalUrl : null;
  const redirects = Number.isSafeInteger(navigation.redirects) && navigation.redirects >= 0 ? navigation.redirects : null;
  const dns = navigation.dnsCheck && typeof navigation.dnsCheck === 'object' ? navigation.dnsCheck : null;
  const count = value => Number.isSafeInteger(value) && value >= 0 ? value : null;
  const dnsCheck = dns ? { status: typeof dns.status === 'string' ? dns.status : null, lookups: count(dns.lookups), failedLookups: count(dns.failedLookups), skippedLookups: count(dns.skippedLookups),
    privateByResolution: dns.session?.type === 'private' && dns.session?.basis === 'resolution' } : null;
  return { url: final ?? declared, navigationRecorded: true, finalUrlRecorded: Boolean(final), ...(dnsCheck ? { dnsCheck } : {}),
    ...(declared && (!final || !sameHref(final, declared)) ? { declaredUrl: declared, redirects } : {}) };
}

/** Header rows for the audited page: final URL, declared URL when different, and the caller-declared binding note. */
function pageRows(model, clip) {
  const rows = [['Page', model.url ? `${esc(clip(model.url, 500))}${model.navigationRecorded && !model.finalUrlRecorded ? ' (declared URL; no final URL was recorded)' : ''}` : 'not recorded']];
  if (model.declaredUrl && model.finalUrlRecorded) {
    const hops = model.redirects === null ? '' : ` (redirected ${model.redirects} hop${model.redirects === 1 ? '' : 's'} to the page above)`;
    rows.push(['Declared URL', `${esc(clip(model.declaredUrl, 500))}${hops}`]);
  }
  if (model.navigationRecorded) rows.push(['URL binding', 'Caller-declared: the caller declares that the declared URL serves the audited project root. Source-to-build or deployment provenance is not attested.']);
  return rows;
}

function untestedScope(model) {
  const items = [];
  const total = model.standard?.criteriaTotal ?? (model.coverage.length || undefined);
  const withFindings = new Set(model.findings.map(finding => finding.criterionId));
  items.push(`No success criterion was assessed as a whole${total ? ` (${total} in the selected catalog; ${withFindings.size} have findings)` : ''}. A criterion with no finding here is not a pass.`);
  items.push('Only the pages, states and viewport the agent actually visited were examined; other pages, user flows and states were not.');
  items.push('Screen readers (VoiceOver, JAWS, NVDA) were not used. Browser ARIA observations are not screen-reader output.');
  items.push('Time-based media, captions, audio description, and any criterion needing human judgment were not tested unless a finding says otherwise.');
  if (model.mode === 'checkpoint') items.push('This is a draft checkpoint: nothing here has been submitted or independently reviewed.');
  else if (model.mode === 'proposal') items.push('This proposal has not been independently reviewed: every finding is a claim awaiting review.');
  else items.push('Review is a declaration by the named reviewer; the tool does not verify that they are independent.');
  if (model.dnsCheck?.status === 'degraded') {
    const failed = model.dnsCheck.failedLookups, total = model.dnsCheck.lookups;
    const skipped = model.dnsCheck.skippedLookups;
    const skippedText = skipped ? ` ${skipped} later main-document request${skipped === 1 ? ' was' : 's were'} not looked up, because the host had already failed or the navigation had used its DNS wait.` : '';
    items.push(`DNS check degraded: ${failed === null ? 'some' : failed} of ${total === null ? 'the' : total} main-document DNS lookup${total === 1 ? '' : 's'} failed or timed out.${skippedText} Those navigations were checked against IP literals and localhost names only, so a DNS name that reaches a private address may not have been detected.`);
  }
  if (model.dnsCheck?.privateByResolution) items.push('The start URL host name resolved to a non-public address, so the session was treated as private (an internal or staging host): navigation between private addresses was allowed, and cloud metadata addresses stayed blocked.');
  if (model.findings.some(finding => finding.gaps?.length) || model.collectionStatus === 'unavailable') {
    items.push(`Evidence gaps are labelled per finding: ${Object.values(GAP_STATES).map(state => `${state.label}: ${state.meaning}`).join(' ')} Only the review decision, the target selector and the referenced collection are classified; other items are not.`);
  }
  if (model.requiresReReview) items.push(`Review policy ${model.reviewPolicy} is legacy or citation-only. Its previous confirmations need re-review and are displayed as needs review.`);
  return items;
}

const plural = (count, one, many = `${one}s`) => `${count} ${count === 1 ? one : many}`;
const percent = (part, whole) => `${whole ? Math.round((part / whole) * 10000) / 100 : 0}%`;
// Card anchors for one document, in record order. Anchors use only [\w.:-], so IDREF lists and fragment links always resolve.
// An ID that is already such a token keeps its exact form (single-file clips it to 120 characters first); any other ID is
// sanitized, and a sanitized, clipped or repeated ID takes the first free numeric suffix, so every anchor is unique.
function findingAnchors(ids, clipText = clip) {
  const texts = ids.map(id => clipText(id, 120)), safe = texts.map(text => text.replace(/[^\w.:-]/g, '_'));
  const used = new Set(), anchors = [];
  safe.forEach((text, i) => { if (text === texts[i] && !used.has(text)) { used.add(text); anchors[i] = text; } });
  safe.forEach((text, i) => {
    if (anchors[i] !== undefined) return;
    let anchor = text;
    for (let n = 2; used.has(anchor); n++) anchor = `${text}-${n}`;
    used.add(anchor); anchors[i] = anchor;
  });
  return anchors;
}
const scAnchor = id => `sc-${clip(id, 20).replace(/[^\w.-]/g, '_')}`;

const CHECK_LABEL = { 'captured-dom': 'unique in the DOM this run captured', 'full-dom-at-capture': "unique in the page's whole DOM when captured" };

/** Plain reproduction steps: where to start, which recorded state, and the selector that should survive a reload. */
function reproduceSteps(finding, pageUrl, clipText = clip) {
  const clip = clipText;
  const url = pageUrl, evidence = finding.target.evidenceId ? clip(finding.target.evidenceId, 40) : null;
  const steps = [`Open <code>${esc(clip(url ?? 'the audited page', REPORT_LIMITS.selector))}</code>${evidence ? ` and bring it to the state recorded in evidence <code>${esc(evidence)}</code>` : ''}.`];
  if (finding.stableSelector) {
    const check = CHECK_LABEL[finding.stableSelectorCheck];
    steps.push(`Find the element with <code>${esc(clip(finding.stableSelector, REPORT_LIMITS.selector))}</code> (${esc(finding.stableSelectorConfidence)}${check ? `; ${esc(check)}` : ''}).`);
  } else steps.push('No reload-stable selector could be stated; use the recorded target selector, which may depend on element position.');
  return steps;
}

const fact = (key, value, { wide = false, className = '', ddClass = '' } = {}) => {
  const classes = [className, wide ? 'wide' : ''].filter(Boolean).join(' ');
  return `<div${classes ? ` class="${classes}"` : ''}><dt>${esc(key)}</dt><dd${ddClass ? ` class="${ddClass}"` : ''}>${value}</dd></div>`;
};
// One collapsible field: the summary always carries a parenthesized count or qualifier so it reads the same without CSS.
const disclosure = (label, meta, body) => `<details><summary>${esc(label)} <span class="dm">(${esc(meta)})</span></summary><div class="db">${body}</div></details>`;

function findingHead(finding, anchor, title, clip) {
  const source = finding.source === 'axe' ? 'axe-adopted' : 'agent-found';
  return `<header class="f-head"><h4 class="f-title" id="ft-${esc(anchor)}">${esc(title)}</h4>
<ul class="tags" aria-label="Classification"><li class="badge s-${esc(finding.status)} status">${esc(STATUS_LABEL[finding.status])}</li><li class="badge src-${esc(finding.source)}"><span class="sw sw-${esc(finding.source)}" aria-hidden="true"></span><span class="k">Source:</span> ${source}</li><li><span class="k">SC</span> ${esc(clip(finding.criterionId, 20))}</li><li><span class="k">Method:</span> ${esc(clip(finding.method ?? 'unspecified', 40))}</li></ul></header>`;
}

function findingFacts(finding, clip) {
  const selector = finding.selector !== undefined ? clip(Array.isArray(finding.selector) ? finding.selector.join(' ') : finding.selector, REPORT_LIMITS.selector) : '';
  const recorded = [finding.target.evidenceId ? `evidence <code>${esc(clip(finding.target.evidenceId, 40))}</code>` : '', finding.target.nodeId ? `node <code>${esc(clip(finding.target.nodeId, 120))}</code>` : ''].filter(Boolean);
  const gaps = array(finding.gaps), targetGap = gaps.find(entry => entry.item === 'targetSelector');
  const target = selector ? `<code>${esc(selector)}</code>` : targetGap?.state === 'unavailable' ? `${esc(targetGap.label)}: ${esc(targetGap.text)}` : 'not recorded';
  const rows = [
    fact('Target', target, { className: 'target' }),
    fact('Recorded in', recorded.join(' · ') || 'not recorded'),
    fact('Scope', esc(clip(finding.scope))),
    fact('Observation', esc(clip(finding.observation)), { wide: true, ddClass: 'obs' }),
  ];
  // Review outcomes stay visible: a reviewer's conclusion is never hidden behind a disclosure.
  if (finding.reviewerVerdict) rows.push(fact('Review verdict', esc(clip(finding.reviewerVerdict)), { wide: true }));
  if (finding.reviewerReason) rows.push(fact('Reviewer', esc(clip(finding.reviewerReason)), { wide: true }));
  // Honest gaps use the shared wording from gaps.js, the same text as the JSON summary.
  if (gaps.length) rows.push(fact('Evidence gaps', `<ul class="gaps">${gaps.map(entry => `<li><strong>${esc(entry.label)}</strong> · ${esc(GAP_ITEMS[entry.item].label)}: ${esc(entry.text)}</li>`).join('')}</ul>`, { wide: true }));
  if (finding.duplicateOf?.length) rows.push(fact('Suspected duplicate', `Advisory only: same criterion, target and recorded state as ${finding.duplicateOf.map(id => `<code>${esc(clip(id, 120))}</code>`).join(', ')}. Nothing was merged, and counts are unchanged.`, { wide: true }));
  return `<dl class="facts">${rows.join('')}</dl>`;
}

function findingShots(shots, repeated) {
  const figures = shots.length ? `<div class="shots">${shots.map(shot => `<figure class="shot"><img alt="Page screenshot from evidence ${esc(shot.evidenceId)}; contents not described" width="${esc(Number(shot.width) || '')}" height="${esc(Number(shot.height) || '')}" src="data:image/png;base64,${shot.base64}"><figcaption>Screenshot, evidence <code>${esc(shot.evidenceId)}</code></figcaption></figure>`).join('')}</div>` : '';
  const earlier = repeated.map(shot => `<p class="hint">Screenshot <code>${esc(shot.evidenceId)}</code> is shown under an earlier finding.</p>`).join('');
  const empty = shots.length || repeated.length ? '' : '<div class="empty"><span class="empty-frame" aria-hidden="true"></span><p>No screenshot is embedded for this finding. Nothing is shown in its place; see Untested scope and limits.</p></div>';
  return figures + earlier + empty;
}

// Rendered only when the author supplied the note; an absent note has no heading, so it cannot read as "no counterevidence".
const rationaleBlock = (finding, clip) => finding.confidenceRationale
  ? `<h5>${esc("Author's confidence rationale")}</h5><p>${esc(clip(finding.confidenceRationale))}</p>` : '';
function counterevidenceBlock(finding, clip, exactId) {
  const items = array(finding.counterevidence), listed = exactId ? items : items.slice(0, NOTE_ITEMS);
  if (!listed.length) return '';
  const more = listed.length < items.length ? `<p class="hint">Showing ${listed.length} of ${items.length} items.</p>` : '';
  return `<h5>${esc("Author's counterevidence")}</h5><p class="hint">Observations the author tried that did not support this claim. They are the author's notes, not reviewed evidence.</p><ul>${listed.map(item => `<li>${esc(clip(item))}</li>`).join('')}</ul>${more}`;
}

function findingDisclosures(finding, shots, repeated, pageUrl, clip, exactId) {
  const steps = reproduceSteps(finding, pageUrl, clip);
  const missing = exactId ? finding.missing : finding.missing.slice(0, REPORT_LIMITS.missing);
  const ids = finding.evidenceIds.map(id => `<li><code>${esc(clip(id, 40))}</code></li>`);
  const pictures = shots.length ? plural(shots.length, 'screenshot') : repeated.length ? 'screenshot shown earlier' : 'no screenshot';
  const parts = [
    disclosure('Reproduce', plural(steps.length, 'step'), `<ol>${steps.map(step => `<li>${step}</li>`).join('')}</ol>`),
    disclosure('Why it may fail the criterion', "author's claim", `<p>${esc(clip(finding.reason))}</p>${rationaleBlock(finding, clip)}`),
    disclosure('Evidence', `${plural(ids.length, 'ID')} · ${pictures}`,
      `${ids.length ? `<ul class="ids" aria-label="Evidence IDs">${ids.join('')}</ul>` : '<p>No evidence IDs were recorded.</p>'}${counterevidenceBlock(finding, clip, exactId)}${findingShots(shots, repeated)}`),
  ];
  if (missing.length) {
    const meta = missing.length < finding.missing.length ? `${missing.length} of ${finding.missing.length} items` : plural(missing.length, 'item');
    parts.push(disclosure('Missing', meta, `<ul>${missing.map(item => `<li>${esc(clip(item))}</li>`).join('')}</ul>`));
  }
  return `<div class="disc">${parts.join('\n')}</div>`;
}

function renderFinding(finding, anchor, images, shown, pageUrl, clipText = clip, exactId = false) {
  const clip = clipText;
  const title = clip(finding.title, 300) || clip(finding.id, 120);
  // Each PNG is embedded once, under the first finding that cites it, so shared evidence cannot bypass the size caps.
  const cited = [...new Set(finding.evidenceIds)].map(id => images.get(id)).filter(Boolean);
  const shots = cited.filter(shot => !shown.has(shot.evidenceId));
  for (const shot of shots) shown.add(shot.evidenceId);
  const repeated = cited.filter(shot => !shots.includes(shot));
  return `<article class="finding" id="f-${esc(anchor)}" aria-labelledby="ft-${esc(anchor)}">
${findingHead(finding, anchor, title, clip)}
${findingFacts(finding, clip)}
${findingDisclosures(finding, shots, repeated, pageUrl, clip, exactId)}
<p class="f-foot"><span>Finding ID <code>${esc(clip(finding.id, 120))}</code></span><a href="#f-${esc(anchor)}">Link to this finding<span class="sr-only">: ${esc(title)}</span></a></p>
</article>`;
}

/** Criterion heading text: "SC x.y.z" plus a name when the catalog or the static table has one. */
function criterionHeading(id, row, clip, { link = true } = {}) {
  const label = `SC ${esc(clip(id, 20))}`, url = link ? safeW3cUrl(row?.url) : null, name = criterionName(id, row);
  return `${url ? `<a href="${esc(url)}" rel="noreferrer noopener">${label}</a>` : `<span class="sc-id">${label}</span>`}${name ? ` <span class="sc-name">${esc(clip(name, 200))}</span>` : ''}`;
}

function renderScGroup(id, row, cards, count, clip) {
  const anchor = esc(scAnchor(id)), level = row?.level;
  return `<section class="sc-group" aria-labelledby="${anchor}"><div class="sc-h"><h3 id="${anchor}">${criterionHeading(id, row, clip)}</h3><span class="sc-meta">${level ? `Level ${esc(clip(level, 4))} · ` : ''}${plural(count, 'finding')}</span></div>${cards}</section>`;
}

/** Pure summary dashboard: status and source bars with text legends, and the criteria table. Bars are decorative (aria-hidden). */
function renderSummary(model, ordered, catalog, { shownCount, linkGroups, clip }) {
  const total = model.findings.length;
  const count = status => model.findings.filter(finding => finding.status === status).length;
  const bySource = source => model.findings.filter(finding => finding.source === source).length;
  const metric = (heading, entries) => `<div class="metric"><h4>${heading}</h4><div class="bar" aria-hidden="true">${entries.filter(([, , n]) => n).map(([, swatch, n]) => `<i class="sw-${swatch}" style="width:${percent(n, total)}"></i>`).join('')}</div>
<dl class="legend">${entries.map(([label, swatch, n]) => `<div${n ? '' : ' class="zero"'}><dt><span class="sw sw-${swatch}" aria-hidden="true"></span>${label}</dt><dd>${n}</dd></div>`).join('')}</dl></div>`;
  const confirmed = count('confirmed'), rejected = count('rejected');
  const catalogTotal = model.standard?.criteriaTotal ?? (model.coverage.length || undefined);
  const max = Math.max(1, ...ordered.map(([, list]) => list.length));
  const rows = ordered.map(([id, list]) => {
    const row = catalog.get(id), name = criterionName(id, row);
    const label = linkGroups ? `<a href="#${esc(scAnchor(id))}">SC ${esc(clip(id, 20))}</a>` : `SC ${esc(clip(id, 20))}`;
    return `<tr><th scope="row">${label}${name ? ` ${esc(clip(name, 200))}` : ''}</th><td>${row?.level ? esc(clip(row.level, 4)) : '<span class="na">not recorded</span>'}</td><td class="num"><span class="sc-cell"><span class="sc-track" aria-hidden="true"><span class="sc-bar" style="width:${percent(list.length, max)}"></span></span>${list.length}</span></td></tr>`;
  });
  const table = rows.length ? `<table><caption>A criterion with no finding is not a pass.</caption>
<thead><tr><th scope="col">Criterion</th><th scope="col">Level</th><th scope="col" class="num">Findings</th></tr></thead><tbody>${rows.join('')}</tbody></table>` : '<p class="hint">No criterion has a finding. A criterion with no finding is not a pass.</p>';
  const callouts = [
    ...(total > shownCount ? [`<p class="callout" role="note"><strong>Partial list.</strong> <span>Showing the first ${shownCount} of ${total} findings.</span></p>`] : []),
    ...(model.errors.length ? [`<p class="callout" role="note"><strong>Coverage incomplete.</strong> <span>The collection recorded ${model.errors.length} error${model.errors.length === 1 ? '' : 's'}; treat coverage as incomplete.</span></p>`] : []),
  ];
  return `<section aria-labelledby="summary"><h2 id="summary">Summary</h2><div class="dash">
<section class="panel" aria-labelledby="k-findings"><h3 id="k-findings">Findings</h3>
<p class="big"><b>${total}</b><span>findings · ${confirmed + rejected} of ${total} decided by a reviewer</span></p>
${metric('Review status', [['Confirmed', 'ok', confirmed], ['Needs review', 'pending', count('needs_review')], ['Rejected', 'reject', rejected]])}
${metric('Source', [['axe-adopted', 'axe', bySource('axe')], ['agent-found', 'agent', bySource('agent')]])}
</section>
<section class="panel" aria-labelledby="k-sc"><h3 id="k-sc">Success criteria affected</h3>
<p class="big"><b>${ordered.length}</b><span>with findings${catalogTotal ? `, of ${esc(clip(catalogTotal, 10))} in the selected catalog` : ''}</span></p>
${table}
</section>
</div>${callouts.join('')}</section>`;
}

/** Pure table of contents. Entries carry pre-escaped labels; counts are integers. */
function renderToc(entries) {
  const item = entry => `<li><a href="${entry.href}"><span>${entry.label}</span>${entry.count === undefined ? '' : ` <span class="n">${entry.count}</span>`}</a>${entry.children?.length ? `<ol>${entry.children.map(item).join('')}</ol>` : ''}</li>`;
  return `<nav class="toc" aria-labelledby="toc-h"><h2 id="toc-h">Contents</h2><ol>${entries.map(item).join('')}</ol></nav>`;
}

const selectorRecorded = selector => Array.isArray(selector) ? selector.length > 0 : typeof selector === 'string' && selector.length > 0;

/**
 * Fill best-effort loader results into normalized findings: recorded and reload-stable selectors, the shared evidence gaps
 * and advisory suspected-duplicate links. Lookups and states exist only for findings whose evidence file the loader tried.
 */
function applyContext(model, { selectors, targets, lookups, states } = {}) {
  const keyOf = finding => `${finding.target.evidenceId}|${finding.target.nodeId}`;
  for (const finding of model.findings) {
    const key = keyOf(finding);
    finding.selector ??= selectors?.get(key);
    const local = targets?.get(key);
    if (!finding.stableSelector && local?.stableSelector) Object.assign(finding, { stableSelector: local.stableSelector, stableSelectorConfidence: local.stableSelectorConfidence, stableSelectorCheck: local.stableSelectorCheck });
    finding.gaps = findingGaps({ mode: model.mode, status: finding.status, decisionRecorded: finding.decisionRecorded, evidenceId: finding.target.evidenceId,
      selectorRecorded: selectorRecorded(finding.selector) }, lookups?.has(key) ? { targetRecord: lookups.get(key) } : null);
  }
  const groups = suspectedDuplicateGroups(model.findings.map(finding => ({ findingId: finding.id, criterionId: finding.criterionId,
    stateId: states?.get(keyOf(finding)), nodeId: finding.target.nodeId, stableSelector: finding.stableSelector })));
  const others = new Map();
  for (const group of groups) for (const id of group.findingIds) others.set(id, group.findingIds.filter(other => other !== id));
  for (const finding of model.findings) if (others.has(finding.id)) finding.duplicateOf = others.get(finding.id);
  return model;
}

/**
 * Render one self-contained HTML document (inline CSS only, no script, no external requests).
 * `images` maps evidence IDs to `{ evidenceId, base64, width, height }` already size-checked by the loader.
 */
function renderReportDocument(report, { images = new Map(), imageNotes = [], selectors = new Map(), targets = new Map(), lookups, states, collectionStatus, inventory = [], references = [], projection } = {}) {
  const clip = projection ? fullText : clipDefault;
  const model = applyContext(normalizeAuditReport(report), { selectors, targets, lookups, states });
  model.collectionStatus = collectionStatus;
  const shown = projection ? model.findings : model.findings.slice(0, REPORT_LIMITS.findings);
  const groups = new Map(), embedded = new Set();
  for (const finding of shown) groups.set(finding.criterionId, [...(groups.get(finding.criterionId) ?? []), finding]);
  const ordered = [...groups.entries()].sort(([a], [b]) => criterionKey(a).localeCompare(criterionKey(b)));
  const catalog = new Map(model.coverage.map(row => [row.id, row]));
  const title = model.mode === 'reviewed' ? 'Accessibility audit report (independently reviewed)' : model.mode === 'proposal' ? 'Accessibility audit report (awaiting review)' : 'Accessibility audit report (draft checkpoint)';
  const [stateLabel, stateClass] = { reviewed: ['Independently reviewed', ' state-reviewed'], proposal: ['Awaiting review', ''], checkpoint: ['Draft checkpoint', ''] }[model.mode];
  const std = model.standard ? `WCAG ${esc(clip(model.standard.version, 10))} level ${esc(clip(model.standard.targetLevel, 10))}` : 'WCAG (catalog not recorded)';
  const anchors = projection ? [] : findingAnchors(shown.map(finding => finding.id));
  const anchorOf = new Map(shown.map((finding, i) => [finding, anchors[i]]));
  const sections = projection ? [projection.body] : ordered.map(([id, list]) =>
    renderScGroup(id, catalog.get(id), list.map(finding => renderFinding(finding, anchorOf.get(finding), images, embedded, model.url)).join('\n'), list.length, clip));
  // Adoption links only point at cards rendered in this same document, indexed by original record position.
  const hrefs = anchors.map(anchor => `#f-${esc(anchor)}`);
  const created = typeof model.createdAt === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.\d{1,9})?)?Z$/.test(model.createdAt)
    ? `<time datetime="${esc(model.createdAt)}">${esc(model.createdAt)}</time>` : esc(clip(model.createdAt ?? 'not recorded', 40));
  const meta = [
    ['Standard', std], ...pageRows(model, clip).map(([key, value]) => [key, value, true]),
    ['Auditor', esc(clip(model.auditor ?? 'not recorded', 200))], ...(model.reviewer ? [['Reviewer', esc(clip(model.reviewer, 200))]] : []),
    ['Created', created], ['Run', `<code>${esc(clip(model.runId ?? 'unknown', 80))}</code>`],
    ['Source file kind', `<code>${esc(model.kind)}</code>`], ['Digest', `<code>${esc(clip(model.reportDigest ?? 'none', 100))}</code>`, true],
    ...(model.reviewPolicy ? [['Review policy', esc(model.reviewPolicy)]] : []),
  ];
  const toc = renderToc([
    { href: '#summary', label: 'Summary' },
    { href: '#findings', label: projection ? 'Finding records' : 'Findings', count: shown.length,
      children: projection ? [] : ordered.map(([id, list]) => ({ href: `#${esc(scAnchor(id))}`, label: `SC ${esc(clip(id, 20))}`, count: list.length })) },
    ...(inventory.length ? [{ href: '#inventory', label: 'Observation inventory', count: inventory.length }] : []),
    { href: '#originals', label: 'Evidence sources', ...(references.length ? { count: references.length } : {}) },
    { href: '#scope', label: 'Untested scope and limits' },
  ]);
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data:; style-src 'unsafe-inline'">
<title>${esc(title)}</title>
<style>
${REPORT_CSS}
</style></head><body>
<a class="skip" href="#main">Skip to report content</a>
<header class="masthead"><div class="wrap">
<p class="eyebrow">a11y-agent-kit · Audit report</p>
<div class="title-row"><h1>Accessibility audit report</h1><p class="state${stateClass}"><span class="sr-only">Report state: </span>${stateLabel}</p></div>
<dl class="meta">${meta.map(([key, value, wide]) => `<div${wide ? ' class="wide"' : ''}><dt>${esc(key)}</dt><dd>${value}</dd></div>`).join('')}</dl>
<div class="notice" role="note"><span class="notice-icon" aria-hidden="true">!</span><p><strong>Not a conformance certification.</strong> This report lists findings from one agent-driven session. It does not state that the page conforms, or fails to conform, to ${std}.</p></div>
</div></header>
<div class="layout wrap">
${toc}
<main id="main" tabindex="-1">
${renderSummary(model, ordered, catalog, { shownCount: shown.length, linkGroups: !projection, clip })}
<section aria-labelledby="findings"><h2 id="findings">${projection ? 'Original finding records' : 'Findings by WCAG success criterion'}</h2>
${projection ? '' : '<p class="lede">Each finding is an observation about one recorded target, not a whole-criterion verdict. Open a row for steps, rationale, evidence and what is still missing.</p>\n'}${projection?.navigation ? projection.navigation + '\n' : ''}${sections.join('\n') || '<p>No findings were recorded. That does not mean the page is accessible.</p>'}</section>
${renderInventory(report, inventory, clip, hrefs)}
${renderReferences(references, clip, collectionStatus)}
<section aria-labelledby="scope"><h2 id="scope">Untested scope and limits</h2><div class="scope"><ul>${untestedScope(model).map(item => `<li>${esc(item)}</li>`).join('')}</ul>
${imageNotes.length ? `<p class="note">${imageNotes.map(esc).join(' ')}</p>` : ''}</div></section>
</main></div>
<footer class="colophon"><div class="wrap"><p>Rendered locally from ${esc(model.kind)} data by a11y-agent-kit. Digests are shown, not re-verified: run <code>audit-check</code> on the source report to verify it. Retained redactions are preserved; screenshots, when embedded, are original page pixels and can show sensitive content.</p>
<p>Digest <code>${esc(clip(model.reportDigest ?? 'none', 100))}</code> · Run <code>${esc(clip(model.runId ?? 'unknown', 80))}</code></p></div></footer>
</body></html>
`;
}

/** Existing single-file projection, including its established text and finding caps. */
export function renderAuditReportHtml(report, context = {}) {
  return renderReportDocument(report, context);
}

// Inventory observations and adopted findings overlap. Explicit maker links are a separate declaration.
function renderInventory(report, inventory, clip, hrefs = []) {
  if (!inventory.length) return '';
  const findings = (report.kind === 'audit-checkpoint-1' ? report.proposal : report)?.findings ?? [];
  const stats = { bound: 0, adopted: 0, linked: 0, unresolved: 0 };
  const rows = inventory.map((row, index) => {
    const adopted = findings.flatMap((f, i) => row.bucket === 'violations' && f.source === 'axe' && f.axeCandidateId === `${row.evidenceId}:${row.ruleId}:${row.ruleNodeIndex}` ? [[f, i]] : []);
    const disposition = row.authorDisposition ?? { status: 'unresolved' };
    if (row.binding?.status === 'bound') stats.bound++;
    if (adopted.length) stats.adopted++;
    if (disposition.status === 'linked') stats.linked++;
    if (disposition.status === 'unresolved') stats.unresolved++;
    const text = value => esc(clip(value));
    const adoption = adopted.length
      ? `Adopted as ${adopted.map(([f, i]) => hrefs[i] ? `<a href="${hrefs[i]}">${text(f.id)}</a>` : text(f.id)).join(', ')} (from axeCandidateId)`
      : 'No matching adoption recorded';
    const fields = [
      ['Evidence', text(row.evidenceId)], ['Rule / bucket', text(`${row.ruleId} / ${row.bucket}`)], ['Target', text(row.target)],
      ['DOM binding', text(row.binding?.status ?? 'not recorded')], ['Author disposition', text(disposition.status)],
      ...(disposition.reason ? [['Disposition reason', text(disposition.reason)]] : []),
      ['Association', text(disposition.status === 'linked' ? `Explicitly linked: ${array(disposition.findingIds).join(', ')}` : 'Not explicitly linked')],
      ['Adoption', adoption],
    ];
    return `<article class="inventory-row" aria-labelledby="inv-${index + 1}"><h3 id="inv-${index + 1}"><span class="sr-only">Observation </span><code>${text(row.observationId)}</code></h3><dl class="kv">${fields.map(([key, value]) => `<dt>${esc(key)}</dt><dd>${value}</dd>`).join('')}</dl></article>`;
  });
  const counts = [[inventory.length, 'observations'], [stats.bound, 'DOM-bound'], [stats.adopted, 'adopted as findings'], [stats.linked, 'explicitly linked'], [stats.unresolved, 'disposition unresolved']];
  return `<section aria-labelledby="inventory"><h2 id="inventory">Original observation inventory (${inventory.length})</h2>
<p class="lede">Inventory observations can overlap adopted finding records; they are not additional defects. Author disposition and explicit association are separate from adoption, DOM binding and review status. Unresolved is an author disposition; it does not mean the observation was never adopted.</p>
<ul class="inv-stats" aria-label="Inventory counts">${counts.map(([n, label]) => `<li><b>${n}</b> ${label}</li>`).join('')}</ul>
<details class="box"><summary>Show all ${plural(inventory.length, 'observation record')}</summary><div class="inv-list">${rows.join('\n')}</div></details></section>`;
}

/** Shared directory of every recorded path, or '' when the paths do not all sit in one directory (then cells keep full paths). */
function sharedDirectory(paths) {
  if (!paths.length || paths.some(file => typeof file !== 'string')) return '';
  const directories = new Set(paths.map(file => path.posix.dirname(file)));
  if (directories.size !== 1) return '';
  const [directory] = directories;
  if (directory === '.' || !directory) return '';
  return directory.endsWith('/') ? directory : `${directory}/`;
}

function renderReferences(references, clip, collectionStatus) {
  const head = '<section aria-labelledby="originals"><h2 id="originals">Original evidence sources</h2><p class="lede">Paths are local references, relative to this HTML directory when available. They come from recorded attachment metadata; existence and digests are not verified here.</p>';
  // A referenced collection that could not be read is Unavailable, not "not recorded".
  if (!references.length && collectionStatus === 'unavailable') return `${head}<p>${esc(GAP_STATES.unavailable.label)}: the referenced collection could not be read, so its original JSON and PNG paths cannot be shown. ${esc(GAP_STATES.unavailable.meaning)}</p></section>`;
  if (!references.length) return `${head}<p>Original JSON path not recorded. Original PNG path not recorded.</p></section>`;
  // Lossless compression: a common directory moves into the caption only when every recorded path shares it.
  const base = sharedDirectory(references.flatMap(row => [row.json, row.png]).filter(Boolean));
  const sources = new Set(references.map(row => row.source)), oneSource = sources.size === 1;
  const cell = (file, kind) => file ? `<td><code>${esc(clip(base ? file.slice(base.length) : file))}</code></td>` : `<td class="na">Original ${kind} path not recorded</td>`;
  const caption = [
    oneSource ? `Source for every row: <code>${esc(clip(references[0].source))}</code>.` : 'Each row names its source.',
    base ? `File names below are relative to <code class="base">${esc(clip(base))}</code>` : 'Paths are shown in full.',
  ].join(' ');
  const rows = references.map(row => `<tr><th scope="row"><code>${esc(clip(row.evidenceId))}</code></th>${oneSource ? '' : `<td>${esc(clip(row.source))}</td>`}${cell(row.json, 'JSON')}${cell(row.png, 'PNG')}</tr>`);
  return `${head}<div class="tablewrap"><table><caption>${caption}</caption>
<thead><tr><th scope="col">Evidence</th>${oneSource ? '' : '<th scope="col">Source</th>'}<th scope="col">JSON</th><th scope="col">PNG</th></tr></thead><tbody>${rows.join('')}</tbody></table></div></section>`;
}

async function readJson(file, limit, { sidecar = false } = {}) {
  const stat = await (sidecar ? fs.lstat : fs.stat)(file); // sidecars next to the report must not be links to elsewhere
  if (!stat.isFile() || stat.size > limit) fail('The file is not a regular file within the size limit.');
  return JSON.parse(await fs.readFile(file, 'utf8'));
}

/**
 * Best-effort local lookups next to the report: selectors (recorded and reload-stable) for target nodes and, when requested, size-capped
 * original PNGs that match their recorded SHA-256. A referenced collection also supplies inventory and attachment metadata.
 */
export async function loadReportContext(reportPath, report, { screenshots = false, outputDirectory } = {}) {
  const dir = path.dirname(path.resolve(reportPath)), selectors = new Map(), targets = new Map(), images = new Map(), notes = [];
  const model = normalizeAuditReport(report);
  const ids = [...new Set(model.findings.flatMap(finding => [finding.target.evidenceId, ...finding.evidenceIds]))].filter(id => EVIDENCE_ID.test(id ?? ''));
  const references = [], inventory = [];
  const reference = report.collection?.reportPath ?? report.sourceAudit?.reportPath;
  let collection;
  if (typeof reference === 'string') {
    const file = path.resolve(dir, reference);
    collection = await readJson(file, 64 * 1024 * 1024).catch(() => null);
    if (collection?.kind !== 'audit' || collection.runId !== report.runId) collection = null;
    if (!collection) notes.push('Referenced collection unavailable or inconsistent; original inventory and attachment paths could not be loaded.');
    else {
      try {
        let options = { limit: 200 };
        do {
          const page = deriveAuditInventory({ collection, report }, options);
          inventory.push(...page.rows);
          options = page.pagination.next;
        } while (options);
      } catch { inventory.length = 0; notes.push('Original inventory could not be derived from the referenced collection.'); }
    }
  }
  const collectionStatus = typeof reference !== 'string' ? 'not-referenced' : collection ? 'read' : 'unavailable';
  const sourceRows = collection?.records ?? report.evidence ?? report.records ?? [];
  const sourceDir = collection ? path.dirname(path.resolve(dir, reference)) : dir;
  for (const row of array(sourceRows)) {
    const attachment = key => typeof row[key]?.path === 'string' && row[key].path ? path.relative(outputDirectory ?? dir, path.resolve(sourceDir, row[key].path)) : null;
    references.push({ evidenceId: row.evidenceId, json: attachment('json'), png: attachment('png'), source: collection ? 'collection.records' : 'input report attachment metadata' });
  }
  const records = new Map(), lookups = new Map(), states = new Map();
  const record = async id => {
    if (!records.has(id)) records.set(id, await readJson(path.join(dir, `${id}.json`), REPORT_LIMITS.evidenceFileBytes, { sidecar: true }).catch(() => null));
    return records.get(id);
  };
  for (const finding of model.findings) {
    const key = `${finding.target.evidenceId}|${finding.target.nodeId}`;
    // A target with no usable evidence ID refers to no record: its selector can only be missing, never unavailable.
    if (!EVIDENCE_ID.test(finding.target.evidenceId ?? '')) { lookups.set(key, 'not-referenced'); continue; }
    const original = await record(finding.target.evidenceId);
    lookups.set(key, original && typeof original === 'object' ? 'read' : 'unavailable');
    if (typeof original?.after?.stateId === 'string') states.set(key, original.after.stateId);
    // Drafts carry no targetObservation: derive a stable selector from this one record (its own nodes and in-page checks) only.
    const stable = finding.stableSelector || !original ? {} : stableSelectorIndex([original]).fieldsFor(finding.target);
    if (stable.stableSelector) targets.set(key, stable);
    if (finding.selector !== undefined) continue;
    const nodes = [...array(original?.result?.nodes), ...(original?.result?.element ? [original.result.element] : [])];
    const node = nodes.find(row => row?.nodeId === finding.target.nodeId);
    if (typeof node?.selector === 'string') selectors.set(`${finding.target.evidenceId}|${finding.target.nodeId}`, node.selector);
  }
  if (screenshots) {
    let total = 0, skipped = 0;
    for (const id of ids) {
      const png = (await record(id))?.png;
      if (!png || typeof png.sha256 !== 'string') continue;
      if (images.size >= REPORT_LIMITS.images) { skipped++; continue; }
      const file = path.join(dir, `${id}.png`);
      const bytes = (await fs.lstat(file).catch(() => null))?.isFile() ? await fs.readFile(file).catch(() => null) : null;
      if (!bytes || bytes.length > REPORT_LIMITS.imageBytes || total + bytes.length > REPORT_LIMITS.imagesTotalBytes) { if (bytes) skipped++; continue; }
      if (!bytes.subarray(0, 8).equals(PNG_SIGNATURE) || createHash('sha256').update(bytes).digest('hex') !== png.sha256) { skipped++; continue; }
      total += bytes.length;
      images.set(id, { evidenceId: id, base64: bytes.toString('base64'), width: png.width, height: png.height });
    }
    if (skipped) notes.push(`${skipped} screenshot${skipped === 1 ? ' was' : 's were'} not embedded (over the ${REPORT_LIMITS.imageBytes / 1024} KiB per-image, ${REPORT_LIMITS.imagesTotalBytes / 1024 / 1024} MiB total or ${REPORT_LIMITS.images}-image cap, or failed the SHA-256 check).`);
  } else notes.push('Screenshots were not embedded (use --screenshots).');
  return { selectors, targets, lookups, states, collectionStatus, images, imageNotes: notes, inventory, references };
}

// Delivery protects originals without requiring audit-check or changing projection semantics.
async function protectReportOutput(input, report, out) {
  const parent = path.dirname(out);
  // Check existing ancestors before mkdir, including aliases to a different directory.
  let ancestor = parent;
  while (!(await fs.lstat(ancestor).catch(error => { if (error.code === 'ENOENT') return null; throw error; }))) ancestor = path.dirname(ancestor);
  for (let current = ancestor; current !== path.dirname(current); current = path.dirname(current)) {
    // Preserve standard macOS filesystem root aliases used by os.tmpdir(); reject application-created aliases.
    const platformAlias = process.platform === 'darwin' && ['/var', '/tmp', '/etc'].includes(current);
    if ((await fs.lstat(current)).isSymbolicLink() && !platformAlias) fail('--out parent must be canonical, without symlink aliases.');
  }
  const destination = await fs.lstat(out).catch(error => { if (error.code === 'ENOENT') return null; throw error; });
  if (destination?.isSymbolicLink()) fail('--out must not be a symlink.');
  const visited = new Set(), scanned = new Set();
  async function protect(file, document, json = false) {
    const absolute = path.resolve(file);
    // An untyped path may be encountered before a JSON reference to the same file.
    if (visited.has(absolute) && (!json || scanned.has(absolute))) return;
    visited.add(absolute);
    const canonical = await fs.realpath(absolute).catch(() => absolute);
    const stat = await fs.stat(absolute).catch(error => {
      if (error.code === 'ENOENT') return null; // optional sidecar absent
      fail(`Cannot scan referenced ${json ? 'JSON' : 'file'}: ${absolute} (${error.code}).`);
    });
    if (out === absolute || out === canonical || (destination && stat && destination.dev === stat.dev && destination.ino === stat.ino)) {
      fail('--out must not replace an original report or referenced evidence.');
    }
    if (document === undefined && json) {
      if (!stat) return;
      try { document = await readJson(absolute, 64 * 1024 * 1024); }
      catch { fail(`Cannot scan referenced JSON: ${absolute}; expected readable, valid JSON within 64 MiB. No output was written.`); }
    }
    if (document !== undefined) scanned.add(absolute);
    async function walk(value, jsonAttachment = false) {
      if (!value || typeof value !== 'object') return;
      if (typeof value.evidenceId === 'string' && /^ev-\d+$/.test(value.evidenceId)) {
        for (const ext of ['json', 'png']) await protect(path.join(path.dirname(absolute), `${value.evidenceId}.${ext}`), undefined, ext === 'json');
      }
      if (Array.isArray(value.evidenceIds)) for (const id of value.evidenceIds) {
        if (typeof id === 'string' && /^ev-\d+$/.test(id)) for (const ext of ['json', 'png']) await protect(path.join(path.dirname(absolute), `${id}.${ext}`), undefined, ext === 'json');
      }
      for (const [key, child] of Object.entries(value)) {
        if (['path', 'reportPath', 'checkpointPath'].includes(key) && typeof child === 'string') await protect(path.resolve(path.dirname(absolute), child), undefined, key !== 'path' || jsonAttachment);
        else if (child && typeof child === 'object') await walk(child, key === 'json');
      }
    }
    await walk(document);
  }
  await protect(input, report);
}

async function replaceHtml(out, html) {
  const temporary = path.join(path.dirname(out), `.${path.basename(out)}.tmp-${randomUUID()}`);
  let owned = false;
  try {
    const handle = await fs.open(temporary, 'wx', 0o600); owned = true;
    try { await handle.writeFile(html); } finally { await handle.close(); }
    await fs.rename(temporary, out);
  } finally { if (owned) await fs.unlink(temporary).catch(error => { if (error.code !== 'ENOENT') throw error; }); }
}

export async function writeAuditReport(inputPath, outPath, { screenshots = false, bounded = false } = {}) {
  const input = path.resolve(inputPath), out = path.resolve(outPath);
  if (input === out) fail('--out must differ from the input report.');
  const report = await readJson(input, 64 * 1024 * 1024).catch(error => {
    throw error instanceof ToolError ? error : new ToolError('INVALID_AUDIT_REPORT', 'The input must be a readable JSON report file.');
  });
  const context = await loadReportContext(input, report, { screenshots, outputDirectory: bounded ? out : path.dirname(out) });
  if (bounded) {
    // Render and validate everything before creating any output. Never reuse an existing directory.
    const artifacts = renderBoundedAuditReportHtml(report, context);
    await protectReportOutput(input, report, out);
    await fs.mkdir(path.dirname(out), { recursive: true });
    await fs.mkdir(out, { mode: 0o700 });
    for (const artifact of artifacts) await fs.writeFile(path.join(out, artifact.name), artifact.html, { flag: 'wx', mode: 0o600 });
    return { status: 'ok', kind: 'audit-report-html-bounded', source: KINDS[report.kind], outPath: path.join(out, 'index.html'),
      artifacts: artifacts.map(({ name, html, findings }) => ({ path: path.join(out, name), bytes: Buffer.byteLength(html, 'utf8'), findings })),
      findings: normalizeAuditReport(report).findings.length, screenshotsEmbedded: context.images.size };
  }
  const html = renderAuditReportHtml(report, context);
  await protectReportOutput(input, report, out);
  await fs.mkdir(path.dirname(out), { recursive: true });
  await replaceHtml(out, html);
  const model = normalizeAuditReport(report);
  return { status: 'ok', kind: 'audit-report-html', source: KINDS[report.kind], outPath: out, bytes: Buffer.byteLength(html), findings: model.findings.length, screenshotsEmbedded: context.images.size };
}

export const BOUNDED_REPORT_LIMITS = Object.freeze({ findings: 50, bytes: 500000 });

/** Complete local delivery in original record order; bounds include escaped content, images and chrome. */
export function renderBoundedAuditReportHtml(report, context = {}) {
  const model = normalizeAuditReport(report), embedded = new Set();
  const anchors = findingAnchors(model.findings.map(finding => finding.id), fullText);
  applyContext(model, context);
  const cards = model.findings.map((finding, i) => ({ criterionId: finding.criterionId,
    html: renderFinding(finding, anchors[i], context.images ?? new Map(), embedded, model.url, fullText, true) }));
  const catalog = new Map(model.coverage.map(row => [row.id, row]));
  // Same card component as the single file; each record keeps its own criterion heading, numbered within the page.
  const pageBody = (start, end) => cards.slice(start, end).map((card, offset) => {
    const row = catalog.get(card.criterionId), anchor = `rec-${start + offset + 1}`, level = row?.level;
    return `<section class="sc-group" aria-labelledby="${anchor}"><div class="sc-h"><h3 id="${anchor}">${criterionHeading(card.criterionId, row, fullText, { link: false })}</h3><span class="sc-meta">${level ? `Level ${esc(fullText(level))} · ` : ''}original record ${start + offset + 1} of ${cards.length}</span></div>${card.html}</section>`;
  }).join('\n');
  const document = (body, navigation = '') => renderReportDocument(report, { ...context, projection: { body, navigation } });
  const fits = html => Buffer.byteLength(html, 'utf8') < BOUNDED_REPORT_LIMITS.bytes;
  const artifacts = [];
  let start = 0;
  while (start < cards.length) {
    const name = `findings-${String(artifacts.length + 1).padStart(4, '0')}.html`;
    let end = start, html;
    while (end < cards.length && end - start < BOUNDED_REPORT_LIMITS.findings) {
      const trial = document(pageBody(start, end + 1),
        `<nav class="pager" aria-label="Report pages"><a href="index.html">Back to index</a><p>Original finding records ${start + 1}–${end + 1} of ${cards.length}; these are not unique issue counts.</p></nav>`);
      if (!fits(trial)) break;
      html = trial; end++;
    }
    if (end === start) fail(`Original finding record ${start + 1} cannot fit in a bounded HTML artifact (<500000 UTF-8 bytes including chrome and screenshots). No output was written.`);
    artifacts.push({ name, html, findings: end - start, start: start + 1, end });
    start = end;
  }
  const index = document(`<p>${cards.length} original finding records in ${artifacts.length} detail pages. These are observations, not unique issue counts. All pages preserve original record order.</p><ol class="pages">${artifacts.map(page => `<li><a href="${page.name}">Original finding records ${page.start}–${page.end}</a></li>`).join('')}</ol>${cards.length ? '' : '<p>No findings were recorded. That does not mean the page is accessible.</p>'}`);
  if (!fits(index)) fail('The bounded HTML index cannot fit below 500000 UTF-8 bytes. No output was written.');
  return [{ name: 'index.html', html: index, findings: 0 }, ...artifacts];
}
