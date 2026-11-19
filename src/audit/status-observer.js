// A read-only main-document recorder. The handle owns all listeners; disposal is
// unconditional, including failed triggers and navigation/context destruction.
export async function openStatusRecorder(browser) {
  const handle = await browser.page.evaluateHandle(({ storeKey }) => {
    const store = globalThis[storeKey], mutations = [], focus = [];
    let omitted = 0, closed = false, finished;
    const id = node => {
      if (!node) return null;
      if (!store.ids.has(node)) store.ids.set(node, `${store.documentId}:n${String(store.next++).padStart(6, '0')}`);
      return store.ids.get(node);
    };
    const identity = node => ({ nodeId: id(node), documentId: store.documentId });
    const semantics = element => {
      const ancestors = [];
      for (let el = element; el && ancestors.length < 128; el = el.parentElement) ancestors.push({
        ...identity(el), tag: el.localName, role: el.getAttribute('role'),
        ariaLive: el.getAttribute('aria-live'), ariaAtomic: el.getAttribute('aria-atomic'),
      });
      return ancestors;
    };
    const record = records => {
      for (const mutation of records) {
        const element = mutation.target.nodeType === 3 ? mutation.target.parentElement : mutation.target;
        if (!element || element.closest('script,style,input,textarea')) continue;
        const nodes = mutation.type === 'characterData' ? [mutation.target] : [...mutation.addedNodes, ...mutation.removedNodes];
        for (const node of nodes) {
          if (node.nodeType !== 3 && node.nodeType !== 1) continue;
          // Match the collector's omission policy; never retain inline scripts.
          if (node.nodeType === 1 && (node.matches('script,style,input,textarea') || node.querySelector('script,input,textarea'))) continue;
          const text = node.textContent || '';
          if (!text && mutation.type !== 'characterData') continue;
          if (mutations.length >= 200) { omitted++; continue; }
          const textElement = node.nodeType === 1 ? node : element;
          const rect = textElement.getBoundingClientRect(), css = getComputedStyle(textElement);
          const chain = semantics(textElement);
          mutations.push({ ...identity(node), targetNodeId: id(textElement), type: mutation.type,
            text: text.slice(0, 1200), textTruncated: text.length > 1200,
            oldText: mutation.oldValue?.slice(0, 1200) ?? null, oldTextTruncated: (mutation.oldValue?.length ?? 0) > 1200,
            ancestorSemantics: chain,
            hasLiveRegionAncestor: chain.some(a => /^(status|alert|log)$/.test(a.role || '') || /^(polite|assertive)$/.test(a.ariaLive || '')),
            focused: textElement === document.activeElement || textElement.contains(document.activeElement),
            visible: textElement.isConnected && rect.width > 0 && rect.height > 0 && !['hidden', 'collapse'].includes(css.visibility) && css.display !== 'none',
            elapsedMs: Math.round(performance.now() - started),
          });
        }
      }
    };
    const started = performance.now(), initialFocus = identity(document.activeElement);
    const observer = new MutationObserver(record);
    const onFocus = event => { if (focus.length < 200) focus.push({ ...identity(event.target), elapsedMs: Math.round(performance.now() - started) }); };
    observer.observe(document, { subtree: true, childList: true, characterData: true, characterDataOldValue: true });
    document.addEventListener('focusin', onFocus, true);
    const close = () => {
      if (!closed) { record(observer.takeRecords()); observer.disconnect(); document.removeEventListener('focusin', onFocus, true); closed = true; }
    };
    return { close, finish: () => { if (finished) return finished; close(); return finished = { mutations, omitted, focus, initialFocus,
      finalFocus: identity(document.activeElement), focusMoved: id(document.activeElement) !== initialFocus.nodeId, elapsedMs: Math.round(performance.now() - started), noChange: mutations.length === 0, disconnected: closed,
      scope: 'Main-document text mutations and focus events; visibility is CSS/geometry only. No announcement or WCAG verdict.' }; } };
  }, { storeKey: browser.storeKey });
  return {
    finish: () => handle.evaluate(value => value.finish()),
    close: async () => { try { await handle.evaluate(value => value.close()); } catch { /* Destroyed document has no surviving observer. */ } finally { await handle.dispose(); } },
  };
}
