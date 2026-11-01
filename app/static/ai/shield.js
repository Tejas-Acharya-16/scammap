/* AI Call Shield, on the phone: which scam script a caller follows, which step they are on, what comes next.
   Naive Bayes scores each line (same tokenizer and features as the message reader, ScamMapReader.features),
   and a hidden Markov model follows the call forward through the script's steps. Trained by
   tools/ai/train_shield.py on synthetic call lines; the maths here must match that file (a browser test checks).
   The only network request is the one-time GET of the model file. Nothing typed ever leaves this page.
   It suggests; it never sets a verdict. */
(function (root) {
  "use strict";
  const MODEL_URL = "/static/ai/shield_model.json";
  let model = null, index = null, loading = null;

  function load() {
    if (!loading) {
      loading = fetch(MODEL_URL, {credentials: "omit"})
        .then(r => { if (!r.ok) throw new Error("model " + r.status); return r.json(); })
        .then(m => { index = new Map(m.vocabulary.map((f, i) => [f, i])); model = m; return true; })
        .catch(() => { loading = null; return false; });
    }
    return loading;
  }

  function ll(table, i) {
    const v = table.seen[String(i)];
    return v === undefined ? table.unseen : v;
  }

  // {probs, present} for one line, or null with fewer than 3 known words.
  function lineProbs(text) {
    if (!model) return null;
    const present = new Map();
    for (const f of root.ScamMapReader.features(text)) {
      const i = index.get(f);
      if (i !== undefined) present.set(i, (present.get(i) || 0) + 1);
    }
    let known = 0;
    present.forEach(n => { known += n; });
    if (known < 3) return null;
    const s = {};
    for (const c of model.classes) {
      let v = model.log_priors[c];
      present.forEach((n, i) => { v += n * ll(model.log_likelihoods[c], i); });
      s[c] = v;
    }
    const T = model.temperature || 1, m = Math.max(...Object.values(s));
    let z = 0;
    const p = {};
    for (const c of model.classes) { p[c] = Math.exp((s[c] - m) / T); z += p[c]; }
    for (const c of model.classes) p[c] /= z;
    return {probs: p, present};
  }

  // The words in a line that pushed it to `cls` most, against the runner-up class (up to 3).
  function why(lp, cls) {
    const others = model.classes.filter(c => c !== cls).sort((a, b) => lp.probs[b] - lp.probs[a]);
    const a = model.log_likelihoods[cls], b = model.log_likelihoods[others[0]];
    const gains = [];
    lp.present.forEach((n, i) => gains.push([n * (ll(a, i) - ll(b, i)), model.vocabulary[i]]));
    gains.sort((x, y) => y[0] - x[0] || (x[1] < y[1] ? -1 : 1));
    const out = [], used = new Set();
    for (const [g, f] of gains) {
      if (g <= 0 || out.length === 3) break;
      const parts = f.split(" ");
      if (parts.some(w => used.has(w))) continue;
      out.push(f);
      parts.forEach(w => used.add(w));
    }
    return out;
  }

  function logAdd(a, b) { return a === undefined ? b : Math.max(a, b) + Math.log1p(Math.exp(-Math.abs(a - b))); }

  function transitions(k, n, h) {
    const w = new Map([[k, h.stay], [k + 1, h.next], [k + 2, h.skip], [k - 1, h.back]]);
    const far = [];
    for (let j = k + 3; j < n; j++) far.push(j);
    for (const j of far) w.set(j, h.jump / far.length);
    let z = 0;
    for (const [j, x] of [...w]) { if (j < 0 || j >= n) w.delete(j); else z += x; }
    for (const [j, x] of w) w.set(j, x / z);
    return w;
  }

  // Follow a call. Returns null until a line says something about a script.
  function decode(lines) {
    if (!model) return null;
    const h = model.hmm, books = model.playbooks, key = (b, k) => b + "|" + k;
    let alpha = null, used = 0, words = [];
    const path = [];
    lines.forEach((line, i) => {
      const lp = lineProbs(line);
      if (!lp || lp.probs.chatter >= h.chatter_skip) return;
      if (!alpha) {
        alpha = {};
        for (const b of books) {
          const n = b.steps.length;
          for (let k = 0; k < n; k++) alpha[key(b.id, k)] = Math.log((k === 0 ? h.start_first : (1 - h.start_first) / (n - 1)) / books.length);
        }
      } else {
        const nxt = {};
        for (const b of books) {
          const n = b.steps.length;
          for (let k = 0; k < n; k++) {
            const a = alpha[key(b.id, k)];
            for (const [j, t] of transitions(k, n, h)) nxt[key(b.id, j)] = logAdd(nxt[key(b.id, j)], a + Math.log(t));
          }
        }
        alpha = nxt;
      }
      for (const b of books) b.steps.forEach((st, k) => { alpha[key(b.id, k)] += Math.log(lp.probs[b.id + ":" + st.id] + h.eps); });
      const vals = Object.values(alpha), m = Math.max(...vals);
      const z = m + Math.log(vals.reduce((s, v) => s + Math.exp(v - m), 0));
      for (const s in alpha) alpha[s] -= z;
      used += 1;
      const best = Object.keys(alpha).reduce((x, y) => alpha[y] > alpha[x] ? y : x);
      const [bid, bk] = best.split("|");
      path.push({line: i, playbook: bid, step: +bk});
      const book = books.find(b => b.id === bid);
      words = why(lp, bid + ":" + book.steps[+bk].id);
    });
    if (!alpha) return null;
    const byBook = {};
    for (const s in alpha) { const b = s.split("|")[0]; byBook[b] = (byBook[b] || 0) + Math.exp(alpha[s]); }
    const bookId = Object.keys(byBook).reduce((x, y) => byBook[y] > byBook[x] ? y : x);
    const book = books.find(b => b.id === bookId), n = book.steps.length;
    const stepP = book.steps.map((_, k) => Math.exp(alpha[key(bookId, k)]) / byBook[bookId]);
    const k = stepP.indexOf(Math.max(...stepP));
    return {playbook: bookId, playbook_p: Math.round(byBook[bookId] * 1e4) / 1e4, step: k, step_id: book.steps[k].id,
            step_p: Math.round(stepP[k] * 1e4) / 1e4, next: k + 1 < n ? k + 1 : null, lines_used: used, path, why: words};
  }

  root.ScamMapShield = {
    load, decode, lineProbs,
    ready: () => model !== null,
    playbooks: () => model && model.playbooks,
    info: () => model && {version: model.version, cross_validation: model.cross_validation, heldout: model.heldout},
  };
})(typeof window !== "undefined" ? window : globalThis);
