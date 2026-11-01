/* On-device scam-message reader: an AI suggestion that can be wrong.
   Multinomial Naive Bayes over word unigrams and bigrams, trained by tools/ai/train_reader.py on synthetic
   messages (tools/ai/messages.jsonl). The message text never leaves this page: the only network request is
   the one-time GET of the model file, started when the page loads, before there is any text. classify()
   makes no request. It suggests a kind of scam; it never sets or changes a verdict.
   The tokenizer must match train_reader.py exactly (tests/e2e/test_ai_reader.py checks it). */
(function (root) {
  "use strict";
  const MODEL_URL = "/static/ai/reader_model.json";
  const DIGITS = /[0-9०-९]/g;
  const JOINERS = /[‌‍]/g;
  const TOKEN = /[a-zऀ-ॣ॰-ॿ]+/g;
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

  function tokenize(text) {
    const t = String(text == null ? "" : text).normalize("NFC").toLowerCase().replace(JOINERS, "").replace(DIGITS, " ");
    return (t.match(TOKEN) || []).filter(w => w.length >= 2);
  }

  function features(text) {
    const toks = tokenize(text), out = toks.slice();
    for (let i = 0; i + 1 < toks.length; i++) out.push(toks[i] + " " + toks[i + 1]);
    return out;
  }

  function ll(table, i) {
    const v = table.seen[String(i)];
    return v === undefined ? table.unseen : v;
  }

  // ------------------------------------------------------------------ hardening ("Attack our AI")
  // Tricks that hide words from a text classifier are undone before reading. An undo only ever produces a
  // word the model already knows, so amounts, names, UPI IDs and normal text stay as they are. Finding a
  // trick is itself a red flag: a real bank never writes "КYС" with Russian letters.
  // Must match harden() in tools/ai/train_reader.py exactly (tests/e2e/test_ai_reader.py checks it).
  const STRIP = /[\u00AD\u034F\u061C\u115F\u1160\u17B4\u17B5\u180B-\u180E\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u206F\u3164\uFE00-\uFE0F\uFEFF\uFFA0]/g;
  const HIDDEN = /[\u00AD\u034F\u115F\u1160\u180E\u200B\u202A-\u202E\u2060-\u2064\u2066-\u2069\u3164\uFFA0]/;
  const LOOK = {
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T", "У": "Y",
    "Х": "X", "Ѕ": "S", "І": "I", "Ј": "J", "Ү": "Y", "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y",
    "х": "x", "ѕ": "s", "і": "i", "ј": "j", "ԁ": "d", "һ": "h", "ӏ": "l", "к": "k", "м": "m", "т": "t", "н": "h",
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P",
    "Τ": "T", "Υ": "Y", "Χ": "X", "α": "a", "ο": "o", "ρ": "p", "ι": "i", "κ": "k", "ν": "v", "τ": "t", "υ": "u",
    "χ": "x", "ε": "e", "ᴀ": "a", "ʙ": "b", "ᴄ": "c", "ᴅ": "d", "ᴇ": "e", "ɢ": "g", "ʜ": "h", "ɪ": "i", "ᴊ": "j",
    "ᴋ": "k", "ʟ": "l", "ᴍ": "m", "ɴ": "n", "ᴏ": "o", "ᴘ": "p", "ʀ": "r", "ꜱ": "s", "ᴛ": "t", "ᴜ": "u", "ᴠ": "v",
    "ᴡ": "w", "ʏ": "y", "ᴢ": "z",
  };
  const LOOK_RE = new RegExp("[" + Object.keys(LOOK).join("") + "]", "g");
  const LEET = {"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "@": "a", "$": "s"};
  const LEET_TOKEN = /[a-z0-9@$]+/g;
  const SPACED = /(?<![a-z])(?:[a-z][\s.\-_*•·|,]{1,3}){2,}[a-z](?![a-z])/g;
  const INJECTION = /\b(ai|a\.i|bot|filter|spam filter|classifier|assistant|chatgpt|gpt|llm|scanner|antivirus|moderator)\b[^.!?\n।]{0,50}\b(safe|genuine|verified|legit|legitimate|trusted|whitelisted|harmless|not a scam|not scam|not spam)\b|\bignore (all |any |the )?(previous|prior|above|earlier|other) (instructions|rules|messages|warnings)\b|\b(note|message|instruction|instructions) (to|for) (the )?(ai|bot|filter|assistant|scanner)\b/;

  function known(word) { return index !== null && index.has(word); }

  // -> {text, tricks}: the text with the tricks undone, and which tricks were found
  function harden(text) {
    const tricks = [];
    let t = String(text == null ? "" : text).normalize("NFKC");
    if (HIDDEN.test(t)) tricks.push("hidden");
    t = t.replace(STRIP, "");
    let looks = 0;
    t = t.replace(LOOK_RE, ch => { looks++; return LOOK[ch]; });
    if (looks) tricks.push("lookalike");
    t = t.toLowerCase();
    let leet = 0;
    t = t.replace(LEET_TOKEN, w => {
      if (!/[a-z]/.test(w) || !/[0-9@$]/.test(w)) return w;
      const a = w.replace(/[0-9@$]/g, c => LEET[c] || c);
      if (a !== w && known(a)) { leet++; return a; }
      const b = w.replace(/[0-9@$]/g, c => (c === "1" ? "l" : LEET[c] || c));
      if (b !== w && known(b)) { leet++; return b; }
      return w;
    });
    if (leet) tricks.push("leet");
    let spaced = 0;
    t = t.replace(SPACED, m => {
      const j = m.replace(/[^a-z]/g, "");
      if (known(j)) { spaced++; return j; }
      return m;
    });
    if (spaced) tricks.push("spaced");
    let talks = 0;
    t = t.replace(/[^.!?\n।]*[.!?\n।]?/g, seg => { if (seg && INJECTION.test(seg)) { talks++; return " "; } return seg; });
    if (talks) tricks.push("talks_to_ai");
    return {text: t, tricks};
  }

  // The plain Naive Bayes reading, with no hardening: what an unprotected model would say.
  function classifyRaw(text) {
    if (!model) return null;
    const present = new Map();
    for (const f of features(text)) {
      const i = index.get(f);
      if (i !== undefined) present.set(i, (present.get(i) || 0) + 1);
    }
    let known = 0;
    present.forEach(n => { known += n; });
    if (known < 3) return null;
    const scores = {};
    for (const c of model.classes) {
      const table = model.log_likelihoods[c];
      let s = model.log_priors[c];
      present.forEach((n, i) => { s += n * ll(table, i); });
      scores[c] = s;
    }
    const T = model.temperature || 1;
    const max = Math.max(...Object.values(scores));
    let z = 0;
    const p = {};
    for (const c of model.classes) { p[c] = Math.exp((scores[c] - max) / T); z += p[c]; }
    const ranked = model.classes.slice().sort((a, b) => p[b] - p[a]);
    const best = ranked[0], runner = ranked[1];
    const lb = model.log_likelihoods[best], lr = model.log_likelihoods[runner];
    const contrib = [];
    present.forEach((n, i) => contrib.push([n * (ll(lb, i) - ll(lr, i)), model.vocabulary[i]]));
    contrib.sort((a, b) => b[0] - a[0] || (a[1] < b[1] ? 1 : a[1] > b[1] ? -1 : 0));
    const words = [], used = new Set();
    for (const [gain, f] of contrib) {
      if (gain <= 0 || words.length === 3) break;
      const parts = f.split(" ");
      if (parts.some(w => used.has(w))) continue;
      words.push(f);
      parts.forEach(w => used.add(w));
    }
    return {type: best, confidence: Math.round(p[best] / z * 10000) / 10000, top_words: words, flags: flags(text)};
  }

  // {type, confidence, top_words, flags}, or null while the model is loading or when the text has fewer than
  // 3 words the model knows (a bare number, an amount). Hardened: tricks are undone first, and a long
  // message that reads as "not a scam" is also read in windows of 12 words, so friendly padding cannot
  // drown a scam ("good word attack"): a window read as a scam at 0.7 or more counts. Found tricks are added
  // to the red flags. Window 12, step 4, threshold 0.7: picked from 8 settings in tools/ai/robustness.py, none
  // of which changed false alarms on safe messages.
  function classify(text) {
    if (!model) return null;
    const h = harden(text);
    let res = classifyRaw(h.text), padded = false;
    if (!res || res.type === "not_scam" || res.confidence < 0.5) {
      const toks = tokenize(h.text);
      if (toks.length >= 20) {
        let best = null;
        for (let i = 0; i + 12 <= toks.length; i += 4) {
          const w = classifyRaw(toks.slice(i, i + 12).join(" "));
          if (w && w.type !== "not_scam" && w.confidence >= 0.7 && (!best || w.confidence > best.confidence)) best = w;
        }
        if (best) { res = best; padded = true; }
      }
    }
    if (!res) return null;
    const fl = flags(h.text);
    for (const k of h.tricks.concat(padded ? ["padding"] : [])) if (!fl.includes(k)) fl.push(k);
    return {type: res.type, confidence: res.confidence, top_words: res.top_words, flags: fl};
  }

  // Red flags: simple patterns, independent of the model. Each is a fact about the text, not a verdict.
  const NEG = /\b(do not|don't|dont|never|not|mat|nahi|nahin|kabhi)\b|\bna\b|(^|\s)(न|ना|मत|नहीं|कभी)(\s|$)/;
  const SECRET = /\b(otp|one time password|pin|cvv|password|code)\b|ओटीपी|पिन|सीवीवी|पासवर्ड|कोड|वन टाइम पासवर्ड/g;
  const ASK = /\b(share|send|tell|give|forward|read out|confirm|type|enter|batao|bata do|bataiye|bhejo|bhej do|de do|do|bolo|likho|daalo|dalo|daal do|dal do)\b|बताएं|बताइए|बताओ|बता दीजिए|बता दें|भेज दीजिए|भेजो|भेजें|लिखें|दें|डालें|दर्ज करें/;
  const RULES = {
    urgency: /\b(urgent|urgently|immediately|right now|act now|asap|within \d+\s*(hours?|hrs?|minutes?|mins?)|today itself|last (chance|warning|reminder)|final (warning|notice|reminder)|before midnight|(update|call|pay|act|reply|verify|click|join|confirm|send) (it )?now|(blocked|suspended|disconnected|cut|closed|deactivated|frozen|freeze|expire|expires|lapse|stopped|returned) (today|tonight|within)|turant|fauran|aaj hi|aaj raat[^.!?]{0,40}(kaat|kat|band)|aakhri (warning|mauka|notice)|jaldi (karo|karein|kijiye)|abhi (karo|karein|bharo|bhejo|pay|call))\b|तुरंत|फौरन|आज ही|आज रात[^।.!?]{0,40}(काट|कट|बंद)|अंतिम चेतावनी|आखिरी चेतावनी|आखिरी मौका|अंतिम नोटिस|अंतिम अनुस्मारक|जल्दी करें|अभी (करें|भरें|भेजें|कॉल)/,
    payment: /\b(pay|deposit|transfer (rs|inr|money|the|your|funds|amount)|send (rs|inr|money|the money|the amount)|processing fee|registration fee|joining fee|clearance (fee|charges?)|penalty|paisa bhej\w*|paise bhej\w*|rupaye bhej\w*|amount bhej\w*|fee bhej\w*|jama kar\w*|bharo|bhar do)\b|₹\s?\d[\d,]*\s*(fee|charge)|भुगतान करें|भुगतान करो|भुगतान करना|पैसे भेज|रुपये भेज|राशि भेज|जमा करें|जमा करो|जमा कर|शुल्क|फीस|जुर्माना/,
    police: /\b(police|cbi|cyber cell|cyber crime|crime branch|narcotics|enforcement directorate|court|warrant|arrest|arrested|fir|money laundering|giraftaar|jail)\b|पुलिस|गिरफ्तार|गिरफ़्तार|अदालत|कोर्ट|वारंट|एफआईआर|सीबीआई|मनी लॉन्ड्रिंग|क्राइम ब्रांच|हिरासत|जेल/,
    link: /https?:\/\/|\bwww\.|\b[a-z0-9-]+(\.[a-z0-9-]+)*\.(example|com|in|net|org|co|xyz|top|info|link|live|site|online|app|me|ly|io|shop|club)\b/,
    prize: /\b(you (have )?won|winner|lottery|lucky draw|jackpot|prize|cash reward|scratch card|gift voucher|inaam|jeeta|jeete|jeeti)\b|इनाम|लॉटरी|जैकपॉट|विजेता|स्क्रैच कार्ड|उपहार वाउचर|जीता|जीते|जीती/,
  };
  const JOB = /\b(job|naukri|vacancy|hiring|recruitment|work from home|part[ -]?time|task|tasks|hr|salary|offer letter|joining)\b|नौकरी|भर्ती|वर्क फ्रॉम होम|टास्क|वेतन|तनख्वाह|नियुक्ति/;
  const FEE = /\b(deposit|registration|joining fee|security (deposit|amount)|training fee|processing|refundable|recharge|fee|pay)\b|जमा कर|जमा राशि|पंजीकरण|फीस|शुल्क/;

  function asksForSecret(t) {
    SECRET.lastIndex = 0;
    let m;
    while ((m = SECRET.exec(t)) !== null) {
      const w = t.slice(Math.max(0, m.index - 40), m.index + m[0].length + 40);
      if (ASK.test(w) && !NEG.test(w)) return true;
    }
    return false;
  }

  function flags(text) {
    const t = String(text == null ? "" : text).normalize("NFC").toLowerCase();
    const out = [];
    if (RULES.urgency.test(t)) out.push("urgency");
    if (RULES.payment.test(t)) out.push("payment");
    if (RULES.police.test(t)) out.push("police");
    if (asksForSecret(t)) out.push("otp");
    if (RULES.link.test(t)) out.push("link");
    if (RULES.prize.test(t)) out.push("prize");
    if (JOB.test(t) && FEE.test(t)) out.push("job_deposit");
    return out;
  }

  root.ScamMapReader = {
    load, classify, classifyRaw, harden, tokenize, features, flags,
    ready: () => model !== null,
    info: () => model && {version: model.version, cross_validation: model.cross_validation, confident_at: model.confident_at},
  };
})(typeof window !== "undefined" ? window : globalThis);
