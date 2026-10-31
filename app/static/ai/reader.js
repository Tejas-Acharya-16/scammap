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

  // {type, confidence, top_words, flags}, or null while the model is loading or when the text has
  // fewer than 3 words the model knows (a bare number, an amount).
  function classify(text) {
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
    load, classify, tokenize, features, flags,
    ready: () => model !== null,
    info: () => model && {version: model.version, cross_validation: model.cross_validation, confident_at: model.confident_at},
  };
})(typeof window !== "undefined" ? window : globalThis);
