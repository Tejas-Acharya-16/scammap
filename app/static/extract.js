/* Deterministic paste parsing. This module is local-only and makes no network calls. */
(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  if (root) root.ScamMapExtract = api;
})(typeof window !== "undefined" ? window : globalThis, function () {
  "use strict";

  const PHONE_RE = /(?<![\w@])((?:\+?91|0091|0)[\s().-]*)?(?:[6-9]\d{4}[\s().-]*\d{5}|[6-9]\d{9})(?![\w])/g;
  const PAY_RE = /(?<![\w])upi:\/\/pay\?[^\s<>"']+/gi;
  const UPI_RE = /(?<![\w@])([a-z0-9][a-z0-9._-]{1,254}@[a-z][a-z0-9]{1,30})(?![\w.-])/gi;
  const SENDER_RE = /\b([A-Z]{2}-[A-Z0-9]{4,10}(?:-[A-Z])?)\b/gi;
  const URL_RE = /(?<![\w@])(?:https?|hxxps?):\/\/[^\s<>"']+|(?<![\w@])www\.[^\s<>"']+|(?<![\w@])(?:[a-z0-9-]+(?:\[\.\]|\.)+)[a-z]{2,}(?:\/[^\s<>"']*)?(?![\w@.-])/gi;

  function trimUrl(value) {
    return value.replace(/[.,!?;:]+$/g, "").replace(/[)\]}]+$/g, "");
  }

  function normalizeUrl(value) {
    let url = trimUrl(value.trim());
    url = url.replace(/^hxxps?:\/\//i, (scheme) => scheme.toLowerCase().startsWith("hxxps") ? "https://" : "http://");
    url = url.replace(/\[\.\]/g, ".");
    if (/^www\./i.test(url) || !/^[a-z][a-z0-9+.-]*:\/\//i.test(url)) url = "https://" + url;
    return url;
  }

  function normalizePhone(value) {
    let digits = value.replace(/\D/g, "");
    if (digits.startsWith("0091") && digits.length === 14) digits = digits.slice(4);
    else if (digits.startsWith("91") && digits.length === 12) digits = digits.slice(2);
    else if (digits.startsWith("0") && digits.length === 11) digits = digits.slice(1);
    if (digits.length !== 10 || !/^[6-9]\d{9}$/.test(digits)) return null;
    return `+91 ${digits.slice(0, 5)} ${digits.slice(5)}`;
  }

  function paymentLinkKey(value) {
    if (!/^upi:\/\/pay\?/i.test(value)) return value.toLowerCase();
    const query = value.slice(value.indexOf("?") + 1).split("&");
    const pa = query.map((part) => part.split("=")).find(([key]) => key.toLowerCase() === "pa");
    if (!pa) return value.toLowerCase();
    try { return decodeURIComponent(pa.slice(1).join("=").replace(/\+/g, "%20")).toLowerCase(); }
    catch (_) { return pa.slice(1).join("=").toLowerCase(); }
  }

  function extractCandidates(text) {
    const source = String(text || "");
    const found = [];
    const addMatches = (regex, type, normalize) => {
      regex.lastIndex = 0;
      let match;
      while ((match = regex.exec(source)) !== null) {
        const raw = match[0];
        const value = normalize(raw);
        if (value) found.push({ type, value, start: match.index, end: match.index + match[0].length });
        if (!match[0].length) regex.lastIndex++;
      }
    };

    addMatches(PAY_RE, "upi", (value) => trimUrl(value));
    addMatches(UPI_RE, "upi", (value) => value);
    addMatches(PHONE_RE, "phone", normalizePhone);
    addMatches(SENDER_RE, "sender_id", (value) => value.toUpperCase());
    addMatches(URL_RE, "url", (value) => /^upi:\/\//i.test(value) ? null : normalizeUrl(value));

    found.sort((a, b) => a.start - b.start || a.end - b.end);
    const seen = new Set();
    return found.filter(({ type, value }) => {
      const keyValue = type === "upi" ? paymentLinkKey(value) : value.toLowerCase();
      const key = `${type}:${keyValue}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    }).map(({ type, value }) => ({ type, value }));
  }

  const KIND_RULES = [
    ["fake-kyc-link", /\bkyc\b/i],
    ["digital-arrest", /\b(?:parcel|customs|police|arrest)\b/i],
    ["lottery-prize", /\b(?:lottery|prize)\b/i],
    ["job-offer", /\b(?:job|task)\b/i],
    ["electricity-disconnection", /\b(?:electricity|bill)\b/i],
    ["otp-call", /\botp\b/i],
    ["upi-refund-qr", /\b(?:refund|qr)\b/i],
    ["loan-app-harassment", /\bloan\b/i],
    ["investment-group", /\b(?:investment|stock|trading)\b/i],
    ["fake-customer-care", /\bcustomer[\s-]+care\b/i],
  ];

  function guessReport(text) {
    const message = String(text || "");
    const candidates = extractCandidates(message);
    const candidate = candidates[0] || null;
    const match = KIND_RULES.find(([, pattern]) => pattern.test(message));
    let channel = "Something else";
    if (candidates.some((item) => item.type === "sender_id") || /\b(?:sms|whatsapp)\b/i.test(message)) {
      channel = "SMS or WhatsApp";
    } else if (candidate && candidate.type === "upi") {
      channel = "UPI request";
    } else if (/\bqr\b/i.test(message)) {
      channel = "QR code";
    } else if (candidate && candidate.type === "url") {
      channel = "Fake website";
    } else if (candidate && candidate.type === "phone") {
      channel = "Phone call";
    }
    return { candidates, candidate, channel, scamType: match ? match[0] : "other" };
  }

  return { extractCandidates, guessReport };
});
