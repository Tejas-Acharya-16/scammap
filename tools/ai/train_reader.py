#!/usr/bin/env python3
"""Train the on-device scam-message reader: multinomial Naive Bayes on word unigrams and bigrams.

    python tools/ai/train_reader.py                       # 5-fold cross-validation, then writes the model
    python tools/ai/train_reader.py --check FILE.jsonl    # classify held-out messages with the written model

Standard library only. Input: tools/ai/messages.jsonl ({"type", "lang", "text"} per line, synthetic).
Output: app/static/ai/reader_model.json, read by app/static/ai/reader.js in the browser.
The tokenizer here and in reader.js must stay identical (tests/unit/test_ai_reader.py checks it).

The model only suggests a kind of scam for a message the person pasted. It never sets a verdict.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
import re
import sys
import unicodedata
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "tools" / "ai" / "messages.jsonl"
OUT = ROOT / "app" / "static" / "ai" / "reader_model.json"
VERSION = "reader-v1"
ALPHA = 0.5          # Laplace smoothing, fixed before looking at results
MIN_DF = 2           # a feature must appear in 2 or more training messages
FOLDS, SEED = 5, 7
CONFIDENT = 0.7      # the app pre-selects a kind only at or above this confidence
TEMPERATURES = [1, 1.5, 2, 3, 4, 5, 6, 8, 10, 12, 15, 20, 25, 30, 40, 50, 70, 100]

DIGITS = re.compile("[0-9०-९]")
JOINERS = re.compile("[‌‍]")
TOKEN = re.compile("[a-zऀ-ॣ॰-ॿ]+")
TOKENIZER = ("NFC; lower case; remove U+200C/U+200D; digits 0-9 and Devanagari digits become spaces; "
             "tokens are runs of a-z and Devanagari letters and marks (U+0900-0963, U+0970-097F), 2+ characters; "
             "features are the tokens and each pair of neighbouring tokens")


def tokenize(text: str) -> list[str]:
    t = unicodedata.normalize("NFC", str(text)).lower()
    t = DIGITS.sub(" ", JOINERS.sub("", t))
    return [w for w in TOKEN.findall(t) if len(w) >= 2]


def features(text: str) -> list[str]:
    toks = tokenize(text)
    return toks + [a + " " + b for a, b in zip(toks, toks[1:])]


# ------------------------------------------------------------------ training
def train(docs: list[str], labels: list[str], classes: list[str]) -> dict:
    feats = [features(d) for d in docs]
    df = Counter(f for fs in feats for f in set(fs))
    vocab = sorted(f for f, n in df.items() if n >= MIN_DF)
    index = {f: i for i, f in enumerate(vocab)}
    counts = {c: Counter() for c in classes}
    n_docs = Counter(labels)
    for fs, y in zip(feats, labels):
        counts[y].update(index[f] for f in fs if f in index)
    V = len(vocab)
    log_priors, log_lik = {}, {}
    for c in classes:
        total = sum(counts[c].values())
        denom = math.log(total + ALPHA * V)
        log_priors[c] = math.log(n_docs[c] / len(docs))
        log_lik[c] = {"unseen": math.log(ALPHA) - denom,
                      "seen": {i: math.log(n + ALPHA) - denom for i, n in counts[c].items()}}
    return {"classes": classes, "vocabulary": vocab, "log_priors": log_priors, "log_likelihoods": log_lik}


def scores(model: dict, text: str, _index_cache={}) -> tuple[dict, Counter]:
    key = id(model)
    if _index_cache.get("key") != key:
        _index_cache.update(key=key, index={f: i for i, f in enumerate(model["vocabulary"])})
    index = _index_cache["index"]
    present = Counter(index[f] for f in features(text) if f in index)
    out = {}
    for c in model["classes"]:
        ll = model["log_likelihoods"][c]
        seen, unseen = ll["seen"], ll["unseen"]
        out[c] = model["log_priors"][c] + sum(n * seen.get(i, seen.get(str(i), unseen)) for i, n in present.items())
    return out, present


def softmax(s: dict, temperature: float) -> dict:
    m = max(s.values())
    e = {c: math.exp((v - m) / temperature) for c, v in s.items()}
    z = sum(e.values())
    return {c: v / z for c, v in e.items()}


# ------------------------------------------------------------------ hardening ("Attack our AI")
# Tricks that hide words from a text classifier, undone before reading. An undo only ever produces a word the
# model already knows. Must match harden() in app/static/ai/reader.js exactly (tests/e2e/test_ai_reader.py).
STRIP = re.compile("[\u00AD\u034F\u061C\u115F\u1160\u17B4\u17B5\u180B-\u180E\u200B-\u200F\u202A-\u202E"
                   "\u2060-\u2064\u2066-\u206F\u3164\uFE00-\uFE0F\uFEFF\uFFA0]")
HIDDEN = re.compile("[\u00AD\u034F\u115F\u1160\u180E\u200B\u202A-\u202E\u2060-\u2064\u2066-\u2069\u3164\uFFA0]")
LOOK = {
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T", "У": "Y",
    "Х": "X", "Ѕ": "S", "І": "I", "Ј": "J", "Ү": "Y", "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y",
    "х": "x", "ѕ": "s", "і": "i", "ј": "j", "ԁ": "d", "һ": "h", "ӏ": "l", "к": "k", "м": "m", "т": "t", "н": "h",
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P",
    "Τ": "T", "Υ": "Y", "Χ": "X", "α": "a", "ο": "o", "ρ": "p", "ι": "i", "κ": "k", "ν": "v", "τ": "t", "υ": "u",
    "χ": "x", "ε": "e", "ᴀ": "a", "ʙ": "b", "ᴄ": "c", "ᴅ": "d", "ᴇ": "e", "ɢ": "g", "ʜ": "h", "ɪ": "i", "ᴊ": "j",
    "ᴋ": "k", "ʟ": "l", "ᴍ": "m", "ɴ": "n", "ᴏ": "o", "ᴘ": "p", "ʀ": "r", "ꜱ": "s", "ᴛ": "t", "ᴜ": "u", "ᴠ": "v",
    "ᴡ": "w", "ʏ": "y", "ᴢ": "z",
}
LOOK_RE = re.compile("[" + "".join(LOOK) + "]")
LEET = {"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "@": "a", "$": "s"}
LEET_TOKEN = re.compile("[a-z0-9@$]+")
SPACED = re.compile("(?<![a-z])(?:[a-z][\\s.\\-_*•·|,]{1,3}){2,}[a-z](?![a-z])", re.ASCII)
INJECTION = re.compile(
    r"\b(ai|a\.i|bot|filter|spam filter|classifier|assistant|chatgpt|gpt|llm|scanner|antivirus|moderator)\b"
    r"[^.!?\n।]{0,50}\b(safe|genuine|verified|legit|legitimate|trusted|whitelisted|harmless|not a scam|not scam|not spam)\b"
    r"|\bignore (all |any |the )?(previous|prior|above|earlier|other) (instructions|rules|messages|warnings)\b"
    r"|\b(note|message|instruction|instructions) (to|for) (the )?(ai|bot|filter|assistant|scanner)\b", re.ASCII)


def harden(model: dict, text: str) -> tuple[str, list[str]]:
    """(text with the tricks undone, the tricks found), as reader.js harden() does."""
    vocab = _unigrams(model)
    tricks = []
    t = unicodedata.normalize("NFKC", str(text))
    if HIDDEN.search(t):
        tricks.append("hidden")
    t = STRIP.sub("", t)
    looks = [0]

    def look(m):
        looks[0] += 1
        return LOOK[m.group(0)]
    t = LOOK_RE.sub(look, t)
    if looks[0]:
        tricks.append("lookalike")
    t = t.lower()
    leet = [0]

    def unleet(m):
        w = m.group(0)
        if not re.search("[a-z]", w) or not re.search("[0-9@$]", w):
            return w
        a = re.sub("[0-9@$]", lambda c: LEET.get(c.group(0), c.group(0)), w)
        if a != w and a in vocab:
            leet[0] += 1
            return a
        b = re.sub("[0-9@$]", lambda c: "l" if c.group(0) == "1" else LEET.get(c.group(0), c.group(0)), w)
        if b != w and b in vocab:
            leet[0] += 1
            return b
        return w
    t = LEET_TOKEN.sub(unleet, t)
    if leet[0]:
        tricks.append("leet")
    spaced = [0]

    def unspace(m):
        j = re.sub("[^a-z]", "", m.group(0))
        if j in vocab:
            spaced[0] += 1
            return j
        return m.group(0)
    t = SPACED.sub(unspace, t)
    if spaced[0]:
        tricks.append("spaced")
    talks = [0]

    def drop(m):
        seg = m.group(0)
        if seg and INJECTION.search(seg):
            talks[0] += 1
            return " "
        return seg
    t = re.sub("[^.!?\n।]*[.!?\n।]?", drop, t)
    if talks[0]:
        tricks.append("talks_to_ai")
    return t, tricks


def _unigrams(model: dict, _cache={}) -> set:
    if _cache.get("key") != id(model):
        _cache.update(key=id(model), words={f for f in model["vocabulary"] if " " not in f})
    return _cache["words"]


def classify(model: dict, text: str) -> dict | None:
    """Hardened reading, as reader.js classify(): tricks undone first; a long message that reads as not a scam
    is also read in windows of 12 words (stride 4) so padding cannot drown a scam. {type, confidence, top_words,
    tricks}; None when the text has fewer than 3 known words."""
    hard, tricks = harden(model, text)
    res, padded = classify_raw(model, hard), False
    if res is None or res["type"] == "not_scam" or res["confidence"] < 0.5:
        toks = tokenize(hard)
        if len(toks) >= 20:
            best = None
            for i in range(0, len(toks) - 12 + 1, 4):
                w = classify_raw(model, " ".join(toks[i:i + 12]))
                if w and w["type"] != "not_scam" and w["confidence"] >= 0.7 and (best is None or w["confidence"] > best["confidence"]):
                    best = w
            if best:
                res, padded = best, True
    if res is None:
        return None
    return {**res, "tricks": tricks + (["padding"] if padded else [])}


def classify_raw(model: dict, text: str) -> dict | None:
    """{type, confidence, top_words}; None when the text has fewer than 3 known words. No hardening."""
    s, present = scores(model, text)
    if sum(present.values()) < 3:
        return None
    probs = softmax(s, model.get("temperature", 1.0))
    ranked = sorted(probs, key=probs.get, reverse=True)
    best, runner = ranked[0], ranked[1]
    lb, lr = model["log_likelihoods"][best], model["log_likelihoods"][runner]
    vocab = model["vocabulary"]

    def ll(table, i):
        return table["seen"].get(i, table["seen"].get(str(i), table["unseen"]))

    contrib = sorted(((n * (ll(lb, i) - ll(lr, i)), vocab[i]) for i, n in present.items()), reverse=True)
    words, used = [], set()
    for gain, f in contrib:
        if gain <= 0 or len(words) == 3:
            break
        parts = set(f.split(" "))
        if parts & used:
            continue
        words.append(f)
        used |= parts
    return {"type": best, "confidence": round(probs[best], 4), "top_words": words}


# ------------------------------------------------------------------ evaluation
def folds_for(labels: list[str]) -> list[int]:
    """Stratified: every class is spread evenly over the folds, in a fixed shuffled order."""
    rng = random.Random(SEED)
    fold = [0] * len(labels)
    by_class = defaultdict(list)
    for i, y in enumerate(labels):
        by_class[y].append(i)
    for y in sorted(by_class):
        idx = by_class[y]
        rng.shuffle(idx)
        for k, i in enumerate(idx):
            fold[i] = k % FOLDS
    return fold


def cross_validate(docs, labels, classes) -> dict:
    fold = folds_for(labels)
    oof = [None] * len(docs)
    for k in range(FOLDS):
        tr = [i for i in range(len(docs)) if fold[i] != k]
        model = train([docs[i] for i in tr], [labels[i] for i in tr], classes)
        for i in (i for i in range(len(docs)) if fold[i] == k):
            oof[i] = scores(model, docs[i])[0]
    # temperature that makes the out-of-fold confidences honest (lowest log loss)
    def nll(T):
        return -sum(math.log(max(softmax(s, T)[y], 1e-12)) for s, y in zip(oof, labels)) / len(labels)
    temperature = min(TEMPERATURES, key=nll)
    pred = [max(s, key=s.get) for s in oof]
    conf = [softmax(s, temperature)[p] for s, p in zip(oof, pred)]
    matrix = [[sum(1 for y, p in zip(labels, pred) if y == a and p == b) for b in classes] for a in classes]
    per_class = {}
    for j, c in enumerate(classes):
        tp = matrix[j][j]
        col = sum(matrix[i][j] for i in range(len(classes)))
        row = sum(matrix[j])
        p = tp / col if col else 0.0
        r = tp / row if row else 0.0
        per_class[c] = {"precision": round(p, 3), "recall": round(r, 3),
                        "f1": round(2 * p * r / (p + r), 3) if p + r else 0.0, "support": row}
    sure = [i for i, x in enumerate(conf) if x >= CONFIDENT]
    return {"folds": FOLDS, "seed": SEED, "temperature": temperature,
            "accuracy": round(sum(y == p for y, p in zip(labels, pred)) / len(labels), 3),
            "macro_f1": round(sum(v["f1"] for v in per_class.values()) / len(classes), 3),
            "per_class": per_class, "confusion": {"labels": classes, "matrix": matrix},
            "at_or_above_0_7": {"share": round(len(sure) / len(labels), 3),
                                "accuracy": round(sum(labels[i] == pred[i] for i in sure) / len(sure), 3) if sure else None}}


# ------------------------------------------------------------------ output
SHORT = {"digital-arrest": "arrest", "fake-kyc-link": "kyc", "upi-refund-qr": "qr", "investment-group": "invest",
         "courier-customs": "courier", "job-offer": "job", "lottery-prize": "prize", "loan-app-harassment": "loan",
         "electricity-disconnection": "power", "fake-customer-care": "care", "otp-call": "otp",
         "sextortion": "sextort", "not_scam": "ok"}


def report(cv: dict) -> str:
    cls = cv["confusion"]["labels"]
    lines = [f"{cv['folds']}-fold cross-validation on our synthetic messages (seed {cv['seed']})",
             f"accuracy {cv['accuracy']:.3f}   macro F1 {cv['macro_f1']:.3f}   temperature {cv['temperature']}",
             f"confidence >= {CONFIDENT}: {cv['at_or_above_0_7']['share']:.1%} of messages, "
             f"{cv['at_or_above_0_7']['accuracy']:.1%} of those right", "",
             f"{'class':<27}{'precision':>10}{'recall':>8}{'F1':>7}{'n':>5}"]
    for c in cls:
        v = cv["per_class"][c]
        lines.append(f"{c:<27}{v['precision']:>10.3f}{v['recall']:>8.3f}{v['f1']:>7.3f}{v['support']:>5}")
    lines += ["", "confusion matrix (rows: true, columns: predicted)",
              " " * 9 + "".join(f"{SHORT[c]:>8}" for c in cls)]
    for c, row in zip(cls, cv["confusion"]["matrix"]):
        lines.append(f"{SHORT[c]:<9}" + "".join(f"{n:>8}" for n in row))
    return "\n".join(lines)


def load_data(path: Path):
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    return [r["text"] for r in rows], [r["type"] for r in rows], rows


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", type=Path, default=DATA)
    ap.add_argument("--out", type=Path, default=OUT)
    ap.add_argument("--check", type=Path, help="classify a JSONL of held-out messages with the written model")
    args = ap.parse_args(argv)
    if args.check:
        model = json.loads(args.out.read_text(encoding="utf-8"))
        right = 0
        for line in args.check.read_text(encoding="utf-8").splitlines():
            row = json.loads(line)
            got = classify(model, row["text"]) or {"type": None, "confidence": 0, "top_words": []}
            right += got["type"] == row["type"]
            print(f"{'ok ' if got['type'] == row['type'] else 'BAD'} {row['type']:<26} -> {str(got['type']):<26} "
                  f"{got['confidence']:.2f} {got['top_words']}")
        print(f"{right} of the held-out messages right")
        return 0
    docs, labels, rows = load_data(args.data)
    classes = sorted(set(labels) - {"not_scam"}) + ["not_scam"]
    cv = cross_validate(docs, labels, classes)
    print(report(cv))
    model = train(docs, labels, classes)
    model["log_likelihoods"] = {c: {"unseen": round(v["unseen"], 4),
                                    "seen": {str(i): round(x, 4) for i, x in sorted(v["seen"].items())}}
                                for c, v in model["log_likelihoods"].items()}
    model["log_priors"] = {c: round(v, 4) for c, v in model["log_priors"].items()}
    out = {"version": VERSION, "classes": classes, "tokenizer": TOKENIZER, "alpha": ALPHA, "min_df": MIN_DF,
           "temperature": cv["temperature"], "confident_at": CONFIDENT,
           "trained_on": {"messages": len(docs), "per_class": dict(Counter(labels)),
                          "languages": dict(Counter(r.get("lang", "?") for r in rows)),
                          "data_sha256": hashlib.sha256(args.data.read_bytes()).hexdigest()},
           "cross_validation": {k: cv[k] for k in ("folds", "seed", "accuracy", "macro_f1", "per_class",
                                                    "confusion", "at_or_above_0_7")},
           "vocabulary": model["vocabulary"], "log_priors": model["log_priors"],
           "log_likelihoods": model["log_likelihoods"]}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(out, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    print(f"\nwrote {args.out.relative_to(ROOT) if args.out.is_relative_to(ROOT) else args.out}: "
          f"{len(out['vocabulary'])} features, {args.out.stat().st_size // 1024} KB")
    return 0


if __name__ == "__main__":
    sys.exit(main())
