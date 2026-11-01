"""Train the AI Call Shield: which scam script a caller is following, which step they are on, what comes next.

Two small models, no LLM, standard library only:
1. Multinomial Naive Bayes reads one line the caller said and scores every script step (plus "chatter", ordinary
   call talk). Same tokenizer and features as the message reader (train_reader.py), so the browser reuses them.
2. A hidden Markov model follows the call: each script runs forward through its 5 steps (stay, next, or skip one;
   rarely back). The forward algorithm turns the line scores into "which script, which step" after every line,
   and the transition table gives the most likely next step.

The browser (app/static/ai/shield.js) runs the same maths on the phone: nothing typed ever leaves it.

    python tools/ai/train_shield.py           # cross-validates, checks the held-out calls, writes the model
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import train_reader as tr  # noqa: E402  (same tokenizer, features, Naive Bayes and folds)

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "tools" / "ai" / "shield_lines.jsonl"
HELDOUT = ROOT / "tests" / "unit" / "data" / "shield_heldout.jsonl"
OUT = ROOT / "app" / "static" / "ai" / "shield_model.json"
VERSION = "shield-v1"
# A call follows one script, mostly forward. "jump" (3+ steps ahead) was added after held-out call arrest-hinglish
# showed the first version could not skip two steps; 3 new sparse calls were written before it was re-run.
HMM = {"start_first": 0.7, "stay": 0.45, "next": 0.35, "skip": 0.1, "jump": 0.05, "back": 0.05, "chatter_skip": 0.5,
       "eps": 1e-4}

PLAYBOOKS = [
    {"id": "digital-arrest", "scam_type": "digital-arrest", "en": "Digital arrest", "hi": "डिजिटल अरेस्ट", "steps": [
        {"id": "hook", "en": "An 'official' calls: courier, customs, telecom or police",
         "hi": "'अधिकारी' का कॉल: कूरियर, कस्टम, टेलीकॉम या पुलिस",
         "do_en": "Hang up. Call the courier or department yourself, on a number you find on their official website.",
         "do_hi": "कॉल काटिए। कूरियर या विभाग को खुद उनकी आधिकारिक वेबसाइट वाले नंबर पर कॉल कीजिए।"},
        {"id": "accuse", "en": "They accuse you: drugs in a parcel, your Aadhaar in a money-laundering case",
         "hi": "आप पर आरोप: पार्सल में ड्रग्स, आपका आधार मनी-लॉन्ड्रिंग केस में",
         "do_en": "This is the digital arrest script. No real case is handled over a phone call. Hang up and call 1930.",
         "do_hi": "यह डिजिटल अरेस्ट की स्क्रिप्ट है। असली केस फ़ोन कॉल पर नहीं चलता। कॉल काटिए और 1930 पर कॉल कीजिए।"},
        {"id": "video", "en": "They 'transfer' you to CBI or police and want a video call",
         "hi": "आपको 'CBI या पुलिस' से जोड़ते हैं और वीडियो कॉल माँगते हैं",
         "do_en": "Do not join the video call. Real police do not question or arrest anyone on a video call.",
         "do_hi": "वीडियो कॉल पर मत आइए। असली पुलिस वीडियो कॉल पर पूछताछ या गिरफ़्तारी नहीं करती।"},
        {"id": "isolate", "en": "You are 'under digital arrest': do not hang up, do not tell anyone",
         "hi": "'डिजिटल अरेस्ट' में हैं: कॉल मत काटिए, किसी को मत बताइए",
         "do_en": "Hang up now and tell your family. Keeping you alone and scared is the whole trick.",
         "do_hi": "अभी कॉल काटिए और परिवार को बताइए। आपको अकेला और डरा हुआ रखना ही पूरी चाल है।"},
        {"id": "pay", "en": "They ask you to move your money to a 'safe' or 'RBI verification' account",
         "hi": "पैसे 'सुरक्षित' या 'RBI वेरिफिकेशन' खाते में भेजने को कहते हैं",
         "do_en": "Send nothing. No agency 'verifies' your savings by holding them. Call 1930 and your bank now.",
         "do_hi": "कुछ भी मत भेजिए। कोई एजेंसी आपकी जमा राशि रखकर 'जाँच' नहीं करती। अभी 1930 और अपने बैंक को कॉल कीजिए।"},
    ]},
    {"id": "bank-kyc", "scam_type": "fake-kyc-link", "en": "Bank KYC and OTP", "hi": "बैंक KYC और OTP", "steps": [
        {"id": "hook", "en": "A 'bank' caller says your KYC has expired",
         "hi": "'बैंक' से कॉल: आपका KYC खत्म हो गया है",
         "do_en": "Banks do not update KYC on a phone call. Hang up and call the number printed on your card.",
         "do_hi": "बैंक फ़ोन कॉल पर KYC अपडेट नहीं करते। कॉल काटिए और कार्ड पर लिखे नंबर पर कॉल कीजिए।"},
        {"id": "urgency", "en": "Your account or card will be 'blocked today'",
         "hi": "'आज ही' खाता या कार्ड बंद होने की धमकी",
         "do_en": "The rush is the trick. Your bank will not block you within hours because of a call.",
         "do_hi": "जल्दबाज़ी ही चाल है। एक कॉल की वजह से बैंक घंटों में खाता बंद नहीं करता।"},
        {"id": "link", "en": "They send a link or ask you to install a screen-sharing app",
         "hi": "लिंक भेजते हैं या स्क्रीन-शेयरिंग ऐप डलवाते हैं",
         "do_en": "Do not open the link or install any app. A screen-sharing app lets them see everything you type.",
         "do_hi": "लिंक मत खोलिए, कोई ऐप मत डालिए। स्क्रीन-शेयरिंग ऐप से वे आपका सब कुछ देख लेते हैं।"},
        {"id": "otp", "en": "They ask for the OTP, PIN, CVV or card number",
         "hi": "OTP, PIN, CVV या कार्ड नंबर माँगते हैं",
         "do_en": "Never share an OTP, PIN or CVV with anyone, not even someone who says they are the bank. Hang up.",
         "do_hi": "OTP, PIN या CVV किसी को मत बताइए, बैंक के नाम पर भी नहीं। कॉल काटिए।"},
        {"id": "drain", "en": "'It failed, one more OTP': money leaves your account",
         "hi": "'फेल हो गया, एक और OTP': खाते से पैसे निकलते हैं",
         "do_en": "Call your bank now to block the card and account, then call 1930.",
         "do_hi": "अभी बैंक को कॉल करके कार्ड और खाता बंद करवाइए, फिर 1930 पर कॉल कीजिए।"},
    ]},
    {"id": "task-job", "scam_type": "job-offer", "en": "Task job (part-time work)", "hi": "टास्क जॉब (पार्ट-टाइम काम)", "steps": [
        {"id": "hook", "en": "An easy part-time job: like videos or rate hotels for money",
         "hi": "आसान पार्ट-टाइम काम: वीडियो लाइक करो, होटल रेट करो",
         "do_en": "Real jobs do not pay you to like videos. Do not share bank or UPI details.",
         "do_hi": "असली नौकरी वीडियो लाइक करने के पैसे नहीं देती। बैंक या UPI की जानकारी मत दीजिए।"},
        {"id": "trust", "en": "They pay a small amount first so it feels real",
         "hi": "पहले थोड़े पैसे देते हैं ताकि सच लगे",
         "do_en": "The small first payout is bait. It is there to win your trust before they ask for deposits.",
         "do_hi": "पहला छोटा भुगतान चारा है। यह भरोसा जीतने के लिए है, ताकि बाद में बड़ी रकम माँग सकें।"},
        {"id": "prepaid", "en": "They move you to a Telegram group and ask for a deposit to unlock tasks",
         "hi": "टेलीग्राम ग्रुप में ले जाते हैं और टास्क खोलने के लिए जमा राशि माँगते हैं",
         "do_en": "Never pay to get a job or to unlock tasks. Leave the group.",
         "do_hi": "नौकरी पाने या टास्क खोलने के लिए कभी पैसे मत दीजिए। ग्रुप छोड़ दीजिए।"},
        {"id": "escalate", "en": "Bigger deposits to 'clear a negative balance' or finish a 'combo task'",
         "hi": "'नेगेटिव बैलेंस' या 'कॉम्बो टास्क' के नाम पर बड़ी रकम",
         "do_en": "Stop paying. The balance on their website is not real money.",
         "do_hi": "पैसे देना बंद कीजिए। उनकी वेबसाइट का बैलेंस असली पैसा नहीं है।"},
        {"id": "locked", "en": "Your money is 'frozen': pay a tax or fee to withdraw",
         "hi": "पैसे 'फ़्रीज़': निकालने के लिए टैक्स या फीस भरो",
         "do_en": "No fee will release the money. Stop, keep the chats and call 1930.",
         "do_hi": "कोई फीस पैसे नहीं छुड़ाएगी। रुकिए, चैट सँभालकर रखिए और 1930 पर कॉल कीजिए।"},
    ]},
    {"id": "upi-refund", "scam_type": "upi-refund-qr", "en": "UPI refund or QR", "hi": "UPI रिफंड या QR", "steps": [
        {"id": "hook", "en": "Someone wants to buy your item, or 'refund' you money you did not ask for",
         "hi": "कोई आपका सामान खरीदना या बिना माँगे 'रिफंड' देना चाहता है",
         "do_en": "A buyer who pays before seeing the item, or a refund you never asked for, is a warning sign.",
         "do_hi": "सामान देखे बिना पैसे देने वाला खरीदार, या बिना माँगा रिफंड, ख़तरे का संकेत है।"},
        {"id": "qr", "en": "They send a QR code or a payment request",
         "hi": "QR कोड या पेमेंट रिक्वेस्ट भेजते हैं",
         "do_en": "Scanning a QR code or approving a request sends money out of your account. You never scan to receive.",
         "do_hi": "QR स्कैन करने या रिक्वेस्ट मंज़ूर करने से पैसे आपके खाते से जाते हैं। पैसे पाने के लिए कभी स्कैन नहीं करना होता।"},
        {"id": "pin", "en": "They say: enter your UPI PIN to receive the money",
         "hi": "कहते हैं: पैसे पाने के लिए UPI PIN डालो",
         "do_en": "You never enter a PIN to receive money. Stop now.",
         "do_hi": "पैसे पाने के लिए कभी PIN नहीं डालना होता। अभी रुकिए।"},
        {"id": "mistake", "en": "'I sent too much by mistake': they want money back",
         "hi": "'गलती से ज़्यादा भेज दिया': पैसे वापस माँगते हैं",
         "do_en": "Check your bank app, not their screenshot. Send nothing back.",
         "do_hi": "अपना बैंक ऐप देखिए, उनका स्क्रीनशॉट नहीं। कुछ भी वापस मत भेजिए।"},
        {"id": "repeat", "en": "Pressure to do it again, fast",
         "hi": "जल्दी-जल्दी दोबारा करने का दबाव",
         "do_en": "Stop. Block the number and report it on the Report tab.",
         "do_hi": "रुकिए। नंबर ब्लॉक कीजिए और रिपोर्ट टैब पर उसकी रिपोर्ट कीजिए।"},
    ]},
]
CLASSES = [f"{p['id']}:{s['id']}" for p in PLAYBOOKS for s in p["steps"]] + ["chatter"]


# ------------------------------------------------------------------ one line
def line_probs(model, text):
    """Probability of every class for one line, or None when the line has fewer than 3 known words."""
    s, present = tr.scores(model, text)
    if sum(present.values()) < 3:
        return None
    return tr.softmax(s, model["temperature"])


# ------------------------------------------------------------------ the whole call (forward algorithm)
def _transitions(k, n, h):
    w = {k: h["stay"], k + 1: h["next"], k + 2: h["skip"], k - 1: h["back"]}
    far = list(range(k + 3, n))                  # a longer jump ahead: shared by every step 3 or more ahead
    for j in far:
        w[j] = h["jump"] / len(far)
    w = {j: x for j, x in w.items() if 0 <= j < n}
    z = sum(w.values())
    return {j: x / z for j, x in w.items()}


def decode(model, lines):
    """Follow a call line by line. Returns None until a line says something about a script."""
    h = model["hmm"]
    books = model["playbooks"]
    alpha, used, path = None, 0, []
    for i, line in enumerate(lines):
        p = line_probs(model, line)
        if p is None or p["chatter"] >= h["chatter_skip"]:
            continue
        if alpha is None:
            alpha = {}
            for b in books:
                n = len(b["steps"])
                for k in range(n):
                    alpha[(b["id"], k)] = math.log((h["start_first"] if k == 0 else (1 - h["start_first"]) / (n - 1)) / len(books))
        else:
            nxt = {}
            for b in books:
                n = len(b["steps"])
                for k in range(n):
                    a = alpha[(b["id"], k)]
                    for j, t in _transitions(k, n, h).items():
                        v = a + math.log(t)
                        cur = nxt.get((b["id"], j))
                        nxt[(b["id"], j)] = v if cur is None else max(cur, v) + math.log1p(math.exp(-abs(cur - v)))
            alpha = nxt
        for b in books:
            for k, st in enumerate(b["steps"]):
                alpha[(b["id"], k)] += math.log(p[f"{b['id']}:{st['id']}"] + h["eps"])
        m = max(alpha.values())
        z = m + math.log(sum(math.exp(v - m) for v in alpha.values()))
        alpha = {s: v - z for s, v in alpha.items()}
        used += 1
        best = max(alpha, key=alpha.get)
        path.append({"line": i, "playbook": best[0], "step": best[1]})
    if alpha is None:
        return None
    post = {s: math.exp(v) for s, v in alpha.items()}
    by_book = Counter()
    for (b, _), v in post.items():
        by_book[b] += v
    book_id = max(by_book, key=by_book.get)
    book = next(b for b in books if b["id"] == book_id)
    n = len(book["steps"])
    step_p = [post[(book_id, k)] / by_book[book_id] for k in range(n)]
    k = max(range(n), key=lambda j: step_p[j])
    return {"playbook": book_id, "playbook_p": round(by_book[book_id], 4), "step": k, "step_id": book["steps"][k]["id"],
            "step_p": round(step_p[k], 4), "next": k + 1 if k + 1 < n else None, "lines_used": used, "path": path}


# ------------------------------------------------------------------ evaluation
def cross_validate(docs, labels):
    fold = tr.folds_for(labels)
    oof = [None] * len(docs)
    for f in range(tr.FOLDS):
        train_idx = [i for i in range(len(docs)) if fold[i] != f]
        model = tr.train([docs[i] for i in train_idx], [labels[i] for i in train_idx], CLASSES)
        for i in (i for i in range(len(docs)) if fold[i] == f):
            oof[i] = tr.scores(model, docs[i])[0]

    def nll(t):
        return -sum(math.log(max(tr.softmax(s, t)[y], 1e-12)) for s, y in zip(oof, labels)) / len(labels)
    temperature = min(tr.TEMPERATURES, key=nll)
    pred = [max(s, key=s.get) for s in oof]
    book = lambda c: c.split(":")[0]
    return {"folds": tr.FOLDS, "seed": tr.SEED, "temperature": temperature, "lines": len(labels),
            "step_accuracy": round(sum(y == p for y, p in zip(labels, pred)) / len(labels), 3),
            "script_accuracy": round(sum(book(y) == book(p) for y, p in zip(labels, pred)) / len(labels), 3)}


def check_heldout(model, path=HELDOUT):
    calls = [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]
    out = {"calls": len(calls), "script_right": 0, "step_right": 0, "next_right": 0, "rows": []}
    for c in calls:
        got = decode(model, c["lines"]) or {}
        book = next((b for b in model["playbooks"] if b["id"] == got.get("playbook")), None)
        nxt = book["steps"][got["next"]]["id"] if book and got.get("next") is not None else None
        ok_book, ok_step = got.get("playbook") == c["playbook"], got.get("step_id") == c["final_step"]
        ok_next = ok_book and nxt == c["next_step"]
        out["script_right"] += ok_book
        out["step_right"] += ok_book and ok_step
        out["next_right"] += ok_next
        out["rows"].append({"id": c["id"], "want": [c["playbook"], c["final_step"], c["next_step"]],
                            "got": [got.get("playbook"), got.get("step_id"), nxt], "p": got.get("playbook_p")})
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", type=Path, default=DATA)
    ap.add_argument("--out", type=Path, default=OUT)
    args = ap.parse_args(argv)
    rows = [json.loads(x) for x in args.data.read_text(encoding="utf-8").splitlines() if x.strip()]
    docs, labels = [r["text"] for r in rows], [r["label"] for r in rows]
    assert set(labels) == set(CLASSES), set(labels) ^ set(CLASSES)
    cv = cross_validate(docs, labels)
    model = tr.train(docs, labels, CLASSES)
    out = {"version": VERSION, "classes": CLASSES, "tokenizer": tr.TOKENIZER, "alpha": tr.ALPHA, "min_df": tr.MIN_DF,
           "temperature": cv["temperature"], "hmm": HMM, "playbooks": PLAYBOOKS,
           "trained_on": {"lines": len(docs), "per_class": dict(Counter(labels)),
                          "languages": dict(Counter(r.get("lang", "?") for r in rows)),
                          "data_sha256": hashlib.sha256(args.data.read_bytes()).hexdigest()},
           "cross_validation": cv,
           "vocabulary": model["vocabulary"],
           "log_priors": {c: round(v, 4) for c, v in model["log_priors"].items()},
           "log_likelihoods": {c: {"unseen": round(v["unseen"], 4),
                                   "seen": {str(i): round(x, 4) for i, x in sorted(v["seen"].items())}}
                               for c, v in model["log_likelihoods"].items()}}
    held = check_heldout(out)
    out["heldout"] = {k: held[k] for k in ("calls", "script_right", "step_right", "next_right")}
    print(f"{cv['folds']}-fold cross-validation on our synthetic lines ({cv['lines']}): "
          f"step {cv['step_accuracy']:.1%}, script {cv['script_accuracy']:.1%}, temperature {cv['temperature']}")
    for r in held["rows"]:
        mark = "ok " if r["want"] == r["got"] else "BAD"
        print(f"  {mark} {r['id']:<16} want {r['want']}  got {r['got']}  p={r['p']}")
    print(f"held-out calls: script {held['script_right']}/{held['calls']}, step {held['step_right']}/{held['calls']}, "
          f"next step {held['next_right']}/{held['calls']}")
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(out, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    print(f"wrote {args.out.relative_to(ROOT) if args.out.is_relative_to(ROOT) else args.out}: "
          f"{len(out['vocabulary'])} features, {args.out.stat().st_size // 1024} KB")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
