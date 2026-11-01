"""Synthetic training lines for the AI Call Shield (tools/ai/shield_lines.jsonl).

Scam calls follow scripts. Each playbook below is one script in 5 steps, and each step has lines a caller might
say, in English, Hinglish and Hindi. Slots are filled at random (fixed seed), so the same command always writes
the same file. Everything is synthetic and written for this project: no real call, no real person, numbers in
+91 90000 xxxxx, links on .example. "chatter" is ordinary call talk that says nothing about the script.

    python tools/ai/shield_data.py          # writes tools/ai/shield_lines.jsonl
"""
from __future__ import annotations

import json
import random
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "tools" / "ai" / "shield_lines.jsonl"
SEED = 11
PER_TEMPLATE = 4

SLOTS = {
    "agency": ["CBI", "Mumbai Police", "Narcotics Bureau", "Cyber Crime Branch", "Customs", "Crime Branch"],
    "agency_hi": ["सीबीआई", "मुंबई पुलिस", "नारकोटिक्स ब्यूरो", "साइबर क्राइम ब्रांच", "कस्टम विभाग"],
    "city": ["Mumbai", "Delhi", "Kolkata", "Hyderabad", "Chennai"],
    "item": ["drugs", "fake passports", "MDMA", "illegal items", "five fake passports", "narcotics"],
    "item_hi": ["ड्रग्स", "नकली पासपोर्ट", "गैरकानूनी सामान", "नशीला पदार्थ"],
    "amount": ["2,499", "15,000", "49,999", "1,20,000", "3,50,000", "8,000", "25,000"],
    "app": ["AnyDesk", "QuickSupport", "a screen sharing app", "the support app", "the bank helper app"],
    "platform": ["WhatsApp", "Skype", "Telegram"],
    "number": ["+91 90000 41237", "+91 90000 58210", "9000077341", "+91 90000 12650"],
    "link": ["kyc-update.example", "bank-verify.example/kyc", "secure-kyc.example", "help-desk.example/form"],
    "task": ["like YouTube videos", "rate hotels", "review restaurants", "follow pages", "rate products"],
    "item_sale": ["sofa", "bike", "fridge", "phone", "study table", "almirah"],
}

# ---------------------------------------------------------------------------- the playbooks
# (playbook id, step id): [templates]. English first, then Hinglish, then Hindi.
LINES = {
    ("digital-arrest", "hook"): [
        "Hello, I am calling from {agency}, this is about a parcel booked in your name",
        "This call is from the courier office, your parcel to Taiwan has been stopped at {city} customs",
        "Sir this is the telecom department, your mobile number will be disconnected in two hours",
        "I am an officer from {agency}, please confirm your full name and Aadhaar number",
        "Madam your courier has been seized by customs at {city} airport, press nine to talk to the officer",
        "Sir main {agency} se bol raha hoon, aapke naam pe ek parcel book hua hai",
        "Aapka mobile number do ghante mein band ho jayega, telecom department se call hai",
        "Courier office se baat kar raha hoon, aapka parcel {city} customs ne rok liya hai",
        "नमस्ते, मैं {agency_hi} से बोल रहा हूँ, आपके नाम पर एक पार्सल बुक हुआ है",
        "आपका पार्सल {city} कस्टम पर रोक दिया गया है, अधिकारी से बात करने के लिए नौ दबाएँ",
    ],
    ("digital-arrest", "accuse"): [
        "Your parcel contains {item} and five bank cards, a case has been registered against you",
        "Your Aadhaar is linked to a money laundering case, there is an FIR in {city}",
        "We found {item} in the package sent from your ID, this is a serious crime",
        "Your bank account was used for illegal transactions of rupees {amount}, you are a suspect",
        "Sir aapke parcel mein {item} mile hain, aapke khilaf FIR darj hui hai",
        "Aapka Aadhaar money laundering case mein use hua hai, aap suspect ho",
        "Aapke account se {amount} rupaye ka illegal transaction hua hai, case ban gaya hai",
        "आपके पार्सल में {item_hi} मिला है, आपके खिलाफ केस दर्ज हुआ है",
        "आपका आधार मनी लॉन्ड्रिंग केस में जुड़ा है, आपके नाम पर एफआईआर है",
    ],
    ("digital-arrest", "video"): [
        "I am transferring your call to the {agency} officer, please join a video call on {platform}",
        "Download {platform} now, the inspector will verify you on a video call",
        "Switch on your camera, the senior officer from {agency} wants to see your face",
        "You will now speak to the investigating officer, keep your ID card ready for the video call",
        "Main aapka call {agency} officer ko transfer kar raha hoon, {platform} pe video call join karo",
        "Camera on karo, senior officer aapse video call pe baat karenge",
        "Abhi {platform} download karo, inspector aapko video pe verify karenge",
        "मैं आपकी कॉल {agency_hi} के अधिकारी को ट्रांसफर कर रहा हूँ, वीडियो कॉल पर आइए",
        "कैमरा चालू कीजिए, बड़े अधिकारी आपसे वीडियो कॉल पर बात करेंगे",
    ],
    ("digital-arrest", "isolate"): [
        "You are under digital arrest now, do not disconnect this call",
        "Do not tell anyone in your family, this is a confidential national security matter",
        "Stay in your room and keep the camera on until the investigation is over",
        "If you cut the call, a team will come to arrest you within one hour",
        "Aap digital arrest mein ho, call mat kaatna",
        "Ghar walon ko kuch mat batana, yeh secret investigation hai",
        "Camera on rakho aur kamre se bahar mat jana, warna arrest warrant nikal jayega",
        "आप डिजिटल अरेस्ट में हैं, कॉल मत काटिए",
        "परिवार में किसी को मत बताइए, यह गोपनीय जाँच है, कमरे से बाहर मत जाइए",
    ],
    ("digital-arrest", "pay"): [
        "To prove you are innocent, transfer your savings to the RBI verification account",
        "Move the money to this safe government account, it will be returned after the verification",
        "You have to pay a security deposit of rupees {amount} to close the case",
        "Send the funds by RTGS to the account I share, the court will refund it in 24 hours",
        "Apni saari savings RBI verification account mein transfer karo, verification ke baad wapas milegi",
        "Case band karne ke liye {amount} rupaye security deposit bhejna padega",
        "Jo account number de raha hoon usme RTGS karo, paisa safe rahega",
        "निर्दोष साबित होने के लिए अपनी जमा राशि आरबीआई वेरिफिकेशन खाते में भेजिए",
        "केस बंद करने के लिए {amount} रुपये की सिक्योरिटी डिपॉजिट भेजनी होगी",
    ],
    ("bank-kyc", "hook"): [
        "Hello, I am calling from your bank's KYC department, your KYC has expired",
        "Sir this is a call from the bank head office about your account verification",
        "Your PAN card is not linked with your bank account, I am calling to update it",
        "Madam your debit card KYC is pending, we need to complete it on this call",
        "Main bank ke KYC department se bol raha hoon, aapka KYC expire ho gaya hai",
        "Sir aapka PAN card account se link nahi hai, update karna padega",
        "Bank head office se call hai, aapke account ka verification pending hai",
        "मैं बैंक के केवाईसी विभाग से बोल रहा हूँ, आपका केवाईसी खत्म हो गया है",
        "आपका पैन कार्ड खाते से लिंक नहीं है, इसे अभी अपडेट करना होगा",
    ],
    ("bank-kyc", "urgency"): [
        "Your account will be blocked today if you do not update it in two hours",
        "Your salary will not be credited and your card will be frozen tonight",
        "This is the last reminder, after this your net banking will be closed permanently",
        "Do it right now sir, the system will deactivate your account at six pm",
        "Do ghante mein update nahi kiya to aapka account aaj hi block ho jayega",
        "Aaj raat aapka card freeze ho jayega, salary bhi nahi aayegi",
        "Last reminder hai sir, abhi karo warna net banking band",
        "दो घंटे में अपडेट नहीं किया तो आपका खाता आज ही बंद हो जाएगा",
        "आज रात आपका कार्ड फ्रीज़ हो जाएगा, यह आखिरी चेतावनी है",
    ],
    ("bank-kyc", "link"): [
        "I am sending you a link on SMS, open {link} and fill your details",
        "Please install {app} from the play store so I can help you update",
        "Click the link I sent and enter your customer ID and password",
        "Download the app I am sending, it will verify your account automatically",
        "Aapko SMS pe link bheja hai, {link} kholo aur details bharo",
        "Play store se {app} download karo, main aapki screen se update kar dunga",
        "Link pe click karke customer ID aur password daalo",
        "मैंने एसएमएस पर लिंक भेजा है, उसे खोलकर अपनी जानकारी भरिए",
        "प्ले स्टोर से {app} डाउनलोड कीजिए, मैं अपडेट कर दूँगा",
    ],
    ("bank-kyc", "otp"): [
        "You will get a six digit OTP now, please read it out to me",
        "Tell me the OTP you just received to complete the KYC",
        "Confirm your debit card number, expiry date and the CVV on the back",
        "Enter your ATM PIN on the screen and tell me the code that comes",
        "Abhi aapke phone pe OTP aayega, mujhe bata dijiye",
        "Card number, expiry aur peeche wala CVV bata do",
        "Jo code aaya hai woh bolo, KYC complete ho jayega",
        "अभी आपके फ़ोन पर ओटीपी आएगा, वह मुझे बताइए",
        "अपने कार्ड का नंबर और पीछे लिखा सीवीवी बताइए",
    ],
    ("bank-kyc", "drain"): [
        "The verification failed, you will get one more OTP, read that also",
        "Some amount got debited by mistake, it will be refunded, just share the next code",
        "Do not call the bank now, the process is still running on our side",
        "Rupees {amount} went out because of a system error, give me the new OTP to reverse it",
        "Verification fail ho gaya, ek aur OTP aayega woh bhi bata do",
        "Galti se paise kat gaye hain, refund ke liye agla code bolo",
        "Bank ko abhi call mat karna, process chal raha hai",
        "वेरिफिकेशन फेल हो गया, एक और ओटीपी आएगा, वह भी बताइए",
        "गलती से पैसे कट गए हैं, वापस करने के लिए अगला कोड बताइए",
    ],
    ("task-job", "hook"): [
        "Hi, we have a part-time work from home job, you can earn {amount} rupees daily",
        "Simple online task, just {task} and get paid for every task",
        "Our company is hiring, no experience needed, only one hour a day on your phone",
        "Would you like to earn extra income by {task} from home",
        "Part time job hai, ghar baithe roz {amount} rupaye kamao",
        "Bas {task} hai, har task ke paise milenge",
        "Company hiring kar rahi hai, sirf phone chahiye, experience nahi",
        "घर बैठे पार्ट टाइम काम है, रोज़ {amount} रुपये कमाइए",
        "बस वीडियो लाइक करने हैं, हर टास्क के पैसे मिलेंगे",
    ],
    ("task-job", "trust"): [
        "You completed three tasks, we have sent 150 rupees commission to your UPI",
        "See, the payment is real, check your account, your first salary has come",
        "Well done, your bonus of 300 rupees is credited, now you can do more tasks",
        "This is your first payout, everyone in our group earns daily like this",
        "Teen task ho gaye, 150 rupaye commission aapke UPI pe bhej diya",
        "Dekho payment real hai, apna account check karo, bonus aa gaya",
        "Pehla payout aa gaya, hamare group mein sab roz aise hi kamate hain",
        "आपने तीन टास्क पूरे किए, 150 रुपये कमीशन आपके यूपीआई पर भेज दिया",
        "देखिए पेमेंट असली है, आपका पहला बोनस आ गया",
    ],
    ("task-job", "prepaid"): [
        "Now join our Telegram group for premium tasks with higher commission",
        "For the merchant task you have to prepay rupees {amount} first, it comes back with 30 percent profit",
        "To unlock the VIP level, deposit 1,000 rupees on the task website",
        "The next tasks are prepaid, recharge your task account and complete them",
        "Ab hamare Telegram group mein aao, premium task milenge",
        "Merchant task ke liye pehle {amount} rupaye jama karne honge, profit ke saath wapas",
        "VIP level unlock karne ke liye website pe 1000 rupaye deposit karo",
        "अब हमारे टेलीग्राम ग्रुप में जुड़िए, प्रीमियम टास्क मिलेंगे",
        "अगले टास्क के लिए पहले {amount} रुपये जमा करने होंगे",
    ],
    ("task-job", "escalate"): [
        "Your account shows a negative balance, deposit {amount} to clear it",
        "You got a combo task, complete it by adding {amount} rupees, then you can withdraw everything",
        "You made an error in the task, pay {amount} to correct it or you lose your earnings",
        "Your credit score dropped, add more money to restore it",
        "Aapka balance negative ho gaya hai, {amount} jama karke clear karo",
        "Combo task aaya hai, {amount} aur daalo phir sab withdraw kar sakte ho",
        "Task mein galti hui hai, {amount} bharo warna kamaai doob jayegi",
        "आपका बैलेंस नेगेटिव है, {amount} रुपये जमा करके साफ़ कीजिए",
        "कॉम्बो टास्क आया है, और पैसे डालिए फिर सब निकाल सकते हैं",
    ],
    ("task-job", "locked"): [
        "Your funds are frozen, pay the 20 percent tax to withdraw",
        "To release your money you need to pay an upgrade fee of rupees {amount}",
        "Withdrawal is blocked until you pay the clearance charge",
        "Your account is under review, pay the unlock fee or the money will be lost",
        "Aapke paise freeze ho gaye hain, nikalne ke liye 20 percent tax bharo",
        "Withdrawal ke liye {amount} rupaye upgrade fee deni padegi",
        "Clearance charge bharo tabhi paisa niklega",
        "आपके पैसे फ्रीज़ हो गए हैं, निकालने के लिए टैक्स भरिए",
        "पैसे निकालने के लिए {amount} रुपये फीस देनी होगी",
    ],
    ("upi-refund", "hook"): [
        "Hello, I saw your {item_sale} on the selling app, I want to buy it, I am an army officer",
        "Sir you have a refund of rupees {amount} from your electricity bill, I am calling to process it",
        "I will pay the full amount in advance, no need to show the {item_sale}",
        "Your order was cancelled, I am calling from customer support to give your refund",
        "Aapka {item_sale} app pe dekha, main lena chahta hoon, main army mein hoon",
        "Aapka {amount} rupaye ka refund pending hai, process karne ke liye call kiya",
        "Main pura paisa advance de dunga, {item_sale} dikhane ki zaroorat nahi",
        "मैंने आपका {item_sale} देखा, मुझे खरीदना है, मैं आर्मी में हूँ",
        "आपका {amount} रुपये का रिफंड बाकी है, उसे देने के लिए कॉल किया है",
    ],
    ("upi-refund", "qr"): [
        "I am sending you a QR code on WhatsApp, scan it to receive the money",
        "I sent a payment request on your UPI app, please approve it",
        "Scan this QR code with any UPI app and the amount will come to you",
        "Check your UPI app, there is a collect request of rupees {amount}",
        "WhatsApp pe QR code bheja hai, scan karo paisa aa jayega",
        "UPI app pe request bheji hai, approve kar do",
        "Yeh QR scan karo, {amount} rupaye aapke account mein aayenge",
        "मैंने व्हाट्सऐप पर क्यूआर कोड भेजा है, स्कैन कीजिए, पैसे आ जाएँगे",
        "आपके यूपीआई ऐप पर रिक्वेस्ट भेजी है, उसे स्वीकार कीजिए",
    ],
    ("upi-refund", "pin"): [
        "Now enter your UPI PIN to receive the payment",
        "Type your PIN, the money will be credited immediately",
        "Put the six digit PIN, that is how you receive money on UPI",
        "Just enter PIN and click pay, the amount will reverse to you",
        "Ab apna UPI PIN daalo, payment receive ho jayegi",
        "PIN daalo aur pay dabao, paisa aapke paas aayega",
        "Paise lene ke liye PIN dalna padta hai",
        "अब अपना यूपीआई पिन डालिए, पैसे मिल जाएँगे",
        "पिन डालकर पे दबाइए, रकम आपके खाते में आएगी",
    ],
    ("upi-refund", "mistake"): [
        "Oh sorry, I sent rupees {amount} extra by mistake, please send it back",
        "It went the wrong way, scan again and the double amount will come to you",
        "My staff typed one zero extra, kindly return the extra money",
        "The payment failed on my side, do it once more and I will pay double",
        "Galti se {amount} zyada chale gaye, wapas bhej do please",
        "Ulta ho gaya, dobara scan karo double paisa aayega",
        "Mere staff ne ek zero zyada daal diya, extra paisa lauta do",
        "गलती से {amount} रुपये ज़्यादा चले गए, कृपया वापस भेज दीजिए",
        "उल्टा हो गया, दोबारा स्कैन कीजिए, दोगुने पैसे आएँगे",
    ],
    ("upi-refund", "repeat"): [
        "Do it fast, my senior officer is waiting, just one more time",
        "Hurry, the request will expire in two minutes, approve it again",
        "Last time I promise, scan the new code and everything will be settled",
        "Do not cut the call, try again quickly, the bank server is slow",
        "Jaldi karo, mere senior wait kar rahe hain, bas ek baar aur",
        "Request do minute mein expire ho jayegi, phir se approve karo",
        "Aakhri baar, naya code scan karo sab settle ho jayega",
        "जल्दी कीजिए, मेरे सीनियर इंतज़ार कर रहे हैं, बस एक बार और",
        "रिक्वेस्ट दो मिनट में खत्म हो जाएगी, फिर से स्वीकार कीजिए",
    ],
}

CHATTER = [
    "Hello, who is speaking", "Yes, tell me", "Hello hello, can you hear me", "Sorry, the network is bad",
    "Wait one minute please", "Okay sir", "I did not understand, say again", "Yes I am listening",
    "Hold on, let me get a pen", "Can you speak slowly", "Haan ji, boliye", "Kaun bol raha hai",
    "Ek minute rukiye", "Theek hai", "Samajh nahi aaya, phir se bolo", "Awaaz nahi aa rahi",
    "Haan main sun raha hoon", "Achha ji", "हाँ जी, बोलिए", "कौन बोल रहा है", "एक मिनट रुकिए", "ठीक है",
    "समझ नहीं आया, फिर से बोलिए", "आवाज़ नहीं आ रही है", "हाँ, मैं सुन रहा हूँ", "Good morning",
    "I am driving right now", "Call me after some time", "Main abhi office mein hoon", "Baad mein call karo",
    "मैं अभी गाड़ी चला रहा हूँ", "बाद में कॉल कीजिए", "What is this regarding", "Yeh kis baare mein hai",
    "यह किस बारे में है", "Please hold the line", "Line pe rahiye", "लाइन पर रहिए",
]

def lang_of(text: str) -> str:
    if any("ऀ" <= ch <= "ॿ" for ch in text):
        return "hi"
    hinglish = ("hai", "karo", "aap", "mein", "ke liye", "bhej", "nahi", "rupaye", "bolo", "ho gaya", "kar", "daalo")
    return "hinglish" if any(w in text.lower().split() or w in text.lower() for w in hinglish) else "en"


def fill(template: str, rng: random.Random) -> str:
    out = template
    for key, values in SLOTS.items():
        token = "{" + key + "}"
        while token in out:
            out = out.replace(token, rng.choice(values), 1)
    return out


# Callers pad their lines: "Sir, ...", "..., samjhe?". Padding varies the lines without changing the step.
PREFIX = {"latin": ["", "", "Sir, ", "Madam, ", "Listen, ", "Look, ", "Dekhiye, ", "Suniye, ", "Okay so "],
          "hi": ["", "", "देखिए, ", "सुनिए, ", "सर, ", "मैडम, "]}
SUFFIX = {"latin": ["", "", ", okay?", " please", ", understood?", ", samjhe?", " jaldi", " right now"],
          "hi": ["", "", ", समझे?", ", ठीक है?", " जल्दी", "।"]}


def build(seed: int = SEED) -> list[dict]:
    rng = random.Random(seed)
    rows, seen = [], set()
    for (playbook, step), templates in LINES.items():
        for template in templates:
            script = "hi" if any("\u0900" <= ch <= "\u097f" for ch in template) else "latin"
            for _ in range(PER_TEMPLATE):
                text = rng.choice(PREFIX[script]) + fill(template, rng) + rng.choice(SUFFIX[script])
                if text not in seen:
                    seen.add(text)
                    rows.append({"label": f"{playbook}:{step}", "lang": lang_of(text), "text": text})
    for text in CHATTER:
        rows.append({"label": "chatter", "lang": lang_of(text), "text": text})
    return rows


def main() -> int:
    rows = build()
    OUT.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows), encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)}: {len(rows)} lines")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
