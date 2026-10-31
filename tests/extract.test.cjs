const test = require('node:test');
const assert = require('node:assert/strict');
const { extractCandidates, guessReport } = require('../app/static/extract.js');

const cases = [
  ['Please call +91 90000 12001 today', [['phone', '+91 90000 12001']]],
  ['Call +91-90000-12002 now', [['phone', '+91 90000 12002']]],
  ['Call (+91) 90000 12003 now', [['phone', '+91 90000 12003']]],
  ['Call 9000012004 now', [['phone', '+91 90000 12004']]],
  ['Call 0 90000 12005 now', [['phone', '+91 90000 12005']]],
  ['Call 0091 90000 12006 now', [['phone', '+91 90000 12006']]],
  ['Call 90000-12007 or +91 90000 12008', [
    ['phone', '+91 90000 12007'], ['phone', '+91 90000 12008'],
  ]],
  ['Pay safetydesk12009@okaxis today', [['upi', 'safetydesk12009@okaxis']]],
  ['Pay refund.team12010@ybl today', [['upi', 'refund.team12010@ybl']]],
  ['Use upi://pay?pa=helpdesk12011@okaxis&pn=Demo%20Shop', [
    ['upi', 'upi://pay?pa=helpdesk12011@okaxis&pn=Demo%20Shop'],
  ]],
  ['Open https://parcel.example/track today', [['url', 'https://parcel.example/track']]],
  ['Open hxxps://pay[.]example/claim today', [['url', 'https://pay.example/claim']]],
  ['Open www.verify.example/kyc today', [['url', 'https://www.verify.example/kyc']]],
  ['Open hxxp://refund[.]example/cash today', [['url', 'http://refund.example/cash']]],
  ['SMS came from VM-HDFCBK today', [['sender_id', 'VM-HDFCBK']]],
  ['SMS came from AD-HDFCBK-S today', [['sender_id', 'AD-HDFCBK-S']]],
  ['Call +91 90000 12017 then +91-90000-12017', [['phone', '+91 90000 12017']]],
  ['Message https://offer.example +91 90000 12018 pay help12018@ybl from VM-HDFCBK', [
    ['url', 'https://offer.example'], ['phone', '+91 90000 12018'],
    ['upi', 'help12018@ybl'], ['sender_id', 'VM-HDFCBK'],
  ]],
  ['Compare hxxps://a[.]example and https://b.example then hxxps://a[.]example', [
    ['url', 'https://a.example'], ['url', 'https://b.example'],
  ]],
  ['WhatsApp says parcel customs police arrest. Call +91 90000 12020; pay help12020@ybl', [
    ['phone', '+91 90000 12020'], ['upi', 'help12020@ybl'],
  ]],
];

test('extracts unique synthetic candidates in message order from 20 messages', () => {
  assert.equal(cases.length, 20);
  for (const [message, expected] of cases) {
    assert.deepEqual(extractCandidates(message).map(({ type, value }) => [type, value]), expected, message);
  }
});

test('guesses deterministic scam kinds and channels without using message text as a note', () => {
  const guesses = [
    ['KYC account update +91 90000 12101', 'fake-kyc-link'],
    ['Parcel customs police called +91 90000 12102', 'digital-arrest'],
    ['Lottery prize +91 90000 12103', 'lottery-prize'],
    ['Job task offer +91 90000 12104', 'job-offer'],
    ['Electricity bill warning +91 90000 12105', 'electricity-disconnection'],
    ['Share your OTP +91 90000 12106', 'otp-call'],
    ['Refund QR +91 90000 12107', 'upi-refund-qr'],
    ['Loan app offer +91 90000 12108', 'loan-app-harassment'],
    ['Investment stock trading group +91 90000 12109', 'investment-group'],
    ['Fake customer care +91 90000 12110', 'fake-customer-care'],
  ];
  for (const [message, scamType] of guesses) {
    assert.equal(guessReport(message).scamType, scamType, message);
  }
  assert.equal(guessReport('SMS VM-HDFCBK: KYC +91 90000 12111').channel, 'SMS or WhatsApp');
  assert.equal(guessReport('WhatsApp: KYC +91 90000 12112').channel, 'SMS or WhatsApp');
  assert.equal(guessReport('Pay help12113@ybl for refund').channel, 'UPI request');
});
