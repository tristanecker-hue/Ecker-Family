const { onDocumentWritten } = require('firebase-functions/v2/firestore');
const { initializeApp } = require('firebase-admin/app');
const { getFirestore, FieldValue } = require('firebase-admin/firestore');
const { getMessaging } = require('firebase-admin/messaging');
const { todoMessages, rewardMessages } = require('./logic');

initializeApp();
// Region = Standort der Firestore-Datenbank (in functions/region.json)
const { region } = require('./region.json');
const OPTS = { region, maxInstances: 2 };

async function send(msgs) {
  const db = getFirestore();
  for (const m of msgs) {
    const toks = [];
    for (const key of [...new Set(m.to)]) {
      const d = await db.doc('pushTokens/' + key).get();
      ((d.exists && d.data().tokens) || []).forEach(t => toks.push({ key, t }));
    }
    if (!toks.length) continue;
    const res = await getMessaging().sendEachForMulticast({
      tokens: toks.map(x => x.t),
      data: { title: m.title, body: m.body, url: m.url || './' },
      webpush: { headers: { Urgency: 'high', TTL: '86400' } }
    });
    const dead = {};
    res.responses.forEach((r, i) => {
      const c = r.error && r.error.code;
      if (c === 'messaging/registration-token-not-registered' || c === 'messaging/invalid-registration-token') (dead[toks[i].key] = dead[toks[i].key] || []).push(toks[i].t);
    });
    for (const k of Object.keys(dead)) await db.doc('pushTokens/' + k).set({ tokens: FieldValue.arrayRemove(...dead[k]) }, { merge: true });
  }
}

exports.onTodo = onDocumentWritten({ ...OPTS, document: 'todos/{id}' }, async ev => {
  const b = ev.data.before.exists ? ev.data.before.data() : null;
  const a = ev.data.after.exists ? ev.data.after.data() : null;
  await send(todoMessages(b, a));
});

exports.onReward = onDocumentWritten({ ...OPTS, document: 'rewards/{kid}' }, async ev => {
  const b = ev.data.before.exists ? ev.data.before.data() : null;
  const a = ev.data.after.exists ? ev.data.after.data() : null;
  await send(rewardMessages(ev.params.kid, b, a));
});
