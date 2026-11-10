// Reine Logik: wer bekommt bei welcher Änderung welche Meldung
const NAMES = { tristan: 'Tristan', claudia: 'Claudia', lina: 'Lina', florian: 'Florian' };
const PARENTS = ['tristan', 'claudia'];
const KIDS = ['lina', 'florian'];
const nm = k => NAMES[k] || k;

function todoMessages(before, after) {
  if (!after) return [];
  const url = './#todos', out = [];
  const text = after.text || 'Aufgabe';
  if (!before) {
    if (after.assigneeKey && after.assigneeKey !== after.createdByKey) {
      out.push({ to: [after.assigneeKey], title: 'Neue Aufgabe', body: text, url });
    }
    return out;
  }
  if (after.claimedAt && !before.claimedAt && !after.done) {
    out.push({ to: PARENTS.filter(p => p !== after.assigneeKey), title: nm(after.assigneeKey) + ' meldet: erledigt', body: text + ' – bitte bestätigen', url });
  }
  if (!before.done && after.done && KIDS.includes(after.assigneeKey)) {
    out.push({ to: [after.assigneeKey], title: 'Bestätigt ✅', body: text, url });
  }
  if (before.claimedAt && !after.claimedAt && !after.done && KIDS.includes(after.assigneeKey)) {
    out.push({ to: [after.assigneeKey], title: 'Bitte nochmals ansehen', body: text, url });
  }
  return out;
}

function rewardMessages(kid, before, after) {
  if (!after || kid === 'catalog') return [];
  const b = (before && before.redeemed) || [], a = after.redeemed || [];
  if (a.length <= b.length) return [];
  const r = a[a.length - 1] || {};
  return [{ to: PARENTS, title: nm(kid) + ' hat eingelöst', body: (r.name || 'Belohnung') + (r.cost ? ' (' + r.cost + ' ⭐)' : ''), url: './#punkte' }];
}

module.exports = { todoMessages, rewardMessages };
