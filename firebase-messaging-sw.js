// Empfängt Push-Nachrichten im Hintergrund (App geschlossen)
importScripts('https://www.gstatic.com/firebasejs/10.12.2/firebase-app-compat.js');
importScripts('https://www.gstatic.com/firebasejs/10.12.2/firebase-messaging-compat.js');

firebase.initializeApp({
  apiKey: 'AIzaSyAEUivDH4qAa07UQFHzJZVFTlFtovIdDNc',
  authDomain: 'ecker-s-family-app.firebaseapp.com',
  projectId: 'ecker-s-family-app',
  messagingSenderId: '607539029616',
  appId: '1:607539029616:web:407caafd1384e25d35b6b5'
});

const messaging = firebase.messaging();
messaging.onBackgroundMessage(payload => {
  const d = payload.data || {};
  return self.registration.showNotification(d.title || "Ecker's Family", {
    body: d.body || '',
    icon: 'icons/icon-192.png',
    badge: 'icons/icon-192.png',
    data: { url: d.url || './' }
  });
});

self.addEventListener('notificationclick', e => {
  e.notification.close();
  const url = new URL((e.notification.data && e.notification.data.url) || './', self.registration.scope).href;
  e.waitUntil(clients.matchAll({ type: 'window', includeUncontrolled: true }).then(list => {
    for (const c of list) if ('focus' in c) return c.focus();
    return clients.openWindow(url);
  }));
});
