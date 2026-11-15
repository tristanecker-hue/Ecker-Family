# Push-Mitteilungen einrichten (Cloudflare, gratis, ohne Kreditkarte)

1. Auf https://dash.cloudflare.com ein kostenloses Konto erstellen.
2. **Workers & Pages → Create → Hello World** → Name `ecker-push` → Deploy.
3. **Edit code**: alles löschen, Inhalt von `worker.js` einfügen → **Deploy**.
4. **Storage & Databases → KV → Create** → Name `ecker-push-kv`.
5. Worker `ecker-push` → **Settings → Bindings → Add → KV namespace** → Variablenname `KV` → Namespace `ecker-push-kv` → Deploy.
6. Die Worker-Adresse (`https://ecker-push.<name>.workers.dev`) im Browser mit `/vapid` am Ende öffnen: es muss `{"pub":"…"}` erscheinen.
7. Adresse in `index.html` bei `PUSH_URL` eintragen. Danach: Einstellungen → Mitteilungen → «Mitteilungen erlauben» (iPhone: App zuerst zum Home-Bildschirm hinzufügen).


## Erinnerungen (Cron-Trigger)
Nach dem Einfügen des neuen worker.js und «Deploy»: Worker → Settings → Trigger Events → Add → Cron Trigger → `*/5 * * * *` (alle 5 Minuten). Ohne diesen Trigger werden keine zeitgesteuerten Erinnerungen gesendet.
