# Login und Datenbank einrichten (Firebase)

Damit die App Anmeldung mit Passwort und gemeinsame Daten auf allen Geräten hat, brauchst du ein kostenloses Firebase-Projekt (Google-Konto nötig). Dauer: ca. 10 Minuten, am besten am Computer.

Solange nichts eingetragen ist, läuft die App wie bisher im lokalen Modus.

## 1. Projekt anlegen
1. Auf https://console.firebase.google.com anmelden.
2. **Projekt hinzufügen** → Name z. B. `ecker-family` → Google Analytics ausschalten → **Projekt erstellen**.

## 2. Anmeldung aktivieren
1. Links **Build → Authentication → Los geht's**.
2. Bei **Anmeldemethode** auf **E-Mail/Passwort** → aktivieren → **Speichern**.

## 3. Die vier Benutzer anlegen
Im Tab **Users** → **Nutzer hinzufügen**. Diese vier Adressen genau so eingeben (sie müssen nicht echt sein), und je ein eigenes Passwort wählen (mind. 6 Zeichen):

- `tristan@ecker-family.example`
- `claudia@ecker-family.example`
- `lina@ecker-family.example`
- `florian@ecker-family.example`

In der App tippt man nur auf die Kachel und gibt das Passwort ein.

Danach unter **Authentication → Settings → User actions** die Option **Enable create (sign-up)** ausschalten, damit sich niemand sonst registrieren kann.

## 4. Datenbank anlegen
1. Links **Build → Firestore Database → Datenbank erstellen**.
2. Standort: `europe-west6 (Zürich)`.
3. **Im Produktionsmodus starten** → **Erstellen**.

## 5. Regeln eintragen
1. In Firestore den Tab **Regeln** öffnen.
2. Alles löschen und den kompletten Inhalt der Datei `firestore.rules` aus diesem Repository einfügen.
3. **Veröffentlichen**.

Die Regeln sorgen dafür, dass nur die vier Familienmitglieder etwas lesen können, die Zeiterfassung nur für Claudia und Tristan zugänglich ist und die Feuerwehr-Einträge nur Tristan sieht.

## 6. App mit Firebase verbinden
1. Oben links auf das Zahnrad → **Projekteinstellungen**.
2. Unter **Allgemein** ganz unten bei **Meine Apps** auf das Web-Symbol `</>` klicken, Namen eingeben, **App registrieren**.
3. Aus dem angezeigten Code diese vier Werte kopieren: `apiKey`, `authDomain`, `projectId`, `appId`.
4. Auf GitHub die Datei `firebase-config.js` öffnen (Stift-Symbol) und die Werte zwischen die Anführungszeichen einfügen. **Commit changes**.

Nach 1–2 Minuten zeigt die Startseite die vier Kacheln mit Passwortabfrage.

## Alte Einträge übernehmen
Wer schon Zeiten im lokalen Modus erfasst hat, exportiert dort vorher mit **Backup exportieren** eine Datei. Nach der Anmeldung importiert jede Person ihr eigenes Backup unter **Datensicherung → Backup importieren**. Es werden nur Einträge des eigenen Kontos übernommen.

## Passwort vergessen
Die Adressen sind nicht echt, deshalb gibt es keine Reset-Mail. Bei einem vergessenen Passwort löschst du die Person in der Firebase-Konsole unter **Authentication → Users** und legst sie mit derselben Adresse und neuem Passwort wieder an. Ihre Einträge bleiben erhalten.
