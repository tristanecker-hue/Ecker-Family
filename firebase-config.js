// Einstellungen für Ecker's Family
//
// 1) FIREBASE_CONFIG: Hier trägst du die Werte aus deinem Firebase-Projekt ein
//    (Anleitung: FIREBASE-ANLEITUNG.md). Solange apiKey leer ist, läuft die App
//    im lokalen Modus ohne Login (Daten nur auf dem jeweiligen Gerät).
//    Diese Werte sind keine Geheimnisse – der Schutz kommt von den Datenbankregeln.
window.FIREBASE_CONFIG = {
  apiKey: "AIzaSyAEUivDH4qAa07UQFHzJZVFTlFtovIdDNc",
  authDomain: "ecker-s-family-app.firebaseapp.com",
  projectId: "ecker-s-family-app",
  messagingSenderId: "607539029616",
  appId: "1:607539029616:web:407caafd1384e25d35b6b5"
};

// 2) Benutzer. Der Schlüssel (links) ist der Benutzername im Firebase-Konto,
//    der Wert (rechts) der angezeigte Name. Die Anmelde-Adresse lautet
//    <benutzername>@<emailDomain>, z. B. tristan@ecker.ch
window.APP_CONFIG = {
  emailDomain: "ecker.ch",
  accounts: {
    tristan: "Tristan",
    claudia: "Claudia",
    lina: "Lina",
    florian: "Florian"
  },
  // Nur diese Personen haben die Zeiterfassung
  timeUsers: ["Tristan", "Claudia"]
};
