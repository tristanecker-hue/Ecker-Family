// Einstellungen für Ecker's Family
//
// 1) FIREBASE_CONFIG: Hier trägst du die Werte aus deinem Firebase-Projekt ein
//    (Anleitung: FIREBASE-ANLEITUNG.md). Solange apiKey leer ist, läuft die App
//    im lokalen Modus ohne Login (Daten nur auf dem jeweiligen Gerät).
//    Diese Werte sind keine Geheimnisse – der Schutz kommt von den Datenbankregeln.
window.FIREBASE_CONFIG = {
  apiKey: "",
  authDomain: "",
  projectId: "",
  appId: ""
};

// 2) Benutzer. Der Schlüssel (links) ist der Benutzername im Firebase-Konto,
//    der Wert (rechts) der angezeigte Name. Die Anmelde-Adresse lautet
//    <benutzername>@<emailDomain>, z. B. tristan@ecker-family.example
window.APP_CONFIG = {
  emailDomain: "ecker-family.example",
  accounts: {
    tristan: "Tristan",
    claudia: "Claudia",
    lina: "Lina",
    florian: "Florian"
  },
  // Nur diese Personen haben die Zeiterfassung
  timeUsers: ["Tristan", "Claudia"]
};
