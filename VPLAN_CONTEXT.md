# Vertretungsplan – Kontext für zukünftige AI-Modelle

> Stand: 20. August 2026. Dieses Dokument beschreibt ausschließlich den Vertretungsplan.
> Der restliche Inhalt dieses Repositories ist für VPlan-Aufgaben grundsätzlich außerhalb
> des Scopes. Vor Änderungen trotzdem immer den aktuellen Code und `git status` prüfen.

## 1. Ziel und Produktverständnis

Der Vertretungsplan ist ein privates, inoffizielles Schülerprojekt. Er stellt den offiziellen
Plan lesbarer dar, ersetzt ihn aber ausdrücklich nicht. Die Oberfläche soll auf Smartphones
besonders einfach funktionieren, ohne Nutzerkonto auskommen und so wenig Daten wie möglich
an den Server übertragen.

Wichtige Produktprinzipien:

- Mobile-first, ruhig, intuitiv und barrierearm gestalten.
- Der offizielle Plan bleibt die verbindliche Quelle.
- Persönliche Klasse, Kurse, eigene Fachnamen und Lehrernamen bleiben im Browser.
- Niemals ungefragt VPlan-Inhalte oder lokale Einstellungen an externe Dienste senden.
- Die VPlan-Subdomain darf keine fachfremden Serverfunktionen offenlegen.
- Originale Lehrerkürzel und ausgeschriebene Namen des Quellsystems werden vor Speicherung
  und Ausgabe redigiert.

## 2. Relevante Dateien

| Datei | Aufgabe |
| --- | --- |
| `main.py` | Flask-Routen, Host-Isolation, PWA-Auslieferung, Feedback-Validierung und Datenbankmodell |
| `vplan_sync.py` | Abruf, Validierung, Lehrerredaktion, schuljahresweises Lernen und atomare Planaktualisierung |
| `templates/vplan.html` | Gesamte Jinja-/HTML-Oberfläche einschließlich Dialogen, Sprachwahl und Credits |
| `templates/vplan_translate.html` | Lokaler, serverseitig schreibfreier Übersetzungseditor |
| `templates/vplan_legal.html` | Isolierte VPlan-Datenschutz- und Impressumsseiten |
| `static/vplan.css` | Ausschließliches Styling der VPlan-Oberfläche |
| `static/vplan.js` | i18n, Tabs, Filter, Personalisierung, Fachnamen, Dialoge, Feedback und PWA-Installation |
| `static/vplan-theme.js` | Frühe Theme-Auswahl ohne Inline-Skript |
| `static/vplan-pwa.js` | Frühe Installationsereignisse und Service-Worker-Registrierung |
| `static/i18n/*.json` | Deutscher Quellkatalog, freigegebene Sprachen und Metadaten |
| `static/vplan-translate.*` | Logik und Styling des lokalen Übersetzungseditors |
| `static/manifest.webmanifest` | PWA-Metadaten |
| `static/vplan-sw.js` | Service Worker für lokale App-Ressourcen |
| `static/vplan-icon*` | Normale und maskierbare PWA-Icons |
| `tests/test_vplan_app.py` | Flask-, UI-Vertrags-, Datenschutz- und PWA-Tests |
| `tests/test_vplan_sync.py` | Parser-, Redaktions- und Synchronisationstests |
| `README.md` | Kurze Betriebs- und Proxy-Dokumentation |
| `vplan.json.sync-state.json` | Private Laufzeitdatei mit Sync-Metadaten sowie gelernten Lehrer- und Kurskennungen; niemals committen |

`main.py` enthält viele andere Anwendungen. Bei einer VPlan-Aufgabe nur die ausdrücklich
zugehörigen Konstanten, Modelle, Hooks und Routen verändern. Keine anderen Endpunkte im Zuge
einer VPlan-Änderung „aufräumen“.

## 3. Datenfluss

```text
Offizielle HTML-Seite
        │
        ▼
vplan_sync.py: herunterladen → eingebettetes JSON prüfen → sichere Lehrerkontexte erkennen
        │                                      │
        │                                      └── Lehrer- und Kurskennungen lernen
        │                                                   │
        ▼                                                   ▼
Lehrerkennungen redigieren → Hash bilden        private Sync-Statusdatei
        ▲
        └── private Namensliste aus SQLite (zusätzliche Redaktionsschicht)
        │
        ▼
lokale vplan.json (bereinigt und atomar ersetzt, nur bei geänderten Inhalten)
        │
        ▼
main.py: erneut defensiv redigieren → /vplan → Template, JavaScript und CSS
        │
        ├── persönliche Einstellungen → ausschließlich localStorage
        └── freiwillige Fehlermeldung → POST /vplan/feedback → SQLite
```

Die Synchronisation prüft standardmäßig alle 120 Sekunden die vollständige Quellseite. Ein
kanonischer SHA-256-Hash aus Quellenzeitpunkt und bereits bereinigten Tagen verhindert unnötige
Neuschreibungen. Fehlerhafte oder unvollständige Downloads dürfen den letzten gültigen Plan nie
überschreiben. Eine noch nicht vorhandene Plan- oder Statusdatei ist ein unterstützter
Erststartfall. Dateiänderungen erfolgen atomar; Thread- und Dateisperren verhindern
konkurrierende Updates.

### Serverseitiges Lernen und Lehrerredaktion

Der private Sync-Status enthält unter `vplan_learning`:

- `school_year`, zum Beispiel `2026-2027`;
- `teacher_codes`, ausschließlich serverseitig verwendete bekannte Lehrerkennungen;
- `course_codes`, alle im laufenden Schuljahr beobachteten Klassen-/Kurskennungen.

Das Schuljahr läuft für diese Funktion vom 1. August bis 31. Juli. Beim ersten Lauf in einem
neuen Schuljahr werden die erlernten Werte automatisch verworfen. Manuelle Lehrer-Startwerte
aus `VPLAN_TEACHER_CODE_SEEDS` werden danach wieder ergänzt. Startwerte gehören nur in die
lokale `.env`; echte Kürzel niemals als Konstanten, Tests oder Dokumentationsbeispiele in Git
ablegen.

Lehrerkennungen werden nur aus stark strukturierten Kontexten gelernt, derzeit insbesondere:

- explizite Quellkennungen wie `LiGyDe.<Kürzel>`;
- die standardisierte Formulierung `Aufgaben von <Kürzel>`;
- Paare nach dem Muster `<Kürzel> und <Kürzel> in <Raum>`.

Die zuletzt genannte Heuristik ist bewusst eng: Sie verlangt zwei dreibuchstabige,
namensähnliche Tokens und danach einen plausiblen Raum. Nicht beliebige großgeschriebene Wörter
als Lehrerkürzel lernen, da ein Fehlfund anschließend legitimen Hinweistext verfälschen würde.
Bekannte Kennungen werden rekursiv in allen Quellstrings ersetzt; mehrere Lehrkräfte werden als
`Lehrkräfte` dargestellt. Neu gefundene Kennungen werden vor Hashbildung und Speicherung aus
dem Plan entfernt.

Ausgeschriebene Namen mit Anrede (`Frau`/`Herr`, optional `Dr.`) werden unabhängig von der
Lernliste bereits beim Parsen erkannt und durch `Lehrkraft` ersetzt. Damit schützt auch der erste
Abruf eine noch unbekannte Lehrkraft. Als zweite Schicht enthält die private SQLite-Tabelle
`vplan_teacher_names` die administrativ importierte Namensliste. Sie wird weder an Templates noch
an JavaScript ausgeliefert. Ein Import aus einer lokal gespeicherten, kopierten Personaltabelle
erfolgt mit:

```bash
uv run flask --app main import-vplan-teachers private-personalliste.txt
```

Der Import liest ausschließlich Einträge der ersten Spalte in der Form `Frau/Herr Nachname`,
entfernt Zusätze in Klammern, dedupliziert und bereinigt außerdem einen vorhandenen Plan-Cache
atomar. Die Quelldatei und echte Namen niemals committen. Die gesamte private Namensliste kann
bei Bedarf mit `uv run flask --app main clear-vplan-teachers` nach Bestätigung gelöscht werden.

Der Export ist zeilenbasiert und dadurch direkt wieder importierbar. Ohne Ziel schreibt er nur
die Namen nach stdout; mit Ziel erstellt er eine neue Datei mit Berechtigung `0600`. Vorhandene
Dateien werden nicht überschrieben:

```bash
uv run flask --app main export-vplan-teachers
uv run flask --app main export-vplan-teachers vplan-teachers-export.txt
```

Exportdateien sind private Laufzeitdaten und werden durch `.gitignore` abgedeckt.

Kurskennungen werden aus `KLASSE` gültiger Planeinträge gesammelt. Sie bleiben bis zum
Schuljahreswechsel verfügbar, selbst wenn sie im aktuellen Plan nicht vorkommen. Das Frontend
erhält nur diese Kurskennungen für die Auswahl, niemals die serverseitige Lehrerliste. Das Lernen
kennt keine individuellen Kurswahlen und speichert keine Zuordnung zwischen Schülern und Kursen.

## 4. Planformat

Der lokale Plan ist ein JSON-Objekt mit mindestens einer Liste `tage`:

```json
{
  "meta": {
    "stand": "2026-08-19 06:00:00",
    "schoolId": 123,
    "synced_at": "ISO-8601",
    "content_sha256": "..."
  },
  "tage": [
    {
      "DATUM": "Mittwoch, 19. August 2026",
      "WICHTIGE_HINWEISE": [],
      "WEITERE_HINWEISE": [],
      "EINTRAEGE_KLASSEN": [
        {
          "STUNDE": "08:35 - 09:20",
          "NEU": "Ausfall: Mathematik",
          "BEMERKUNGEN": "",
          "KLASSE": "7a"
        }
      ]
    }
  ]
}
```

Das Template behandelt einen Eintrag als Ausfall, wenn `NEU` das Wort `ausfall` enthält.
Alle von der Quelle kommenden sichtbaren Werte werden mit Jinja `striptags` behandelt. Die
primäre Lehrerredaktion erfolgt bereits beim Parsen vor Hash und lokaler Speicherung. `main.py`
wendet vor jedem Rendern zusätzlich die aktuelle Lernliste, die private Namensliste und neu im
vorhandenen Cache erkennbare Kontexte rekursiv an. Dadurch werden auch ältere, noch unbereinigte
lokale
Plandateien defensiv geschützt. Der Jinja-Filter `redact_teacher_codes` bleibt eine weitere
Ausgabesicherung für explizite `LiGyDe.*`-Kennungen und Namen mit Anrede.

## 5. HTTP-Routen und Host-Isolation

- `GET /vplan`: Rendert den aktuellen Plan ohne Anmeldung und mit `Cache-Control: no-store`.
- `GET /` auf dem konfigurierten VPlan-Host: Rendert direkt dieselbe VPlan-Ansicht.
- `GET /sw.js`: Liefert den Service Worker für den begrenzten Scope `/vplan` aus.
- `GET /manifest.webmanifest`: Liefert das aktuelle Manifest ausdrücklich ohne Cache aus.
- `GET /vplan/privacy` und `GET /vplan/imprint`: VPlan-spezifische Rechtstexte ohne Inhalte anderer Projekte.
- `POST /vplan/feedback`: Nimmt eine freiwillige Klartext-Fehlermeldung an.
- Auf dem VPlan-Host sind ansonsten nur die benötigten VPlan-Assets und lokalen Sprachkataloge
  erreichbar. Generische Rechtstexte, fachfremde statische Dateien, andere Routen und andere
  POST-Anfragen liefern 404.

Der öffentliche Host ist standardmäßig `vplan.echteralsfake.me` und kann über
`VPLAN_PUBLIC_HOST` geändert werden. `StripVisitorIPHeaders` entfernt bekannte weitergeleitete
Besucher-IP-Header, bevor Flask und Flask-Limiter sie sehen. `ProxyFix` vertraut Host und
Schema des vorgeschalteten Proxys, ausdrücklich aber keiner weitergeleiteten Besucher-IP.
VPlan-Anfragen werden nicht in die projektweiten Gesamtstatistiken aufgenommen. VPlan-Antworten
erhalten eine eigene Content-Security-Policy ohne externe Skriptquellen und ohne Inline-JavaScript.

## 6. Oberfläche

Die Seite besitzt aktuell:

- eine dezente obere Leiste mit „Verantwortlicher“, „Datenschutz“, „Credits“ und „Änderungen“;
- einen App-Header mit Aktualisierungszeit und Hell-/Dunkelmodus;
- Tastatur-bedienbare Tag-Tabs mit automatischer Auswahl des passenden Plantags;
- drei immer sichtbare Schnellaktionen in einer Reihe:
  1. „Mein Plan“,
  2. „App installieren“,
  3. „Fehler melden“;
- Hinweise, Suche und Filter „Alle“/„Nur Ausfälle“;
- optionale persönliche Filter nach Jahrgang, Klasse und Kursen;
- eine Auswahl ausschließlich für die tatsächlich vorhandenen Parallelklassen A bis C;
- eine Kursauswahl aus aktuellem Plan plus der im laufenden Schuljahr erlernten Historie;
- Bearbeitung jedes Eintrags über optionalen Namen, Lehrkraft und eine Material-ähnliche Akzentfarbe;
- lokale Sprachwahl sowie einen Link zum browserbasierten Übersetzungseditor;
- Informationsdialoge, Installationshilfe, Feedbackdialog und einmaligen Nutzungshinweis;
- Credits mit Stack und bisherigen Danksagungen.

Der Dialog „Änderungsprotokoll“ enthält eine kurze, nutzerfreundliche Zusammenfassung relevanter
VPlan-Commits, gruppiert nach Datum. Die Einträge werden nicht zur Laufzeit aus `.git` geladen,
sondern nach Prüfung mit `git log` und `git show` bewusst im Template gepflegt. So funktioniert
die Ansicht auch in Deployments ohne Git-Metadaten und veröffentlicht keine internen Committexte.

Die Schnellaktionen bleiben auch bei leerem oder vorübergehend nicht verfügbarem Plan sichtbar.
Dialoge verwenden das native `<dialog>`-Element. Neue Interaktionen sollen die vorhandenen
`data-*`-Hooks fortführen und sichtbaren dynamischen Text grundsätzlich mit `textContent`,
nicht mit `innerHTML`, einsetzen.

Jeder Tag-Tab erhält serverseitig ein aus dem deutschen Quelldatum normalisiertes ISO-Datum in
`data-day-date`. Beim Seitenaufruf vergleicht der Browser diese Werte mit seinem lokalen Datum:
Vor 15 Uhr wird der heutige Plantag bevorzugt, ab 15 Uhr der nächste vorhandene zukünftige Tag.
Fehlt dieser, bleibt der heutige Tag aktiv; fehlt auch der heutige Tag, wird der nächste künftige
beziehungsweise zuletzt vergangene Tag verwendet. Diese Auswahl wird nicht gespeichert und
überschreibt keine anschließende manuelle Tab-Auswahl.

## 7. Browser-Speicherung

Es gibt keine Nutzerkonten. Diese Schlüssel liegen ausschließlich im `localStorage` des
jeweiligen Origins:

| Schlüssel | Inhalt |
| --- | --- |
| `vplan-theme` | `light` oder `dark` |
| `vplan-language` | freigegebener Sprachcode, derzeit `de` oder `en` |
| `vplan-preferences` | `{ enabled, grade, classLetter, courses }` |
| `vplan-subject-overrides` | Objekt aus stabilem Fachschlüssel und `{ name, teacher, color }` |
| `vplan-disclaimer-accepted-v1` | `"true"`, nachdem der Nutzungshinweis bestätigt wurde |

Alle interaktiven Zugriffe laufen über `safeStorage`, damit
die Seite auch bei gesperrtem oder vollem Browser-Speicher weiter bedienbar bleibt. Daten auf
`localhost` und auf der öffentlichen Domain sind wegen der Origin-Trennung nicht identisch.
Das frühe Theme-Lesen liegt in einer kleinen externen Datei und fängt Speicherfehler separat ab.
Schlägt ein schreibender Zugriff fehl, weist die Oberfläche darauf hin, dass die Änderung nicht
dauerhaft gespeichert wurde.

Ohne gespeicherte Auswahl startet die VPlan-Oberfläche im Dunkelmodus. Ein gültiger Wert aus
`vplan-theme` wird bereits im `<head>` vor dem Laden des Stylesheets angewandt. Der Theme-Schalter
wird vor den asynchron geladenen Sprachkatalogen aktiviert, speichert `dark` oder `light` und liest
den Wert zur Kontrolle unmittelbar wieder aus. So bleibt die Auswahl bei späteren Aufrufen
erhalten und der Schalter funktioniert auch bei langsamen oder vorübergehend nicht verfügbaren
Übersetzungsdateien.

Die serverseitig erlernte Liste verfügbarer Kurskennungen ist davon getrennt: Sie enthält nur
das Kursangebot aus den Quelldaten. Die konkrete Auswahl eines Kindes bleibt ausschließlich im
jeweiligen Browser in `vplan-preferences`.

### Fach- und Lehrernamen

Die Schlüsselbildung ist absichtlich differenziert:

- Eindeutige Kurskennung, zum Beispiel `12_mat1`: normalisierte Kurskennung als Schlüssel.
- Basisklasse, zum Beispiel `7a`: `7a::<erkanntes-fach>`, beispielsweise `7a::eng` oder
  `7a::ges`.

Diese Trennung ist kritisch. Ein Lehrer für Englisch in `7a` darf niemals bei Geschichte in
`7a` erscheinen. Bei Basisklassen wird das Fach deshalb aus `NEU` erkannt; bekannte Fächer
stehen in der `subjects`-Liste in `static/vplan.js`. Für unbekannte Beschreibungen wird ein
normalisierter Fallback aus dem Beschreibungstext gebildet.

Eigene Textwerte sind auf 60 Zeichen begrenzt. Name, Lehrkraft und Farbe können unabhängig
voneinander gesetzt werden. Erlaubte Farbwerte sind ausschließlich die festen IDs `violet`,
`blue`, `cyan`, `green`, `lime`, `amber`, `orange` und `pink`; unbekannte gespeicherte Werte
werden ignoriert. Die Palette verwendet bewusst leuchtende, kontrastreiche Farben. Im Dark Mode
werden Kontur, obere Akzentkante, Badge und ein leichter Glow verstärkt, während der rote
Ausfallstatus semantisch unverändert bleibt. Alle Anpassungen verändern nur die Anzeige und die lokale Suche,
nicht die Quelldatei. Einträge mit einer nicht leeren Klassen-/Kurskennung sind bearbeitbar.

## 8. Installierbare Web-App (PWA)

Die PWA ist auf dem öffentlichen VPlan-Host sowie auf `localhost`, `127.0.0.1` und `::1`
aktiviert. Loopback-Adressen gelten in modernen Browsern als geeigneter lokaler Testkontext;
eine beliebige LAN-IP über unverschlüsseltes HTTP ist dagegen normalerweise nicht installierbar.

Das Manifest startet unter `/vplan?source=pwa` im Modus `standalone`. Wenn der Browser ein
`beforeinstallprompt` bereitstellt, verwendet der Installationsbutton diesen. Andernfalls zeigt
die Seite verständliche manuelle Installationsschritte, einschließlich iOS/Safari.

Manifest und Service Worker werden cache-frei ausgeliefert. Der Worker ist auf `/vplan` begrenzt,
hält Plan-Navigationen immer netzwerkaktuell und speichert nur eine feste Liste von App-Ressourcen
zwischen. Fachfremde `/static/`-Dateien und das Manifest werden nicht in den App-Cache aufgenommen.
Der eigentliche Plan ist bewusst kein Offline-Snapshot. Installationsereignisse und
Worker-Registrierung werden vor den asynchronen Übersetzungen eingerichtet. Bei relevanten
Cache-Strategieänderungen `CACHE_NAME` erhöhen.

## 9. Fehlermeldungen

Das Formular enthält genau ein Textfeld mit 10 bis 1500 Zeichen und eine verpflichtende
Bestätigung, dass keine personenbezogenen Informationen enthalten sind. Der Browser und der
Server weisen erkennbare E-Mail-Adressen, URLs, Telefonnummern und HTML zurück. Beliebige Namen
lassen sich technisch nicht zuverlässig automatisch erkennen; deshalb sind der deutliche
Hinweis und die Bestätigung Teil des Sicherheitskonzepts und dürfen nicht entfernt werden.

Der Request ist JSON:

```json
{
  "message": "Beschreibung des Fehlers",
  "privacy_confirmed": true
}
```

Zusätzlich ist `X-VPlan-Request: feedback` erforderlich. Der Browser verwendet
`credentials: "omit"` und `referrerPolicy: "no-referrer"`. Der Endpunkt ist bewusst von der
sessionbasierten CSRF-Prüfung ausgenommen, akzeptiert aber nur JSON mit dem eigenen Header und
verwendet einen anonymen, datenbankgestützten Gesamtzähler pro Minute. Das Limit gilt dadurch
über alle Gunicorn-Worker hinweg, speichert keine Besucherkennung und wird innerhalb eines Tages
entfernt.

SQLite-Modell und Tabelle heißen `VPlanFeedback` beziehungsweise `vplan_feedback`. Gespeichert
werden ausschließlich:

- `id`,
- `message`,
- `created_at` als UTC-ISO-Zeitpunkt.

Es werden keine Klasse, lokalen Einstellungen, Browserkennung oder Besucher-IP an den Datensatz
angehängt. Ein eigener Hintergrund-Worker bereinigt Meldungen älter als 180 Tage stündlich;
zusätzlich erfolgt die Bereinigung beim ersten VPlan-Aufruf und beim Eingang einer
neuen Meldung. Fehlerantworten verwenden sprachneutrale Codes, die der
Browser lokal übersetzt. Für Fehlerantworten und Erfolge gilt `Cache-Control: no-store`. Es
existiert aktuell keine öffentliche Ansicht zum Lesen der Meldungen; sie liegen in der lokalen
`server.db`.

## 10. Nutzungshinweis und Datenschutz

Beim ersten Aufruf erscheint ein nicht wegklickbarer Hinweis, dass die Seite inoffiziell und
ohne Gewähr ist. Erst nach Aktivieren der Checkbox kann er bestätigt werden. Die Bestätigung
wird in `vplan-disclaimer-accepted-v1` gespeichert und bei späteren Aufrufen desselben Origins
nicht erneut abgefragt.

Die Datenschutzaussagen in der Oberfläche müssen bei neuen Serverfunktionen aktualisiert werden.
Cloudflare sieht für Bereitstellung und Schutz technisch bedingt Verbindungsdaten; der private
Ursprungsserver soll keine Besucher-IP protokollieren. Gunicorn-Zugriffslogs müssen deaktiviert
bleiben oder ein Format ohne Remote-Adresse, Query-String und sensible Header verwenden.

## 11. Credits

Die Credits-Ansicht enthält aktuell:

- Stack: Python, HTML, CSS, JavaScript und Flask;
- Programmierung: Codex 5.6 SOL (high);
- Hosting: Cloudflare und Google Pixel 7 Pro;
- IDE: PyCharm;
- Code: GitHub;
- Umbenennung der Fächer/Lehrer: Anonym;
- Installation der App: Richard Lewerenz.

Die Liste soll unkompliziert erweiterbar bleiben. Bestehende Nennungen nicht ohne ausdrücklichen
Auftrag entfernen oder umformulieren.

## 12. Übersetzungen

Die statische Oberfläche verwendet stabile Schlüssel aus `static/i18n/de.json`. Deutsch ist der
vollständige Quell- und Fallbackkatalog; `en.json` ist die erste, als Beta und noch nicht
menschlich geprüft gekennzeichnete Übersetzung. `languages.json` ist die einzige Liste der in der
Planansicht angebotenen Sprachen. Dort werden Sprachcode, Eigenname, Prüfstatus und die im Header
angezeigte Flagge gepflegt. Ein neuer Katalog allein schaltet deshalb keine Sprache frei.

`static/vplan.js` lädt ausschließlich Dateien vom eigenen Origin, validiert Katalogwerte als
Strings und setzt Texte beziehungsweise Attribute über `textContent` und `setAttribute`, niemals
über `innerHTML`. Fehlende oder leere Werte fallen einzeln auf Deutsch zurück. Platzhalter wie
`{count}` werden ohne HTML-Interpretation eingesetzt. Die zugänglichen Flaggen-Schaltflächen im
Kopfbereich werden aus `languages.json` aufgebaut. Die Sprachwahl liegt unter `vplan-language` im
`localStorage`; `html[lang]`, der aktive Zustand der Schaltflächen und sichtbare Community-Hinweise
werden passend aktualisiert.

`GET /vplan/translate` bietet einen auch auf der VPlan-Subdomain erlaubten Editor. Er liest
Quell- und Zielkataloge, kann lokale JSON-Dateien importieren und erzeugt den Download per
`Blob` vollständig im Browser. Es gibt keinen Upload- oder Speicherendpunkt. Der Editor prüft
Sprachcode, HTML-Fragmente und unveränderte Platzhalter; unvollständige Kataloge sind zulässig
und verwenden zur Laufzeit den deutschen Fallback.
Auch die statischen und dynamischen Texte des Editors selbst stammen aus denselben Katalogen.

Nicht übersetzt werden Daten des offiziellen Plans, darunter Datumstexte der Quelle,
Bemerkungen, Hinweise, Klassen-/Kurskennungen und selbst eingetragene Fach- oder Lehrernamen.
Diese Trennung verhindert, dass eine Community-Übersetzung den Inhalt eines verbindlichen
Schulhinweises verändert. Das statische Manifest bleibt vorerst deutsch; die sichtbare Webseite
und ihre zugänglichen Beschriftungen folgen der Browserauswahl.

Neue sichtbare Texte immer zuerst in `de.json` aufnehmen und mit `data-i18n` beziehungsweise
`t()` referenzieren. Jeder veröffentlichte Katalog muss dieselben Schlüssel und Platzhalter wie
Deutsch besitzen. AI- oder Community-Übersetzungen bleiben bis zur menschlichen Prüfung als
`reviewed: false` gekennzeichnet. Beim manuellen Freischalten einer weiteren Sprache müssen der
Katalog, der Eintrag mit `code`, `name`, `status` und `flag` in `languages.json` sowie der Eintrag im
App-Shell-Cache gemeinsam ergänzt werden.

## 13. Konfiguration

Relevante Umgebungsvariablen:

- `VPLAN_SCHOOL_ID` – erforderlich;
- `VPLAN_SYNC_ENABLED` – automatische Synchronisation, standardmäßig aktiv;
- `VPLAN_JSON_PATH` – Pfad zur lokalen Plandatei;
- `VPLAN_SYNC_STATE_PATH` – optionaler Statuspfad;
- `VPLAN_SYNC_LOCK_PATH` – optionaler Lock-Pfad;
- `VPLAN_SOURCE_URL` – optionale alternative Quelle;
- `VPLAN_TEACHER_CODE_SEEDS` – optionale, kommaseparierte Lehrer-Startwerte aus der lokalen
  `.env`; niemals in Git übernehmen;
- `VPLAN_CHECK_INTERVAL_SECONDS` – Standard 120, Minimum 60;
- `VPLAN_REQUEST_TIMEOUT_SECONDS` – Standard 20;
- `VPLAN_MAX_RESPONSE_BYTES` – Größenlimit der Quelle;
- `VPLAN_PUBLIC_HOST` – Standard `vplan.echteralsfake.me`;
- `PF_SERVER_DB` – Pfad zur SQLite-Datenbank einschließlich Feedbacktabelle.

Die SQLite-Datenbank enthält zusätzlich die private Tabelle `vplan_teacher_names`. Ein
prozessübergreifender Schema-Lock serialisiert `db.create_all()` beim parallelen Start mehrerer
Gunicorn-Worker und verhindert konkurrierende Tabellenerstellung.

Die Plandatei, Sync-Statusdatei, Sperrdatei und SQLite-Datenbank sind Laufzeitdaten und gehören
nicht in Git. Die Sync-Statusdatei ist nicht nur ein Zeitstempel-Cache: Das Löschen setzt auch
die automatisch gelernten Lehrer- und Kurskennungen zurück. Bei einem Umzug oder Deployment die
lokale `.env` bewusst übernehmen, da die darin gesetzten Startwerte nicht aus dem Repository
kommen.

## 14. Entwicklung und Prüfungen

Lokaler Start aus dem Repository-Root:

```bash
VPLAN_SCHOOL_ID=<id> python main.py
```

Danach ist die Testansicht unter `http://localhost:8000/vplan` erreichbar. Für Entwicklung ohne
Quellabrufe zusätzlich `VPLAN_SYNC_ENABLED=false` setzen und eine gültige `vplan.json` verwenden.

Vor Übergabe einer VPlan-Änderung mindestens ausführen:

```bash
python -m unittest discover -s tests
python -m py_compile main.py vplan_sync.py tests/test_vplan_app.py tests/test_vplan_sync.py
node --check static/vplan.js
node --check static/vplan-translate.js
git diff --check
```

Wichtige Testverträge:

- Subdomain-Root rendert nur den VPlan und gibt fachfremde Routen nicht frei.
- Fehlende oder ungültige Plandatei liefert 503, ohne einen gültigen Cache zu zerstören.
- Lehrerkürzel werden in expliziten, standardisierten und eng strukturierten Kontexten gelernt;
  ausgeschriebene Namen mit Anrede werden allgemein erkannt. Beides wird vor Speicherung sowie
  erneut vor Ausgabe redigiert.
- Lernwerte sammeln sich innerhalb eines Schuljahres an und werden zum 1. August zurückgesetzt.
- Früher beobachtete Kurse bleiben in der persönlichen Auswahl, auch wenn sie im aktuellen Plan
  fehlen; Lehrerkennungen gelangen dabei nicht ins HTML.
- Fachschlüssel unterscheiden bei Basisklassen zwischen einzelnen Fächern.
- Nutzungshinweis wird lokal gemerkt.
- PWA funktioniert auf öffentlichem Host und lokalen Loopback-Hosts.
- Feedback speichert nur Nachricht und Zeitpunkt und lehnt erkennbare Kontaktdaten ab.
- Sprachkataloge besitzen identische Schlüssel und Platzhalter; der Editor sendet keine Daten
  an den Server und Planinhalte werden nicht übersetzt.

## 15. Regeln für zukünftige Änderungen

1. Zuerst `VPLAN_CONTEXT.md`, `git status` und die tatsächlich betroffenen Dateien lesen.
2. Bestehende Nutzeränderungen im Worktree erhalten; keine fachfremden Dateien zurücksetzen.
3. Daten der Quelle als nicht vertrauenswürdig behandeln: serverseitig bereinigen und im DOM nie
   unsicher als HTML einsetzen.
4. Lehrerkennungen vor Hashbildung und Speicherung entfernen. Neue Erkennungsheuristiken nur mit
   eindeutigem Kontext und Tests ergänzen; keine pauschale Dreizeichen-Ersetzung einführen.
5. Keine neue Server-Speicherung einführen, ohne Datenmodell, Datenschutzhinweis, Löschlogik und
   Tests gemeinsam zu aktualisieren.
6. Personalisierung standardmäßig lokal halten und stabile, fachgenaue Schlüssel verwenden.
7. Plan-Navigationen nicht offline cachen; Aktualität ist wichtiger als ein veralteter Offlineplan.
8. Mobile Breiten, Tastaturbedienung, Dark Mode, Dialog-Fokus und leere/fehlerhafte Pläne prüfen.
9. Neue sichtbare UI-Texte im deutschen Quellkatalog ergänzen und über `data-i18n` oder `t()`
   anbinden; keine Sprachdatei darf HTML enthalten.
10. Die Tests proportional zur Änderung ergänzen und die vollständige Suite ausführen.
11. Diese Datei aktualisieren, wenn sich Architektur, Speicherung, Routen oder zentrale
    Produktentscheidungen des Vertretungsplans ändern.
12. Bei einer sichtbaren VPlan-Veröffentlichung den Änderungsdialog anhand des tatsächlichen
    Git-Diffs ergänzen; technische Details knapp und aus Nutzersicht formulieren.
