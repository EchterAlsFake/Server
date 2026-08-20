# Regeln für Coding-Agents

Diese Datei gilt für das gesamte Repository. Für Änderungen am Vertretungsplan muss zusätzlich
`VPLAN_CONTEXT.md` vollständig gelesen und bei Architekturänderungen aktualisiert werden.

## Übersetzungen sind verpflichtend

- Jeder neue oder geänderte statische, für Nutzer sichtbare Text muss im selben Arbeitsschritt in
  das Übersetzungssystem aufgenommen werden. Dazu gehören auch Dialogtexte, Schaltflächen,
  Fehlermeldungen, Statusmeldungen, Platzhalter, Tooltips, Seitentitel sowie `aria-label`- und
  sonstige Accessibility-Texte.
- Beim Vertretungsplan wird der deutsche Ausgangstext in `static/i18n/de.json` angelegt und in HTML
  über `data-i18n` beziehungsweise passende `data-i18n-*`-Attribute oder in JavaScript über `t()`
  beziehungsweise `tp()` referenziert. Ein neuer Text darf nicht ausschließlich hart codiert
  werden.
- Alle freigeschalteten Sprachkataloge müssen dieselben Schlüssel und dieselben Platzhalter wie der
  deutsche Quellkatalog besitzen. Noch nicht menschlich geprüfte Übersetzungen bleiben als Beta
  beziehungsweise mit `reviewed: false` gekennzeichnet.
- Übersetzungswerte dürfen kein HTML enthalten und müssen als Text über `textContent` oder sichere
  Attribute eingesetzt werden. Daten aus dem offiziellen Vertretungsplan, persönliche Fachnamen
  und Lehrernamen werden nicht automatisch übersetzt.
- Übersetzungsänderungen benötigen Tests für Schlüsselkonsistenz und unveränderte Platzhalter.

## Datenschutzänderungen immer dokumentieren

- Jede Änderung, die Erhebung, Verarbeitung, Speicherung, Übertragung, Protokollierung, Löschung
  oder Weitergabe von Daten beeinflusst, muss gleichzeitig in den betroffenen Datenschutzhinweisen
  nachvollziehbar beschrieben werden. Das gilt auch für `localStorage`, Cookies, Logdaten,
  Datenbankfelder, externe Dienste, neue Endpunkte und geänderte Aufbewahrungsfristen.
- Beim Vertretungsplan sind mindestens der Datenschutzdialog in `templates/vplan.html` und dessen
  Sprachkataloge zu prüfen. Betrifft die Änderung die gesamte Webseite, müssen auch
  `templates/privacy_policy_de.html` und `templates/privacy_policy_en.html` geprüft und bei Bedarf
  gemeinsam aktualisiert werden.
- Datenschutzhinweise müssen der tatsächlichen Implementierung entsprechen. Es dürfen weder Daten
  verschwiegen noch technisch nicht garantierte Datenschutzversprechen gemacht werden.
- Es gilt Datenminimierung: Nur notwendige Daten speichern, klare Lösch- beziehungsweise
  Aufbewahrungsregeln festlegen und datenschutzrelevantes Verhalten mit Tests absichern.

## Datenbankzugriffe sicher implementieren

- Für Datenbankzugriffe SQLAlchemy ORM oder SQLAlchemy Core mit gebundenen Parametern verwenden.
  Nutzereingaben dürfen niemals durch Stringverkettung, f-Strings, `.format()` oder ähnliche
  Verfahren in SQL-Abfragen eingesetzt werden. Rohes SQL ist nur zulässig, wenn es unvermeidbar
  ist und sämtliche variablen Werte strikt parametrisiert sind.
- Eingaben müssen serverseitig validiert, normalisiert und in Länge sowie Datentyp begrenzt werden.
  Clientseitige Validierung allein ist keine Sicherheitsmaßnahme.
- Schreibende oder sensible Endpunkte benötigen passend zum Risiko Authentifizierung,
  Autorisierungsprüfung, CSRF-Schutz und Rate-Limiting. Fehler dürfen keine Interna, SQL-Abfragen,
  Zugangsdaten oder personenbezogenen Daten offenlegen.
- Datenbankänderungen müssen Mehrprozessbetrieb berücksichtigen. Tabellen- oder Schemaerstellung
  darf beim parallelen Start mehrerer Gunicorn-Worker keine Race Conditions auslösen; für
  Schemaänderungen sind kontrollierte Migrationen zu bevorzugen.
- Transaktionen müssen bei Fehlern sicher zurückgerollt werden. Geheimnisse gehören weder in die
  Datenbankausgabe noch in Logs oder das Repository.
- Für jedes neue Datenbankfeature sind Positivtests, ungültige Eingaben, unberechtigte Zugriffe und
  typische SQL-Injection-Zeichenfolgen zu testen.

## Nur modernes und sicheres HTML/JavaScript

- Standards-konformes, semantisches und zugängliches HTML verwenden. Veraltete oder obsolete
  Elemente und Attribute wie `<font>`, `<center>`, `<marquee>`, `<frameset>`, `bgcolor` oder
  präsentationsbezogene Tabellenlayouts sind verboten.
- Keine Inline-Eventhandler wie `onclick`, keine `javascript:`-URLs, kein `document.write`, kein
  `eval()` und keine dynamische Codeausführung über `new Function()` verwenden.
- Nicht vertrauenswürdige oder dynamische Daten niemals über `innerHTML`, `outerHTML` oder
  `insertAdjacentHTML` einsetzen. In JavaScript `textContent`, sichere DOM-Methoden und
  `setAttribute` für geprüfte Attribute verwenden. Jinja-Autoescaping darf nicht mit `|safe`
  umgangen werden, sofern der Inhalt nicht nachweislich statisch und vertrauenswürdig ist.
- Formulare benötigen zugeordnete Labels, Buttons einen expliziten `type`, Dialoge eine klare
  Beschriftung und interaktive Funktionen müssen per Tastatur bedienbar sein. Externe Links in
  neuen Tabs benötigen `rel="noopener noreferrer"`.
- Neue Browserfunktionen progressiv erweitern: Eine fehlende optionale API darf die grundlegende
  Seite nicht unbenutzbar machen.

## Abschlussprüfung

- Bestehende Nutzeränderungen im Worktree erhalten und keine fachfremden Dateien zurücksetzen.
- Änderungen proportional mit automatisierten Tests absichern. Für den Vertretungsplan mindestens
  die in `VPLAN_CONTEXT.md` dokumentierten Prüfkommandos ausführen.
- Vor Abschluss `git diff --check` ausführen und den Diff auf nicht übersetzte Texte,
  Datenschutzfolgen, unsichere Datenbankzugriffe und veraltete beziehungsweise unsichere
  HTML-Muster prüfen.
