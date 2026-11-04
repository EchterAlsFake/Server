# Rechtlicher Abgleich von Website, App und Server

Stand: 31.10.2026. Geprüft wurden die lokalen Arbeitsstände in `Server` und `Porn_Fetch`, insbesondere Datenschutztexte DE/EN, AGB DE/EN, Erstattungsrichtlinie, Checkout, Lizenzierung, Diagnoseberichte und relevante Deployment-Dateien. Vorhandene fremde Änderungen bleiben erhalten. Keine Produktionskonfiguration, privaten Postfächer, Kundendaten oder tatsächlichen Provider-Checkouts geprüft; kein Deployment vorgenommen. Die rechtlichen Bewertungen sind eine technische Vorprüfung, keine verbindliche Einzelfallentscheidung.

## Umgesetzte Korrekturen

- Aktuelle Kontaktadressen in Website-Templates, Dokumentationsquellen und ausgelieferter Dokumentation sowie App-Kontakthinweisen, CONTRIBUTING und Paketmetadaten auf `support@echteralsfake.me` vereinheitlicht. Fremdanbieter-Adressen bleiben erhalten. Die historische Signaturidentität in `Porn_Fetch/docs/ANTIVIRUS_FLAGS.md` ist keine Kontaktadresse und bleibt zur Schlüsselprüfung erhalten.
- Datenschutz DE/EN: optionale Fehlerberichte, Einwilligung/Widerruf, tatsächlich manuelle Löschung, lokale App-Verarbeitung, Update-/Providerverbindungen und Proton Mail ergänzt. Die App-Einwilligungsinformation wurde ebenfalls korrigiert; die nicht existierende automatische 30-Tage-Löschung wird nicht mehr versprochen.
- Nach Betreiberbestätigung: TLS-Ende im Heimnetz, Privex-Weiterleitung und Vodafone-Sicht auf die Tunnelgegenstelle präzisiert. Proton AG als E-Mail-Dienst für Lizenzierung und Support benannt.
- Aufsichtsbehörde: veraltete Leiterstraße durch Otto-von-Guericke-Straße 34a ersetzt. [Aktuelle Behördenanschrift](https://datenschutz.sachsen-anhalt.de/landesbeauftragte/kontakt).
- Lizenzdienst-Domain an App-Standard `licenses.pornfetch.to` angepasst; anfängliche Offline-Frist von sieben auf drei Tage berichtigt (`src/licensing/client.py: INITIAL_GRACE`). Nach erfolgreicher Prüfung bleiben sieben Tage. Dies betrifft nur den Text, nicht die Lizenzfunktion.
- NOWPayments-Verweis auf eingebettete Widgets durch tatsächlich verwendeten Anbieter-Checkout ersetzt. Regionsergebnis wird im Middleware-Code noch zur Sperrprüfung genutzt; die falsche Behauptung, es werde schon davor verworfen, korrigiert. Ausgabereferenz als pseudonym statt pauschal nicht personenbezogen bezeichnet.
- Nach Zustimmung des Betreibers: pauschale Ausschlüsse von Mängeln/Erstattungen bei Plattformänderungen entfernt; erforderliche gesetzliche Updates von kostenpflichtigen neuen Versionen abgegrenzt; Erstattungen wegen Nichtlieferung/Mängeln nicht mehr als reine Kulanz dargestellt. [§ 327f BGB](https://www.gesetze-im-internet.de/bgb/__327f.html), [§ 327h BGB](https://www.gesetze-im-internet.de/bgb/__327h.html).
- Salvatorische Klausel korrigiert: gesetzliche Regelung statt wirtschaftlich möglichst ähnlicher Ersatzklausel. [§ 306 BGB](https://www.gesetze-im-internet.de/bgb/__306.html).
- Widerrufstexte: keine Behauptung mehr, Checkbox allein bewirke Erlöschen oder die Vertragsbestätigung werde bereits zuverlässig geliefert. Veralteten Absatzverweis der Erstattungsrichtlinie an die aktuelle Fassung angepasst. [§ 356 Abs. 6 BGB](https://www.gesetze-im-internet.de/bgb/__356.html).

## Offene rechtlich relevante Punkte

### 1. Hoch: Widerruf, Vertragsbestätigung und Vertragsschluss

**Befund:** `pf_server/checkout_consent.py` speichert allgemeine Zustimmungen für eine Stunde in der Browsersitzung. `payment_routes.create_crypto_payment` prüft Booleans, archiviert aber keine vollständige, bestellbezogene Zustimmung mit Textfassung. `OnrampCheckout` hat eine Hinweisversion und Zeitpunkte, aber das ersetzt keine Bestätigung an den Kunden. `i18n/license_email_*.json`, `templates/emails/license.html` und `invoice_service.py` enthalten keine vollständige Vertragsbestätigung einschließlich Widerrufszustimmung und Pflichtinformationen. Ohne E-Mail wird nur ein Download von Lizenz/Rechnung angeboten; der Wiederherstellungszugang endet sechs Stunden nach Erfüllung. Eine gespeicherte Rechnung ist kein automatischer Nachweis aller Vertragsinformationen.

**Folge:** Erlöschen des Widerrufsrechts ist derzeit nicht verlässlich belegbar. Die Texte allein beheben den Ablauf nicht. Maßgeblich sind [§ 312f BGB](https://www.gesetze-im-internet.de/bgb/__312f.html) und [§ 356 BGB](https://www.gesetze-im-internet.de/bgb/__356.html). Die aktuelle Fassung von [§ 356a BGB](https://www.gesetze-im-internet.de/bgb/__356a.html) verlangt zudem für entsprechende Online-Fernabsatzverträge eine zugängliche elektronische Widerrufsfunktion während der Widerrufsfrist. Eine solche Funktion wurde im geprüften Code nicht gefunden.

**Konkreter nächster Schritt:** Den unten festgelegten gewünschten Vertragsschluss mit den tatsächlichen Anbieterabläufen abgleichen; die letzte verbindliche Schaltfläche und unmittelbar davor Preis/Produktinformationen nach [§ 312j BGB](https://www.gesetze-im-internet.de/bgb/__312j.html) prüfen. „Continue to NOWPayments“ ist nur dann unproblematisch, wenn es tatsächlich noch keine verbindliche Bestellung auslöst. Vollständige Widerrufsbelehrung und Musterformular bereitstellen. Zustimmungen einschließlich Wortlaut/Version und Zeit der Bestellung zuordnen. Unveränderliche Bestätigung als E-Mail bzw. geeigneten dauerhaften Datenträger bereitstellen; bloßer veränderlicher Webseitenlink genügt nicht. Elektronische Erklärung mit Bestätigungsschritt und unverzüglicher Eingangsbestätigung ergänzen. Banxa-Kryptokauf und Softwarelizenzvertrag dabei auseinanderhalten. Patreon-Ablauf separat prüfen.

**Entscheidung des Betreibers:** zunächst dokumentieren und Ablauf klären, keine Checkout-Implementierung in diesem Auftragsschritt.

**Nachträgliche Klarstellung des Betreibers:** Die eigene Website bereitet den Kauf unverbindlich vor. Bei Krypto soll der Lizenzvertrag erst bei erfolgreicher Zahlung entstehen; das Öffnen einer NOWPayments-Session bleibt unverbindlich. Der Banxa-Kryptokauf allein soll somit noch keinen erfolgreich bezahlten Lizenzkauf darstellen. Bei Patreon ist die bezahlte Mitgliedschaft mit Lizenzleistung maßgeblich. Diese Festlegung beschreibt das gewünschte Modell, nicht den bereits abschließend rechtlich geprüften Ist-Ablauf.

**Formulierungsvorschlag für den späteren Abgleich mit den Anbieter-Checkouts:**

> Die Auswahl einer Zahlungsart und das Erstellen oder Öffnen einer Checkout-Sitzung auf dieser Website begründen noch keinen Lizenzvertrag. Bei Kryptowährungszahlungen kommt der Lizenzvertrag mit der erfolgreichen Zahlung des Lizenzpreises an die für die Bestellung bestimmte Zahlungsadresse zustande. Bei Verwendung von Banxa ist der Erwerb von Kryptowährung ein gesonderter Vorgang; für den Lizenzvertrag ist die erfolgreiche Weiterleitung der Zahlung an den Lizenz-Checkout maßgeblich. Die Lizenz wird nach Prüfung der Zahlungsbestätigung bereitgestellt. Bei Patreon wird die Lizenz als Bestandteil der erfolgreich bezahlten, hierfür ausgewiesenen Mitgliedschaft bereitgestellt.

Dieser Vorschlag wurde noch nicht in die öffentlichen AGB oder den Checkout übernommen. Zu prüfen bleiben die rechtsgeschäftliche Ausgestaltung von Angebot und Annahme, die tatsächlich angezeigten Providerbedingungen, der Nachweis erfolgreicher Zahlung sowie der Umgang mit Unterzahlungen, Gebühren und Fehlleitungen. Der Zeitpunkt einer verzögerten Webhook-Verarbeitung ist nicht automatisch der Zeitpunkt des Vertragsschlusses. Ein Softwareliefervertrag wird durch Verwendung eines Kryptozahlungsdienstes nicht automatisch selbst zur Finanzdienstleistung; die Informations- und Bestellpflichten sind deshalb für den Lizenzkauf gesondert zu prüfen. [§ 312j BGB](https://www.gesetze-im-internet.de/bgb/__312j.html). Vertragsschluss, Zahlungsprüfung und Bereitstellung sind zu unterscheiden; die Leistungszeit muss zum zugesagten Ablauf passen. [§ 327b BGB](https://www.gesetze-im-internet.de/bgb/__327b.html).

**Technischer Abgleich:** `nowpayments_service._validate_finished_payment` prüft Bestellreferenz, Betrag und Währung. `payment_routes.nowpayments_ipn` nimmt auch `partially_paid` zur weiteren Prüfung an; für Onramp besteht eine technische Betragstoleranz von 10 Prozent. Deshalb darf der spätere Text nicht ungeprüft ausschließlich den Providerstatus `finished` oder einen centgenauen Zahlungseingang voraussetzen. `patreon_member_is_paid_and_entitled` verlangt eine aktive, bezahlte, berechtigte Mitgliedschaft und schließt Probe-/Geschenkmitgliedschaften aus. Bloßes Öffnen des Checkouts bzw. kostenlose Registrierung löst keine Lizenz aus. Diese Erfüllungsprüfung allein legt noch keinen zivilrechtlichen Vertragsschluss fest.


### 2. Hoch: Fehlerbericht-Aufbewahrung bleibt organisatorisch offen

**Belege:** `Porn_Fetch/src/shared/error_reporting.py`, `src/backend/config.py`, `src/cli/settings.py`; `deploy/pocketbase/pb_hooks/error_log.pb.js`, `deploy/pocketbase/README.md`. Einwilligung ist standardmäßig aus; neue Berichte enthalten strukturelle Diagnosen ohne Video-URLs. Server akzeptiert auch ältere Freitextberichte und filtert sie; dies garantiert keine Anonymität. Keine automatische Löschung vorhanden.

**Betreiberentscheidung:** manuelle Löschung, vorgesehen jeweils zur nächsten veröffentlichten Version, keine feste Frist. Texte spiegeln dies jetzt wider. **Offen bleibt:** Falls lange keine Version erscheint, gibt es keine belastbare Obergrenze bzw. dokumentierte regelmäßige Erforderlichkeitsprüfung. Veröffentlichung als Löschanlass allein gewährleistet keine Speicherbegrenzung. Empfohlen: verbindliche manuelle Prüfung/Löschung auch bei ausbleibenden Releases und Behandlung der Sicherungen festlegen (Art. 5 Abs. 1 lit. e, Art. 13 DSGVO). Keine neue Löschfrist ohne Betreiberentscheidung eingeführt.

**Erneute Betreiberbestätigung:** Löschung von Hand, möglichst bei jeder neuen veröffentlichten Version; keine zusätzliche Frist oder feste Prüfung bei ausbleibenden Releases zugesagt. Diese Entscheidung ist dokumentiert; die offene datenschutzrechtliche Bewertung wird dadurch nicht als erledigt markiert. Die DSGVO schreibt nicht allgemein einen bestimmten 30-Tage-Zeitraum oder einen automatischen Löschjob vor. Personenbezogene Berichte dürfen aber nicht länger identifizierbar bleiben, als ihr Zweck es erfordert; Auskunft über Aufbewahrungsdauer oder nachvollziehbare Kriterien bleibt erforderlich (Art. 5 Abs. 1 lit. e und Art. 13 Abs. 2 lit. a DSGVO).

**Technische Klarstellung zum gewünschten Löschen von Dateien:** Die Fehlerberichte sind keine einzelnen Logdateien. `error_log.pb.js` speichert sie als Datensätze der PocketBase-Collection `error_logs`; die Migration legt zusätzlich die Collection innerhalb einer Datenbank mit weiteren Verwaltungsdaten an. Das Löschen irgendeiner Textdatei entfernt diese Datensätze nicht. Das Entfernen der gesamten Datenbank bzw. des Datenverzeichnisses würde auch Schema und Verwaltungs-/Authentifizierungsdaten betreffen. Für die manuelle Pflege sind gezielt die betroffenen `error_logs`-Datensätze zu löschen, etwa über die bestehende geschützte Admin-Oberfläche. Vorhandene Exporte, Sicherungen und Wiederherstellungskopien sind gesondert zu berücksichtigen. In diesem Auftrag wurden keine Produktionsdaten gelöscht und kein Löschjob eingerichtet.


### 3. Hoch: Privex-Rollen und Drittlandübermittlungen nicht abschließend geklärt

Die vom Betreiber genannte [BayLDA-Auslegungshilfe](https://www.lda.bayern.de/media/veroeffentlichungen/FAQ_Hosting_keine_Auftragsverarbeitung.pdf) existiert. Sie betrifft statische Selbstdarstellungsseiten ohne Nutzer-Tracking und ohne personenbezogene Seitenaufrufdaten, die zum Betreiber fließen. Sie bestätigt **keine allgemeine Ausnahme für jeden TLS-verschlüsselten VPS**. Hier nutzt der Betreiber zumindest für Checkout-Geolokalisierung Besucher-IP-Adressen; außerdem bestehen Checkout und Diagnosedienst. Ob Privex für die isolierte Transportleistung als eigener Telekommunikationsanbieter oder als Auftragsverarbeiter handelt, muss anhand des konkreten Vertrags und der VPS-Verarbeitung bestimmt werden. Aus dieser Prüfung ergibt sich weder ein pauschales AVV-Muss noch eine gesicherte AVV-Befreiung.

TLS schützt Inhaltsdaten, beseitigt aber nicht die Verarbeitung von Quell-IP/Verbindungsmetadaten. Standort Schweden allein beantwortet mögliche Drittlandzugriffe nicht. Für Privex, NOWPayments, Banxa, Onramp-Pay und Patreon müssen tatsächliche Empfängerrollen, Länder und einschlägige Übermittlungsgrundlagen festgehalten werden; bloße Links zu Anbieter-Datenschutzhinweisen ersetzen die eigenen Informationen nicht. NOWPayments nennt FD Transfers LLC in Saint Vincent and the Grenadines in seiner [Datenschutzerklärung](https://nowpayments.io/privacy-policy). Keine SCC oder sonstigen Garantien ohne Nachweis behauptet.

Proton stellt bereits ein vertraglich einbezogenes [DPA](https://proton.me/legal/dpa) bereit. Die Schweiz hat einen [Angemessenheitsbeschluss](https://commission.europa.eu/law/law-topic/data-protection/international-dimension-data-protection/adequacy-decisions_en). Das ersetzt nicht die Klärung anderer Empfänger und Weiterübermittlungen.

### 4. Mittel: Besucherzählung und Löschversprechen außerhalb des Repositorys

`templates/base.html` bindet `/__eaf/visit.js` ein. Die Datenschutzerklärung behauptet tägliche geheime IP-Prüfwerte und kurze Speicherung. Die konkrete Zählerimplementierung ist hier nicht vorhanden; Flask `operations_routes.py` zählt nur Anfragen und Bytes. Deshalb konnte ich tatsächliche Prüfwertaussage, Laufzeit, IP-Logs im gesamten Transportweg und etwaige Endgerätezugriffe des Skripts nicht bestätigen. Nicht mit bewiesener Falschangabe gleichzusetzen. Prüfen: tatsächliche Proxy-/Skriptkonfiguration, Löschung und Rechtsgrundlage für Reichweitenmessung. Hashing allein macht Daten nicht automatisch anonym. Erforderliche Sitzungscookies können unter [§ 25 Abs. 2 TDDDG](https://www.gesetze-im-internet.de/ttdsg/__25.html) fallen; das gilt nicht automatisch auch für jedes Analyseskript.

Ähnliches gilt für zugesagte Keygen-Sicherungsfristen und manuelle Datenbanksicherungen. Code für Versandbereinigung existiert, ein tatsächlich laufender Scheduler ist anhand des Quellcodes allein nicht nachgewiesen.

Zusätzlich gefunden: `templates/donation.html` lädt direkt ein NOWPayments-iframe. Das widerspricht der pauschalen Zusage in Datenschutzabschnitt 5, keinerlei externe Ressourcen zu laden. Die Route `/donation` ist in `pf_server/page_routes.py` registriert; ein visueller Overlay verhindert den bereits durch `src` ausgelösten Drittanbieterabruf nicht. Entscheidung zum Beibehalten oder Laden erst nach Klick angefragt; keine ungefragte Änderung am Zahlungsablauf.

### 5. Mittel: Support-Postfächer und Aufbewahrung

Eine aus der Versandwarteschlange entfernte Zustelladresse kann weiter in Proton-Postfächern, versendeten Nachrichten und Anhängen vorkommen. Datenschutztext unterscheidet dies jetzt. Löschpraxis für Support-/Lizenzkorrespondenz sowie gesetzliche Aufbewahrung nach Dokumentart noch konkretisieren. Steuer-/OSS-Pflichten und Lizenzzuordnungen brauchen getrennte Fristen/Kriterien; nicht jede technische Statuszeile muss so lange wie eine Rechnung gespeichert werden. Bei fehlenden Angaben dürfen keine pauschalen Fristen erfunden werden.

### 6. Mittel: Lizenzzusagen, notwendige Updates und Kontinuität

Jahresberechtigung, zehn Installationen, zufällige Installationskennung und sieben Tage nach erfolgreicher Prüfung passen grundsätzlich zum Code. Produktiv-Keygen-Policy nicht live geprüft. Die App sperrt Releases nach dem Berechtigungsende; die neue gesetzliche Update-Ausnahme in den AGB braucht deshalb einen tatsächlichen Weg, gesetzlich geschuldete Fehler-/Sicherheitsupdates ohne Wiederkauf bereitzustellen, etwa für weiterhin berechtigte Versionen.

`templates/partials/license_dialogs.html` verspricht die Veröffentlichung dauerhafter Ersatzlizenzen bei Aufgabe bzw. längerem Serverausfall. Der Dialog weist zutreffend darauf hin, dass dies manuell und nicht automatisch erfolgt. Organisatorische Erfüllbarkeit und Verfügbarkeit alter Builds bleiben zu sichern. Bestehende Beta-Käufer behalten gegebenenfalls eigene Ansprüche; der Verweis auf historische Bedingungen legitimiert deren Inhalt nicht automatisch.

### 7. Mittel: Weitere rechtliche Aussagen auf „Legal Statement“

`templates/legal-statement.html` enthält pauschale Freistellungen zu Datenbankrechten, Zugriffsschutz, Wettbewerbsrecht und Jugendmedienschutz. Sie sind durch den Code nicht bewiesen und sollten nicht als gesicherte Rechtslage veröffentlicht werden. Insbesondere automatisierte Profil-/Playlistabrufe sind nicht allein wegen des einzelnen Profils stets unerheblich. Öffentlich abrufbar bedeutet nicht automatisch rechtmäßig kopierbar; [§ 53 UrhG](https://www.gesetze-im-internet.de/urhg/__53.html) ist an Voraussetzungen gebunden. Markenverweise zur Kompatibilität sind insbesondere unter [§ 23 Abs. 1 Nr. 3 und Abs. 2 MarkenG](https://www.gesetze-im-internet.de/markeng/__23.html) zu prüfen.

Aus lokalem App-Betrieb folgt nicht pauschal, dass sämtliche Jugendschutzpflichten entfallen. Die [KJM](https://www.kjm-online.de/themen/technischer-jugendmedienschutz/unzulaessige-inhalte/) verlangt für entsprechende pornografische Online-Angebote geschlossene Benutzergruppen. Ob das konkrete eigene Angebot darunter fällt, hängt von tatsächlich veröffentlichten Bildern/Inhalten und Funktionen ab; kein AVS-Erfordernis allein aus dem App-Namen abgeleitet. Keine technische Sperrumgehungsfunktion in diesem Auftrag verändert. Für diese weitergehenden Aussagen ist eine gesonderte rechtliche Einzelfallprüfung nötig.

### 8. Bedingt: Steuern, Barrierefreiheit, Schlichtung

`invoice_service.py` verwendet pauschal den §-19-UStG-Hinweis. Er ist nur mit tatsächlichem Steuerstatus zulässig. EU-Auslandsumsätze können zusätzliche Anforderungen auslösen; Länderwahl allein klärt dies nicht. [§ 19 UStG](https://www.gesetze-im-internet.de/ustg_1980/__19.html), [§ 3a UStG](https://www.gesetze-im-internet.de/ustg_1980/__3a.html). Steuerstatus/Umsätze wurden nicht erhoben, daher kein festgestellter Verstoß.

Der Online-Shop kann dem BFSG unterfallen; Dienstleistungen von Kleinstunternehmen können ausgenommen sein. Beschäftigten-/Umsatzdaten fehlen. [Bundesfachstelle Barrierefreiheit](https://www.bundesfachstelle-barrierefreiheit.de/DE/Barrierefreiheitsstaerkungsgesetz/barrierefreiheitsstaerkungsgesetz). Keine allgemeine Accessibility-Überarbeitung durchgeführt. Auch [§ 36 VSBG](https://www.gesetze-im-internet.de/vsbg/__36.html) hängt teilweise von Beschäftigtenzahl und Teilnahmeverpflichtung ab; keine Pflicht ohne diese Prüfung unterstellt.

## Weitere Auffälligkeiten, nur dokumentiert

- AGB nennen das Lizenzmodell teilweise künftig/testweise, während das App-Repository bereits die Source-Available-Lizenz enthält. Öffentlich freigegebene Version und Entwicklungsstand deutlich zuordnen; alte GPL-Rechte nicht rückwirkend ändern.
- Deutsch/Englisch enthalten teils unterschiedliche Detailtiefe und Entwurfskennzeichnungen. Keine allgemeine redaktionelle Überarbeitung vorgenommen.
- Deployment-Dokumente nennen teils alte Dienst-Domains; App verwendet `pornfetch.to`. Routing/Erreichbarkeit nicht im Produktivbetrieb getestet.

## Noch erforderliche Entscheidungen

1. Gewünschter Zeitpunkt geklärt: bei Krypto erst erfolgreiche Zahlung, keine Bindung durch bloßes Öffnen der Session. Noch zu klären: rechtlich passender Anbieterablauf und zuverlässige Vertragsbestätigung für Käufer ohne E-Mail.
2. Manuelle Löschung möglichst bei jeder Veröffentlichung bestätigt; keine weitere Frist festgelegt. Die Speicherbegrenzung bei ausbleibenden Releases bleibt ein offener Befund, keine noch unbeantwortete Präferenzfrage.
3. Wo liegen aktuelle Proxy-/Besucherzählungs-Konfiguration und belastbare Angaben zu den Anbieterrollen/Übermittlungsgrundlagen?

Die gesetzlich relevante DSGVO-Prüfung bezieht sich insbesondere auf Art. 5, 6, 7, 13, 14, 28 und 44 ff. [Amtlicher DSGVO-Text](https://eur-lex.europa.eu/legal-content/ENG/ALL/?uri=celex%3A32016R0679). Lokale Verarbeitung von Erwachseneninhalten kann sensible Informationen betreffen; die neue minimale Diagnosegestaltung reduziert dieses Risiko, macht ältere Freitexte aber nicht automatisch anonym.

## Prüfung der Änderungen

- Alle Jinja-Templates erfolgreich geparst.
- Bestehende Website-/Marketing-Tests: 9 erfolgreich. Dabei vorhandene ResourceWarning für eine nicht geschlossene Promo-Videodatei; kein Testfehler.
- Bestehende App-Tests für Fehlerberichte: 11 erfolgreich.
- `git diff --check` im Server ohne Beanstandung.
- Kein vollständiger Build und keine Live-Zahlung ausgelöst; Checkout blieb unverändert.

Nachtrag zur Prüfung: Die ergänzten Betreiberentscheidungen und der Formulierungsvorschlag ändern nur Dokumentation. Keine Zahlungs-, Lizenzierungs- oder Löschlogik verändert.

## Umsetzung: E-Mail-Pflicht bei beiden Krypto-Checkouts

Auf ausdrücklichen Wunsch des Betreibers benötigen neue direkte NOWPayments- und
Banxa/Onramp-Bestellungen jetzt eine E-Mail-Adresse. Der optionale Ablauf ohne
E-Mail wurde entfernt. Eine verschlüsselte Bestellreferenz bleibt in
`Transaction.customer_email_encrypted` nach dem Versand und nach der separaten
Versandbereinigung erhalten. Sie enthält keinen neuen Bestandteil der Lizenzdatei
und wird nicht an Keygen oder NOWPayments weitergegeben. Datenschutztexte und
Checkout-Hinweise beschreiben Zustellung sowie spätere Kaufanfragen als Zwecke.
Bestehende Bestellungen werden nicht rückwirkend ergänzt. Patreon verwendet weiter
den bestehenden Webhook-Ablauf; dessen Adressspeicherung wurde nicht erweitert.

Damit entfällt für neue Krypto-Käufe die zuvor diskutierte Gestaltung ohne E-Mail.
Eine vollständige Vertragsbestätigung und Widerrufsfunktion müssen weiterhin
separat umgesetzt werden. Die Bestellreferenzen werden manuell auf Erforderlichkeit
geprüft und gelöscht; eine neue feste Aufbewahrungsfrist wurde nicht zugesagt.
Vor Inbetriebnahme ist die Migration `ae902bd71c40` erforderlich.


## Umsetzung: Bestellnachweis und dauerhafte Vertragsbestätigung

Dieser Nachtrag ersetzt die früheren Aussagen zum noch unveränderten Checkout und
zur fehlenden Vertragsbestätigung für neue Käufe. Die elektronische Widerrufsfunktion
bleibt separat offen. Die vorangegangenen Befunde zu Anbieterablauf, Produktionsbetrieb
und sonstigen rechtlichen Fragen sind damit nicht insgesamt erledigt.

Neue Krypto-/Banxa-Bestellungen übernehmen den zuvor ausdrücklich bestätigten Textstand
mit Produktinformationen, AGB, Widerrufsbelehrung und Musterformular, Zustimmungen,
Version und Zeitpunkt in die Datenbank. Bloße API-Booleanwerte genügen nicht mehr.
Nach verifizierter Zahlung wird die Bestätigung als unverändert gespeicherte PDF
zusammen mit Lizenz und Rechnung per E-Mail versandt; bei Fehlern erneut, auch nach
sieben Tagen. Sie ist zusätzlich über den geschützten Wiederherstellungszugriff verfügbar.
Alte Bestellungen erhalten keine nachträglich erfundene Zustimmung.

Entsprechend der Betreiberentscheidung bestätigt Patreon den Mitgliedschaftsvertrag.
Der Server bestätigt allein die Lizenzleistung und behauptet keinen Widerrufsverzicht.
Die Patreon-Adresse wird neu verschlüsselt bis zum erfolgreichen Versand gespeichert,
danach aus der Warteschlange gelöscht. Datenschutztexte beschreiben diese Änderung
sowie die Aufbewahrung der Vertragsnachweise. Die Lizenzdatei enthält weiterhin keine E-Mail-Adresse.

Rechtsgrundlage der Bestätigungsanforderungen: [§ 312f BGB](https://www.gesetze-im-internet.de/bgb/__312f.html).
Eine gespeicherte Zustimmung und ein SMTP-Erfolg belegen für sich allein weder den
Zugang noch sämtliche Voraussetzungen des Erlöschens nach § 356 Abs. 6 BGB.
Browserbereitstellung bleibt bei einem Mailfehler verfügbar; daraus wird kein automatischer
Verlust des Widerrufsrechts abgeleitet. Die tatsächlich noch erforderliche elektronische
Widerrufsfunktion richtet sich nach [§ 356a BGB](https://www.gesetze-im-internet.de/bgb/__356a.html).

Vor Inbetriebnahme: Migration bis `bf371c20a913`, stabile Verschlüsselungsschlüssel,
SMTP und beide Versandtimer aktivieren; ausstehende Sendungen und Rückläufer überwachen.
Keine Migration gegen die Produktivdatenbank und kein echter Mail-/Zahlungsvorgang
wurden in dieser Umsetzung ausgeführt.

Validierung dieses Nachtrags: 159 Tests erfolgreich (115 Zahlungs-/Zustimmungs-/
Bestätigungs-/Mailtests, 35 Banxa-/Konfigurations-/Migrationstests und 9 Webseitentests).
Alle 65 Jinja-Templates geparst; öffentliche Belehrungsseite und geschützter PDF-Download
geprüft. Migration einschließlich Rückmigration nur mit isolierter Testdatenbank.
`git diff --check` ohne Beanstandung. Bestehende ResourceWarning im Marketingtest
zur nicht geschlossenen Promo-Videodatei; kein Testfehler.


## Umsetzung: Elektronische Widerrufsfunktion

Dieser Nachtrag ersetzt den zuvor offenen technischen Befund zur elektronischen
Widerrufsfunktion. Nach [§ 356a BGB](https://www.gesetze-im-internet.de/bgb/__356a.html)
steht nun „Vertrag widerrufen“ hervorgehoben außerhalb der einklappbaren Navigation,
im Footer und vor der Altersbestätigung zur Verfügung. Das Formular unter `/withdrawal`
erfasst Name, Angaben zum Vertrag bzw. betroffenen Teil und die E-Mail für die Bestätigung.
Auf einer zweiten Seite wird die vollständige Erklärung angezeigt und ausschließlich mit
„Widerruf bestätigen“ übermittelt. Anmeldung, JavaScript, Gründe, ein gültiger Kauflink
oder eine in der Datenbank bereits bekannte Bestellnummer sind keine Voraussetzungen.
Eine automatische Ablehnung nach 14 Tagen oder wegen digitaler Lieferung findet nicht statt.

Die endgültige Bestätigung speichert Eingang und Zeitstempel vor dem E-Mail-Versuch.
Die unveränderte Bestätigung enthält die vollständigen Angaben und UTC-/Berliner Eingangszeit,
wird als E-Mail mit UTF-8-Textanhang versandt und steht zusätzlich als geschützter Download
zur Verfügung. Ein separater Versand informiert support@echteralsfake.me. Fehler werden
über einen eigenen Minutentimer erneut versucht; Wiederholung derselben Übermittlung
ändert den ursprünglichen Eingang nicht. Beide Versandwege besitzen getrennte Zustände.
Die Erklärung wird auch bei unbekannter Referenz entgegengenommen; Zuordnung, rechtliche
Bewertung und gegebenenfalls Erstattung bleiben manuell. Keine automatische Lizenzsperre
und keine Gleichsetzung von Eingang mit einer Entscheidung über den Widerruf.

Die Belehrung enthält jetzt den Funktionshinweis nach dem aktuellen amtlichen
[Muster, Gestaltungshinweis 3](https://www.gesetze-im-internet.de/bgbeg/art_253anlage_1.html).
Neue Vertragsbestätigungen enthalten diesen Text; bereits gespeicherte PDFs bleiben unverändert.
Datenschutzhinweise beschreiben verschlüsselte Entwürfe, empfangene Erklärungen, Bestätigungen,
Versand an Kunde und Support über Proton Mail sowie manuelle Aufbewahrungsprüfung.

Vor Produktivbetrieb: Migration `c482e16d09a2`, bestehender stabiler Verschlüsselungsschlüssel,
SMTP-Konfiguration und eigener Timer `eaf-withdrawals.timer`. Ausstehende Sendungen,
Mailrückläufer und die manuelle Bearbeitung müssen überwacht werden. Technisch erfolgreicher
SMTP-Versand ist kein Beweis des Zugangs. Andere zuvor dokumentierte rechtliche und
betriebliche Befunde sind durch diese Funktion nicht automatisch erledigt.


Abschlussprüfung am 01.11.2026: 158 unterschiedliche gezielte Tests erfolgreich,
darunter 16 Prüfungen der Widerrufsfunktion, Versandfehlern, doppelten Übermittlungen,
CSRF, geschütztem Download und Betreiberbearbeitung. Migration, Speicherung auf dem
migrierten Schema und Rückmigration wurden ausschließlich isoliert geprüft. Alle 67
Jinja-Templates wurden geparst. Desktop (1440 px) und Smartphone (390 px) wurden mit
Chromium bei deaktiviertem JavaScript und aktivem CSRF-Schutz vollständig bis zum
Download durchlaufen; Mailversand war dabei simuliert. Kein horizontaler Überlauf.
Das mobile Menü verdeckt die Erklärung auch ohne JavaScript nicht mehr.

Die vorhandene Schulplan-Verweissperre darf die gesetzliche Widerrufsmöglichkeit nicht
sperren. Ausschließlich der Widerrufsweg samt notwendigen Darstellungsdateien und
Datenschutz-/Anbieterinformationen wurde ausgenommen; die Sperrseite verlinkt die
Funktion. Die sonstige Sperre bleibt aktiv und ist getestet. Zwei ältere Testannahmen
zum inzwischen erweiterten Bestellschema und dem vom Betreiber festgelegten Mailanbieter
Proton Mail wurden an die bereits umgesetzten Änderungen angepasst.
`git diff --check` ohne Beanstandung. Vorhandene ResourceWarnings für nicht geschlossene
Dateien in älteren Webseiten-/Anwendungstests sind keine Testfehler.
Keine Produktivmigration, keine echten E-Mails und keine Zahlung wurden ausgelöst.

## Ergänzung 01.11.2026: Scraping-Leistungsumfang und gesonderter Erstattungsweg

Auf ausdrücklichen Wunsch wurden die deutschen und englischen AGB, die vorvertragliche
Produktbeschreibung und die Erstattungsrichtlinie konkretisiert. Ausgangspunkt sind
`Porn_Fetch/src/shared/provider_routing.py`, `src/shared/media.py`,
`docs/WEBSITES.md`, `README.md`, `CONTEXT.md` und der Website-Katalog
`pf_server/product_catalog.py`. Geprüft wurde der Quellcode-/Dokumentationsstand, nicht
jede Plattform durch echte Downloads. Die Leistungsbeschreibung benennt die 15
Integrationen, Unterschiede bei Profilen, Sammlungen, Konten und CLI-Fotoalben,
Premium-Qualitäten, den YouPorn-MP4-Sonderfall sowie fehlende Stichwortsuche und nicht
unterstützte Webseiten. Keine fremden Inhalte, Konten, Nutzungsrechte oder beliebigen
Auflösungen werden als Bestandteil der Lizenz verkauft.

AGB Abschnitt 6 beschreibt Layout-/Schnittstellenänderungen, CAPTCHA/Cloudflare,
Zugangssperren und rechtliche Hindernisse. Geschuldete Nacherfüllung erfolgt innerhalb
einer angemessenen Frist ab Mangelmitteilung, kostenfrei und ohne erhebliche
Unannehmlichkeiten. Es gibt keine pauschale Wartefrist bis zum nächsten Release.
Keine zusätzliche Verfügbarkeitsgarantie und kein zusätzliches jederzeitiges
Kulanz-Rückgaberecht werden eingeräumt. Keine Pflicht zur rechtswidrigen Umgehung;
gesetzliche Minderungs-/Beendigungsrechte bei unmöglicher Nacherfüllung bleiben
bestehen. Ein allgemeiner Risikohinweis oder die AGB-Checkbox ersetzt keine
konkrete gesonderte Beschaffenheitsvereinbarung nach § 327h BGB. Die neue Checkbox
betrifft ausschließlich den Erstattungsweg, keinen Verzicht auf Mängelrechte.

### Erstattungsvereinbarung und Nachweis

- Eine eigene, anfangs leere Pflicht-Checkbox gilt vor allen drei Website-Zahlungswegen.
  Der Server verlangt sie zusätzlich zu den bisherigen Erklärungen. Die Zustimmung
  zum vorzeitigen Leistungsbeginn wird bei Patreon weiterhin nicht verlangt;
  das gilt auch im Formular ohne JavaScript.
- NOWPayments und Banxa-finanzierte Lizenzzahlungen: Kryptowährung. Patreon: innerhalb
  von 90 Tagen ab jeweiliger Originalzahlung über Patreon auf das ursprüngliche
  Zahlungsmittel, danach Kryptowährung nach der gesonderten Vereinbarung.
- Empfängeradresse, Währung und Netzwerk werden vor der tatsächlichen Auszahlung
  abgestimmt. Bei Fiatforderungen bleibt der volle geschuldete Betrag maßgeblich;
  dokumentierter aktueller Kurs, keine pauschale Rückgabe der ursprünglichen
  Coin-Anzahl. Notwendige Netzwerk-, Empfangs- und Umrechnungskosten trägt der Anbieter.
- Ist eine rechtzeitige kostenfreie Krypto-Abwicklung nicht möglich, bleibt die
  gesetzliche Rückzahlung geschuldet: ursprüngliches Zahlungsmittel oder ausdrücklich
  vereinbarte andere kostenfreie Möglichkeit. Die 90 Tage sind keine Ausschlussfrist
  für Ansprüche. Anbieter-/Bank-/Apple-Streitverfahren werden nicht ausgeschlossen;
  Banxas eigenständiger Kryptokauf wird nicht automatisch rückabgewickelt.
- Textfassung `contract-2026-11-01-v3`, Sessionfassung `checkout-v3`. Bei neuen
  NOWPayments-/Banxa-Bestellungen werden Erklärung und vollständiger Vereinbarungstext
  im bestehenden Auftragssnapshot gespeichert und in die Vertrags-PDF aufgenommen.
  Alte Bestellungen werden nicht nachträglich als zustimmend behandelt.
- `/checkout/agreement` liefert einen PDF-Zustimmungsbeleg nur für die aktuelle,
  gültige Browsersitzung, mit Referenz, Textfassung, UTC-Zeit, Zahlungsweg und den
  tatsächlich erfassten Erklärungen. Kein Zahlungsbeleg, kein Identitätsnachweis.
  Kein öffentlicher Zugriff über eine Referenz-URL. Download während der bestehenden
  einstündigen Sitzung; nicht zugeordnete Datensätze werden weiterhin nach einem Tag
  durch den vorhandenen Bereinigungslauf gelöscht. Auftragskopien bleiben erhalten.
- Vom Nutzer ausdrücklich gewählte Patreon-Variante: Checkbox und Kundenbeleg,
  **keine OAuth-Anmeldung und keine automatische Zuordnung zum Mitglied**. Der
  Download steht sowohl im JavaScript-Vorschaufenster als auch auf der HTML-Seite.
  Direkte Patreon-Käufe können die Website umgehen. Ein Webhook belegt keine Zustimmung.
  Ohne zuordenbaren Nachweis wird der abweichende Erstattungsweg im Einzelfall nochmals
  vereinbart. Die Lizenzleistungsbestätigung behauptet keine solche Zustimmung.

### Betrieb und offene Grenzen

Diese Änderung führt keine automatischen Rückzahlungen aus und benötigt keine weitere
Datenbankmigration zusätzlich zu den bereits dokumentierten Migrationen. Für jeden
Erstattungsfall Originalzahlung, Anspruch, Betrag, bisherige Erstattungen und laufende
Streitfälle prüfen. Patreon-Guthaben für fristgerechte Erstattungen verfügbar halten;
fehlendes Guthaben oder technische Anbieterfristen verlängern keine gesetzlichen
Fristen. Keine zusätzliche Krypto-Auszahlung neben einem bereits abgewickelten
Plattformrefund. Adresse/Netzwerk und gegebenenfalls Kurs ausdrücklich abstimmen,
Kosten übernehmen und Auszahlungsbeleg mit der Originalzahlung dokumentieren.

Vor Produktivverkauf sollte die konkrete vorformulierte Krypto-Vereinbarung auf ihre
AGB-Wirksamkeit, insbesondere Transparenz, tatsächliche Kostenfreiheit und praktische
Erfüllbarkeit, anwaltlich geprüft werden. Eine zusätzliche Checkbox allein garantiert
keine Wirksamkeit. Die vereinbarte Rückfallregel erhält gesetzliche Rechte.

Einfach dokumentierte weitere Widersprüche, hier nicht technisch umgebaut:
- App-Dokumentation unterscheidet Entwicklungsstand 3.9 und ältere veröffentlichte
  3.8-Binaries. Die Beschreibung des 3.9-Quellcodes beweist keine Verfügbarkeit einer
  passenden fertigen Veröffentlichung. Vor echten Verkäufen Release-Angebot abgleichen.
- Bestehende Website-Warnungen nennen Test-/Vorschaukäufe und untersagen echte Zahlungen,
  während aktivierter Banxa-Checkout technisch echte Käufe ermöglichen kann.
- Die bisherige Marketing-Liste stellt kostenlose allgemeine App-Funktionen gemeinsam
  mit der Premium-Berechtigung dar. Der neue Vertragstext erklärt insbesondere, dass
  automatische App-Updates selbst nicht kostenpflichtig sind.

Primärquellen, online geprüft am 01.11.2026:
- https://www.gesetze-im-internet.de/bgb/__357.html — abweichendes Zahlungsmittel nur
  ausdrücklich vereinbart und ohne Kosten für Verbraucher.
- https://www.gesetze-im-internet.de/bgb/__327n.html und
  https://www.gesetze-im-internet.de/bgb/__327o.html — Minderung, Vertragsbeendigung,
  Rückzahlungsfristen und Zahlungsmittel.
- https://www.gesetze-im-internet.de/bgb/__327l.html und
  https://www.gesetze-im-internet.de/bgb/__327m.html — angemessene Nacherfüllung,
  Unmöglichkeit, weitere Rechte, Unerheblichkeit.
- https://www.gesetze-im-internet.de/bgb/__327h.html,
  https://www.gesetze-im-internet.de/bgb/__327r.html und
  https://www.gesetze-im-internet.de/bgb/__327s.html — Produktabweichungen,
  Änderungen und Grenzen vorweggenommener Ausschlüsse.
- https://support.patreon.com/hc/en-us/articles/39611657224717-How-to-manage-refunds-for-your-fans
  — 90-Tage-Creator-Erstattung bei ausreichendem Guthaben; ursprüngliches Zahlungsmittel.

Validierung dieser Ergänzung: 165 unterschiedliche automatisierte Tests aus den
Bereichen Vertragsnachweis, gemeinsame Checkout-Zustimmung, NOWPayments, Banxa,
Patreon, Zahlungsfortschritt, Anwendung, Marketing und Widerruf erfolgreich.
Zusätzlich neun isolierte Chromium-Abläufe: alle drei Zahlungswege bei 1440 px und
390 px mit JavaScript sowie bei 390 px ohne JavaScript. Pflichtzustimmung,
Erreichbarkeit und Download der PDF geprüft, eine PDF per Textextraktion kontrolliert.
CSRF war im Browser aktiviert; Providerzugriffe waren blockiert bzw. gemockt.
Keine echten Käufe, E-Mails, Erstattungen oder Produktivmigrationen ausgeführt.
