# Plausibilitätsabgleich: Legal Statement, Spendenwidget und Besucherzählung

Geprüft am 01.11.2026. Auftrag: rechtlich relevante Aussagen mit App und Server
abgleichen, keine vollständige juristische Freigabe oder allgemeine Funktionsrevision.
Die Änderungen wurden lokal vorbereitet. Der laufende Server wurde nur lesend geprüft;
keine Produktivmigration, kein Versand, keine Zahlung und kein Dienstneustart.

## Ergebnis

Die Grundbeschreibung einer lokal laufenden Download-Anwendung ist vertretbar.
Mehrere bisherige rechtliche Schlussfolgerungen waren jedoch zu pauschal: Zugänglichkeit
eines Videos, einzelne Profile, fehlende Registrierung, lokale Verarbeitung und eine
Alterscheckbox begründen jeweils für sich keine allgemeine Rechtmäßigkeit.
`templates/legal-statement.html` wurde entsprechend eingegrenzt und mit Primärquellen
versehen. Die vertraglichen Verbraucherrechte aus der vorangegangenen Überarbeitung
werden dadurch nicht eingeschränkt.

| Thema | Abgleich und Korrektur |
| --- | --- |
| Privatkopie | § 53 UrhG setzt u. a. private, nicht erwerbsbezogene Nutzung durch natürliche Personen und keine offensichtlich rechtswidrige Quelle voraus. Öffentliche Erreichbarkeit erlaubt weder automatisch Kopie noch Weiterveröffentlichung. |
| Verschlüsselung | HTTPS ist Transportverschlüsselung. Streamformat und Erreichbarkeit belegen weder fehlenden rechtlichen Schutz noch die Erlaubnis, wirksame Schutzmaßnahmen zu umgehen. Kein pauschales „nur ungeschützte Inhalte“. |
| Datenbanken | Profile/Playlists können qualitativ oder quantitativ wesentlich sein. Wiederholte systematische Entnahme kleiner Teile kann relevant sein. Die Batch-Funktion setzt keine rechtliche Mengenbegrenzung durch. |
| Zugriffsschutz | App und Abhängigkeiten bieten Browser-Impersonation, Cookies, Proxy/SNI-Optionen und Behandlung bestimmter Anti-Bot-Challenges. „Keine Umgehung irgendwelcher Schutzmaßnahmen“ wäre technisch zu weitgehend. § 202a StGB verlangt eine konkrete Prüfung seiner Voraussetzungen; nicht jede technische Anpassung ist automatisch strafbar. |
| Plattform-AGB | Registrierung ist weder alleinige Voraussetzung noch alleiniger Nachweis der Einbeziehung. Bestehende Account-Verträge und die tatsächliche Einbeziehung sind maßgeblich. |
| Rechtsprechung | BGH I ZR 154/16 betrifft Werbeblocker. Daraus folgt keine pauschale Erlaubnis für Web-Scraping. |
| Marken | Benennende Bezugnahme kann § 23 Abs. 1 Nr. 3, Abs. 2 MarkenG entsprechen; kein Freibrief für jede Logo-Verwendung oder einen Partnerschaftseindruck. |
| Jugendschutz | Lokale Ausführung entbindet nicht automatisch von sämtlichen Pflichten. Tatsächliche Inhalte und Zugänglichmachung entscheiden. Eine 18+-Checkbox ist keine ausreichende AVS für ein Angebot, das eine geschlossene Benutzergruppe voraussetzt. Umgekehrt wird nicht behauptet, jeder lokale Downloader brauche allein deshalb eine solche Gruppe. |

Technische App-Referenzen: `/home/asuna/PycharmProjects/Porn_Fetch/src/shared/provider_routing.py`,
`src/shared/provider_accounts.py`, `src/backend/clients.py`, `src/cli/flows/settings.py`
sowie die tatsächlich vorhandene Netzwerkabhängigkeit `base_api/base.py` (Challenge-
Behandlung). Der Abgleich betrifft den vorhandenen 3.9-Quellstand, nicht eine Zusicherung,
dass sämtliche veröffentlichten älteren Binärdateien dasselbe Verhalten zeigen.

## NOWPayments-Spendenwidget

`templates/donation.html` enthält zunächst keinen iframe mit `src`. Erst der separate
Button „Agree and load NOWPayments / Zustimmen und laden“ erzeugt den iframe über
`static/donation.js`. Alters- und Länderbestätigung sind dafür Vorbedingungen, ersetzen
aber nicht die Ladeentscheidung. Kein automatischer Anbieteraufruf beim Seitenaufruf,
keine dauerhafte Speicherung dieser Auswahl, Entladen über eigenen Button. Zurücknahme
der Voraussetzungen entfernt das Widget ebenfalls. Die Herkunfts-URL wird unterdrückt.

Hinweise auf der Spendenseite und beide Datenschutzfassungen nennen Anbieter, mögliche
IP-/Browser-/Transaktionsdaten, Cookies, Verarbeitungszwecke und Drittlandbezug.
„Kryptospenden sind anonym“ wurde korrigiert. Entladen beendet die Einbindung, löscht
aber keine bereits beim Anbieter vorhandenen Daten oder Cookies.

Offen bleibt ein belastbarer Nachweis der einschlägigen Drittland-Übermittlungsgrundlage
und der tatsächlichen Zwecke/Unterempfänger des Widgets. Die öffentliche
NOWPayments-Datenschutzerklärung nennt FD Transfers LLC in St. Vincent und den Grenadinen
und Cookies für Betrieb, Statistik und Marketing; daraus ergibt sich keine von uns
verifizierte konkrete Garantie nach Art. 46 DSGVO. Der Ladeklick ist **kein** Nachweis
solcher Garantien und keine pauschale Freigabe späterer beliebiger Werbeverarbeitung.
Die tatsächliche Anbieter-Konfiguration und gegebenenfalls zusätzliche Einwilligungen
müssen dazu passen. Es wurde keine fremde vollständige Cookie-Inventur behauptet.

## Besucher und Downloads: tatsächlich geprüfter Betrieb

Gelesen wurden aktuelle Caddy-Konfigurationen, Dashboard-Quellen und der relevante Code
im laufenden Container sowie der installierte Download-Importer. Keine Nutzerdatensätze,
Produktivlogs oder geheimen Schlüssel wurden zur Auswertung kopiert.

- Besucherkennung: HMAC aus dauerhaftem Geheimnis, UTC-Tag und IP; anschließend weiterer
  gekürzter Hash in `visitor_seen`. Der Host ist aktuell nicht Bestandteil des HMAC.
  Deshalb können auf mehreren eigenen Hosts identische Tages-Prüfwerte entstehen.
  Gefundene Auswertungen aggregieren; eine tatsächliche Interessenprofilbildung wurde
  nicht festgestellt. „Nicht verknüpfbar“ wäre trotzdem falsch.
- Aufräumen erst bei neuer Besucherzählung, mit Grenze vor dem aktuellen UTC-Tag minus
  zwei Tagen. Aktueller und zwei vorangegangene Tage können bleiben; ohne Verkehr
  findet keine unabhängige Bereinigung statt. Die ursprüngliche Formulierung einer
  kurzen, technisch garantierten Aufbewahrung war zu unbestimmt.
- Das Browser-Skript sendet den ersten Pfadbestandteil; der Server ignoriert ihn und
  verwendet „page“. Kein Cookie, Local Storage oder Fingerprinting im Zählskript gefunden.
- Caddy protokolliert Software-/Update-Downloads mit gehashten IP-Feldern, Dateipfad,
  Zeitpunkt, Methode, Status und Datenmenge. Queryparameter sowie Request-/Response-
  Header werden entfernt. IP-Hashes sind nicht täglich wechselnd geschützt.
- Der Download-Importer übernimmt IP-Prüfwerte mit Quelle, Pfad und Tag in
  `/var/lib/pornfetch-ops/update-traffic.db` und zählt unterschiedliche Downloader.
  Kein automatischer Löschlauf für diese Zuordnungen vorhanden. Logrotation beseitigt
  nicht die bereits in SQLite übernommenen Werte.
- `direct6.pornfetch.to` ist ein aktiver direkter IPv6-Downloadzugang ohne Privex.
  Vodafone kann dort die Gegenstellen-IP sehen. Die Aussage zur allein sichtbaren
  Privex-Gegenstelle wurde ausdrücklich auf den Privex-/WireGuard-Weg eingeschränkt.

Die Datenschutzabschnitte 2, 3–5 beschreiben jetzt diese Ausgangslage. Die pauschale
Marketingaussage „No IP logs“ wurde ebenfalls korrigiert, weil sie rechtlich relevante
Datenschutzinformation ist. Die lokale Länderprüfung im Checkout wird getrennt von der
Website-Statistik beschrieben. „Keine externen Ressourcen/Drittanbieter-Cookies“ gilt
mit aktiviertem Widget ebenfalls nicht allgemein.

## Vorbereitete technische Verbesserung

Siehe [Änderungssatz und Aktivierungsanleitung](../deploy/dashboard-privacy/README.md).
Hostgetrennte Tages-Prüfwerte, weniger Browserdaten, unabhängiger Cleanup-Timer,
IP-freie Download-Logfelder und eine Statistik ohne Besucherkennungen sind vorbereitet.
Historische Summen können erhalten bleiben; personenbezogene Altbestände benötigen
gezielte Bereinigung. Beide Download-Zugänge werden berücksichtigt.

Art. 6 Abs. 1 Buchst. f DSGVO ist als Grundlage für eigene begrenzte Betriebsstatistik
plausibel, aber nicht schon durch das Etikett „cookielos“ bewiesen. Zweck, Erforderlichkeit,
Interessenabwägung, Widerspruchsbehandlung und Löschpraxis sind zu dokumentieren. Die
weniger eingreifende Variante reduziert insbesondere die Rechtfertigung für dauerhaft
gespeicherte Download-Prüfwerte. Auch § 25 TDDDG ist anhand der tatsächlichen Zugriffe
auf Endgeräte zu prüfen; kein pauschales „ohne Cookie stets einwilligungsfrei“.

Die öffentliche Datenschutzerklärung stellt den vorbereiteten Zustand ausdrücklich
noch nicht als laufenden Betrieb dar. Textbausteine für die spätere Umstellung liegen
im Änderungssatz. Eine bloße wahrheitsgemäße Beschreibung heilt keine unnötige oder
unverhältnismäßig lange Datenspeicherung.

## Weitere Abweichungen, nur dokumentiert

- Produktbeschreibung/Quellcode 3.9 und ältere veröffentlichte Binärstände können
  unterschiedliche Funktionen haben; kein allgemeiner Release-Umbau in diesem Auftrag.
- Der lokale ältere Deployment-Entwurf verwendet teilweise Port 8010, der geprüfte
  laufende Besucherzähler Port 18010. Keine Änderung anderer Infrastrukturabläufe.
- Download-Anfragen und Teilabrufe sind keine vollständigen Installationen. Die
  vorbereitete Statistik benennt die tatsächlich gemessenen Größen entsprechend.

## Primärquellen

- [§ 53 UrhG](https://www.gesetze-im-internet.de/urhg/__53.html),
  [§ 87b UrhG](https://www.gesetze-im-internet.de/urhg/__87b.html),
  [§ 95a UrhG](https://www.gesetze-im-internet.de/urhg/__95a.html).
- [§ 202a StGB](https://www.gesetze-im-internet.de/stgb/__202a.html),
  [§ 305 BGB](https://www.gesetze-im-internet.de/bgb/__305.html),
  [§ 23 MarkenG](https://www.gesetze-im-internet.de/markeng/__23.html).
- [BGH I ZR 154/16, Urteil vom 19.04.2018](https://juris.bundesgerichtshof.de/cgi-bin/rechtsprechung/document.py?Art=pm&Blank=1&Datum=2018&Gericht=bgh&Seite=4&file=dokument.pdf&linked=urt&nr=88498).
- [KJM: unzulässige Inhalte und geschlossene Benutzergruppen](https://www.kjm-online.de/themen/technischer-jugendmedienschutz/unzulaessige-inhalte/).
- [NOWPayments Privacy Policy](https://nowpayments.io/privacy-policy), abgerufene
  Fassung mit Stand 15.12.2025.
- [§ 25 TDDDG](https://www.gesetze-im-internet.de/ttdsg/__25.html),
  [LfD Niedersachsen: TDDDG-FAQ](https://www.lfd.niedersachsen.de/startseite/infothek/faqs_zur_ds_gvo/faq-telekommunikation-digitale-dienste-datenschutzgesetz-tdddg-206449.html),
  [DSK: Orientierungshilfe Digitale Dienste](https://www.bfdi.bund.de/SharedDocs/Downloads/DE/DSK/Orientierungshilfen/OH_Digitale-Dienste.pdf?__blob=publicationFile&v=1).
- [Caddy: Logging, Filter und Rotation](https://caddyserver.com/docs/caddyfile/directives/log).

## Validierung

30 bestehende Website-/Anwendungstests, vier Dashboard-Tests einschließlich
Host-/Tagestrennung und unabhängiger Bereinigung sowie vier Statistik-/Migrationstests
mit synthetischen Daten erfolgreich. Widget-Browserprüfung: Desktop, Mobil und ohne
JavaScript; externe Anbieterantworten ersetzt, keine echten Spenden. Die Caddy-Filter-
und Rotationssyntax wurde mit dem installierten Caddy-Parser geprüft; keine vollständige
Produktivkonfiguration geladen oder aktiviert. Patch-Anwendbarkeit gegen die gelesenen
Ausgangsdateien geprüft. Ausführungsdetails im Änderungssatz.
