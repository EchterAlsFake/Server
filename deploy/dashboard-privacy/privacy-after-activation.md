# Textbausteine erst nach bestätigter Aktivierung

Diese Bausteine ersetzen die betroffenen Absätze in den deutschen und englischen
Datenschutz-Partialtemplates **erst nach** dem dokumentierten Rollout. Rechtsgrundlage,
Zwecke, Betroffenenrechte, Widgetbeschreibung und die IPv6-Ausnahme bleiben erhalten.
Alte Logs/Backups sind gesondert zu prüfen; ihr Fortbestand muss weiterhin genannt werden.

## Deutsch — tägliche Besucherzählung, Abschnitt 2

Ein selbst gehosteter Dashboard-Dienst schätzt tägliche Besucherzahlen pro Host. Er
verarbeitet die Verbindungs-IP-Adresse im Arbeitsspeicher mit UTC-Datum, Hostnamen und
einem geheimen Schlüssel zu einem Prüfwert. Gespeichert werden ein daraus abgeleiteter
Hash, Datum, Host und die feste Gruppe „page“, nicht die IP-Adresse im Klartext. Gleiche
IP-Adressen ergeben für verschiedene Hosts und Tage unterschiedliche Prüfwerte. Der
geheime Schlüssel selbst wird nicht täglich ausgetauscht; die Verarbeitung bleibt eine
Pseudonymisierung, keine garantierte Anonymisierung. Gemeinsame oder wechselnde
IP-Adressen können die Schätzung verzerren.

Prüfwerte vergangener UTC-Tage werden bei neuen Zählungen und zusätzlich durch einen
täglichen Bereinigungsdienst um 00:05 UTC entfernt. Bei Ausfällen kann sich die
Bereinigung bis zum nächsten erfolgreichen Lauf verzögern. Tages- und Host-Summen
bleiben ohne diese Prüfwerte erhalten. Sicherungskopien werden gesondert behandelt.

## Deutsch — Downloadstatistik, Abschnitt 2

Für App-Dateien und Updates werden gefilterte Zugriffsprotokolle mit Zeitpunkt, Host,
Dateipfad ohne URL-Parameter, Anfragemethode, Antwortstatus und Übertragungsvolumen
geführt. IP-Adressfelder, Quellport, TLS-Details sowie Anfrage- und Antwort-Header werden
vor dem Schreiben entfernt. Die Downloadstatistik speichert nur zusammengefasste
Anfragen, Teilabrufe und Datenmengen pro Quelle, Datei und UTC-Tag sowie Summen je
Übertragungsweg; sie verwendet keine Besucher-Prüfwerte und zählt keine eindeutigen
Downloader. Diese Statistik betrifft Software- und Updatedateien, nicht die mit der
App heruntergeladenen Videos. Aggregierte Summen bleiben dauerhaft bestehen.

Logdateien werden bei 20 MiB oder beim nächsten Schreibzugriff nach 24 Stunden rotiert;
für Archive sind höchstens zehn Dateien und sieben Tage eingestellt. Ohne weitere
Schreibzugriffe kann sich die Rotation und Bereinigung verzögern. Das ist keine
garantierte Sieben-Tage-Löschung sämtlicher Rohdaten. Noch vorhandene Altbestände und
Sicherungen aus der vorherigen Statistik werden gesondert behandelt.

## Deutsch — Zählskript, Abschnitt 5

Das selbst gehostete Zählskript sendet eine Anfrage mit leerem JSON-Objekt an einen
Dienst unter derselben Website-Adresse. Es liest keinen Seitenbereich aus und sendet
weder diesen noch URL-Parameter, Seitentitel oder eine Herkunfts-URL mit. Die Anfrage
überträgt keine Cookies. Das Skript verwendet weder Local Storage noch
Browser-Fingerprinting. Die Verarbeitung der Verbindungs-IP ist in Abschnitt 2
beschrieben.

## English — daily visitor count, Section 2

A self-hosted dashboard estimates daily visitors per host. It processes the connection
IP address in memory with the UTC date, hostname and a secret key to form a check value.
The table stores a derived hash, date, host and fixed group “page”, not the plain IP
address. The same IP produces different check values for different hosts and days.
The secret key itself is not replaced daily; this remains pseudonymisation, not
guaranteed anonymisation. Shared or changing IP addresses can distort the estimate.

Check values from past UTC days are deleted during new counts and by a separate daily
cleanup at 00:05 UTC. Outages may delay deletion until the next successful run. Daily
and host totals remain without these check values. Backups are handled separately.

## English — download statistics, Section 2

Filtered access logs for application files and updates contain timestamp, host, file
path without URL parameters, request method, response status and transfer volume.
IP fields, source port, TLS details and request/response headers are removed before
writing. Download statistics store aggregate request, partial-request and byte counts
per source, file and UTC day, plus transport-route totals; they do not use visitor check
values or count unique downloaders. These statistics concern software and update files,
not videos downloaded with the app. Aggregate totals remain permanently.

Logs rotate at 20 MiB or on the next write after 24 hours; archives are configured for
at most ten files and seven days. Without further writes, rotation and cleanup can be
delayed. This is not a guaranteed seven-day deletion of every raw record. Any remaining
legacy records and backups from the previous statistics are handled separately.

## English — counting script, Section 5

The self-hosted counting script sends an empty JSON object to an endpoint under the
same website address. It does not read a page section or send one, URL parameters,
page titles or a referrer URL. The request omits cookies. The script uses neither
local storage nor browser fingerprinting. Processing of the connection IP is
described in Section 2.
