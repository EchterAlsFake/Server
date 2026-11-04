# Vorbereitete datensparsamere Betriebsstatistik

Stand: 01.11.2026. **Nicht auf dem laufenden Server aktiviert.** Die öffentlichen
Datenschutzhinweise beschreiben bis dahin weiterhin den tatsächlich geprüften Betrieb.
Diese Dateien enthalten keine Zugangsdaten und keine Kopien der Produktivdatenbank.

## Inhalt und Wirkung

| Datei | Änderung |
| --- | --- |
| `dashboard.patch` | Besucher-Prüfwerte beziehen UTC-Tag **und Host** ein; keine Übermittlung des Seitenbereichs; Bereinigung vergangener Tage auch per CLI; Downloadansicht ohne vermeintlich eindeutige Downloader. Enthält Verhaltenstests. |
| `update-statistics.patch` | Download-Importer zählt Anfragen, Teilabrufe und Bytes pro Quelle, Dateipfad und UTC-Tag ohne IP-Prüfwerte. Bestehende Importpositionen bleiben erhalten. |
| `caddy.patch` | Entfernt IP-Felder, Quellport und TLS-Details aus beiden Download-Logs: regulärer Zugang und `direct6.pornfetch.to`. Ergänzt zeitabhängige Rotation. |
| `migrate_download_statistics.py` | Fasst bestehende Downloadstatistik zusammen und entfernt die bisherige Tabelle mit Besucher-Prüfwerten. Keine Änderung an Lizenz-, Kauf- oder Dashboard-Datenbanken. |
| `eaf-dashboard-privacy-cleanup.*` | Benutzer-Service und Timer für tägliche Bereinigung um 00:05 UTC, unabhängig von Besuchen. |
| `test_download_statistics.py` | Migration, Wiederholbarkeit, Schutz bei falschem Schema und Import ohne Besucherkennung mit synthetischen Daten. |

Der Besucherzähler bleibt eine Verarbeitung personenbezogener Daten: Ein dauerhafter
geheimer Schlüssel wird mit Host, Tag und Verbindungs-IP verwendet. Das ist keine
tägliche Schlüsselrotation und keine garantierte Anonymisierung. Die Änderung
verhindert identische Prüfwerte derselben IP auf verschiedenen Hosts; sie macht den
Betreiber nicht technisch außerstande, eine bekannte IP mit seinem Schlüssel zu prüfen.
Tages-/Host-Summen bleiben bestehen. Gemeinsame IP-Adressen und IP-Wechsel verzerren
die Zahl weiterhin; es ist eine Schätzung, keine eindeutige Personenzählung.

Download-Anfragen beweisen weder vollständige Downloads noch Installationen.
Die neue Statistik misst deshalb keine „Unique Downloader“. Zeit, Host und Dateipfad
bleiben in den gefilterten Rohlogs; es wird nicht behauptet, jeglicher Personenbezug
sei unter allen Umständen ausgeschlossen. Der Importer ignoriert IP-Felder auch in
alten noch nicht importierten Zeilen, löscht aber keine alten Logdateien.

## Geprüfte Ausgangsbasis

- Dashboard-Quellen: `/home/asuna/analysis/eaf-dashboard` auf dem Server; relevante
  Funktionen mit laufendem Container `eaf-dashboard` unter `/app/dashboard` abgeglichen.
  Gelesenes Image: `localhost/eaf-dashboard@sha256:0c8cbd4053969a4f21948b532d516315dceecd0cbf2d9ece839b53b4558055c4`.
- Importer-Quelle `/srv/infra/ops/update_admin.py` und installierte Datei
  `/usr/local/lib/pornfetch-ops/update_admin.py` stimmen per SHA-256 überein:
  `dc6251b0614acac46bbaaa1f7930230475c9c21149001ceee8b28a91fd4ce8f3`.
- Caddy: `/etc/caddy/Caddyfile` mit Import `/etc/caddy/direct6.caddy`, Version 2.11.7.
  Beide stimmen mit `/srv/infra/msi/caddy/Caddyfile` bzw.
  `/srv/infra/msi/caddy/direct6.caddy` überein; denselben Patch auch dort übernehmen.
- Tatsächliches Dashboard-Upstream-Ziel für Besucherzählung: `127.0.0.1:18010`.
  Ältere lokale Deployment-Beispiele mit Port 8010 sind keine aktuelle Betriebsreferenz.

Vor Anwendung auf neuere Dateien jeweils `git apply --check /absoluter/pfad/zum/patch`
im passenden Quellverzeichnis ausführen. Für `caddy.patch` ist das Verzeichnis mit
`Caddyfile` und `direct6.caddy` die Wurzel; für `update-statistics.patch` das Verzeichnis
mit `update_admin.py`. Änderungen auch in den **erzeugenden Infrastrukturvorlagen**
übernehmen, falls diese die installierten Caddy-Dateien später neu schreiben.

## Geordnete Aktivierung

1. Patches zunächst in einer Arbeitskopie prüfen und Tests ausführen. Dashboard-Image
   mit gepatchtem Code bauen. Nicht lediglich die Dateien im laufenden Container ändern.
2. Wartungsfenster verwenden. `pornfetch-update-metrics.timer`, einen noch laufenden
   `pornfetch-update-metrics.service` und den Broker `pornfetch-updates.service` anhalten.
   Der Broker muss ebenfalls neu gestartet werden, weil er `stats()` im Speicher hält.
   Vorher einen letzten regulären Import abschließen, falls alle bisherigen Summen
   erhalten bleiben sollen. Parallelzugriffe während der Migration verhindern.
3. Konsistente, zugriffsgeschützte Sicherung von
   `/var/lib/pornfetch-ops/update-traffic.db` erstellen (SQLite-Backup, keine unvollständige
   Kopie einer laufenden WAL-Datenbank). Migration zuerst an einer Kopie prüfen:
   `python migrate_download_statistics.py /pfad/zur/kopie/update-traffic.db`.
   Summen vorher/nachher vergleichen. Erst danach auf der angehaltenen Arbeitsdatenbank
   ausführen. Das Skript verweigert fehlende Dateien und ein unerwartetes Altschema.
4. Gepatchten Importer an Quelle und installiertem Pfad bereitstellen. Beide
   Caddy-Konfigurationen aktualisieren und die vollständige Konfiguration im passenden
   Dienstkontext validieren. Caddy neu starten: Änderungen am vorhandenen Log-Datei-Writer
   werden laut Caddy-Dokumentation durch bloßes Reload nicht zuverlässig übernommen.
   Filter und Rotation wurden isoliert mit dem installierten Parser geprüft; das ersetzt
   keine Validierung der vollständigen Betriebsumgebung.
5. Gepatchtes Dashboard ausrollen. Die bisherigen `visitor_seen`-Zeilen enthalten noch
   die alten, hostübergreifend gleichen Prüfwerte. Bei angehaltenem Zähler diese Tabelle
   einmal gezielt leeren; `daily_usage` **behalten**. Die Umstellung möglichst am
   UTC-Tageswechsel durchführen, weil eine Leerung tagsüber bereits gezählte Besucher
   für diesen Tag nochmals zählbar macht. Keine anderen Dashboard-Tabellen löschen.
6. Die beiden Cleanup-Units als `pornfetch`-Benutzer unter dessen
   `~/.config/systemd/user/` installieren und mit `systemctl --user daemon-reload` sowie
   `systemctl --user enable --now eaf-dashboard-privacy-cleanup.timer` aktivieren.
   Einmaligen Service-Lauf und Timerstatus prüfen. Der Container muss dabei dieselbe
   `EAF_DASHBOARD_DATA_DIR`-Konfiguration verwenden wie sein Webprozess.
   Der Timer meldet Fehler, wenn der Container nicht läuft; Fehlermeldungen überwachen.
7. Neuen Collector einmal ausführen, dann Broker und Metrik-Timer wieder starten.
   Testdownload über beide Zugänge: keine IP-Prüfwerte/Quellports/TLS-Details in neuen
   Logzeilen, Summen steigen weiterhin. Zwei eigene Hosts mit synthetischer Test-IP
   prüfen: unterschiedliche Tages-Prüfwerte, keine Cookie-Antwort des Zählendpunkts.
8. Bestehende IP-haltige Download-Logs und kurzzeitig benötigte Migrationssicherungen
   nach erfolgreicher Prüfung gezielt entfernen bzw. datensparsam ersetzen. Neue Filter
   bereinigen keine historischen Logs, Snapshots oder Backups. `secure_delete`, Checkpoint
   und `VACUUM` betreffen nur die Arbeitsdatenbank, nicht SSD-Reste oder Dateisystemsnapshots.
9. Erst nach verifizierter Aktivierung die öffentliche Datenschutzerklärung nach
   `privacy-after-activation.md` umstellen. Deaktivierte Timer oder verbliebene Altbestände
   dürfen nicht als bereits gelöschte Daten dargestellt werden.

Ein technischer Rückbau erfordert zusammenpassende alte Code- und Datenbankstände.
Einfach den alten Importer über die migrierte Datenbank starten würde eine leere alte
Tabelle erzeugen und die Auswertung verfälschen. Alte personenbezogene Sicherungen
nicht vorsorglich unbegrenzt für einen möglichen Rückbau behalten.

Die Rotation `roll_interval 24h` erfolgt erst beim nächsten Schreibzugriff.
`roll_keep_for 168h` betrifft Archive und wird bei Rotation ausgewertet. Daraus folgt
auch nach dieser Änderung **keine garantierte Löschung jedes Rohlog-Eintrags exakt
nach sieben Tagen**. Eine solche Zusage würde einen zusätzlichen unabhängigen,
getesteten Löschablauf benötigen. [Caddy-Dokumentation](https://caddyserver.com/docs/caddyfile/directives/log).

## Tests

Im gepatchten Dashboard-Checkout mit ausschließlich temporärem Datenverzeichnis:

```sh
SECRET_KEY=synthetic-test-key-at-least-thirty-two-characters EAF_DASHBOARD_DATA_DIR=/tmp/dashboard-privacy-test uv run --with pytest python -m pytest tests/test_dashboard.py -k 'visit or purge' -q
```

Im Website-Repository, `UPDATE_ADMIN_CANDIDATE` auf die gepatchte **Arbeitskopie** setzen:

```sh
UPDATE_ADMIN_CANDIDATE=/pfad/zur/arbeitskopie/update_admin.py python -m unittest discover -s deploy/dashboard-privacy -p test_download_statistics.py -v
```

Ohne diese Variable wird der Importertest ausdrücklich übersprungen; die drei
Migrationstests laufen weiterhin. Keine Tests mit produktiven Daten erforderlich.
