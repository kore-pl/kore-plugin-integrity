# kore-plugin-integrity (Plugin für die Integrität kritischer Dateien)

## Was es tut

Erstellt eine sha256-Baseline kritischer Dateien und vergleicht sie bei Bedarf, um geänderte, hinzugefügte oder gelöschte Dateien zu melden. Das Plugin liest nur Dateien und berechnet Hashes und Metadaten: es liest niemals Dateiinhalte, verändert keine geprüften Dateien, erhöht keine Berechtigungen und sendet keine Ereignisse. depth_level=basic, lifecycle=lazy, Protokoll kore.plugin.v1.

Lesemethoden deklarieren system:read; baseline, restore und schedule.set deklarieren system:admin; auf Plugin-Ebene system:read + system:admin (Methodenebene verengt nur, sie erweitert nie).

## Wichtige Punkte

- Einzige Fremdabhängigkeit: github.com/pengtang1024/kore/pkg/pluginapi v0.1.1; alles andere ist die Standardbibliothek.
- Ressourcen: memory_mb 6, cpu_quota 10 %, pids_max 16; Streaming-Hashing hält den Speicher unabhängig von der Dateigröße.
- Methoden: baseline, baseline.list, restore, check, status, verify_file, schedule.set, schedule.get (vollständige Parametertabellen in DETAIL.md; Methodennamen und JSON-Felder sind sprachneutral).
- Warnungen: file_removed und file_modified (critical), file_added und scan_incomplete (warning); nur in alerts[] zurückgegeben, nie extern versendet.

## Installation und Prüfung

Installieren Sie `integrity` über den Plugin-Markt oder importieren Sie das mit make dist erzeugte dist/integrity-0.6.0.tar.gz. Prüfen Sie mit make check (gofmt, go vet, go test -timeout 200s).

---

简体中文原文见 [DETAIL.md](DETAIL.md)。
