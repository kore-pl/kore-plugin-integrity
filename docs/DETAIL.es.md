# kore-plugin-integrity (plugin de integridad de archivos críticos)

## Qué hace

Crea una línea base sha256 de archivos críticos y los compara cuando se solicita, informando de archivos modificados, añadidos o eliminados. El plugin solo lee archivos y calcula hashes y metadatos: nunca lee contenidos, modifica archivos escaneados, eleva privilegios ni emite eventos. depth_level=basic, lifecycle=lazy, protocolo kore.plugin.v1.

Los métodos de lectura declaran system:read; baseline, restore y schedule.set declaran system:admin; a nivel de plugin se declara system:read + system:admin (la restricción por método nunca amplía el permiso).

## Puntos clave

- Única dependencia externa: github.com/pengtang1024/kore/pkg/pluginapi v0.1.1; el resto es biblioteca estándar.
- Recursos: memory_mb 6, cpu_quota 10%, pids_max 16; el hash por flujos mantiene la memoria residente independiente del tamaño del archivo.
- Métodos: baseline, baseline.list, restore, check, status, verify_file, schedule.set, schedule.get (las tablas completas de parámetros están en DETAIL.md; nombres de método y campos JSON son neutrales al idioma).
- Alertas: file_removed y file_modified (critical), file_added y scan_incomplete (warning); solo se devuelven en alerts[], nunca se envían.

## Instalación y verificación

Instale `integrity` desde el mercado de plugins o importe dist/integrity-0.6.0.tar.gz generado con make dist. Verifique con make check (gofmt, go vet, go test -timeout 200s).

---

简体中文原文见 [DETAIL.md](DETAIL.md)。
