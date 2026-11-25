# kore-plugin-integrity (плагин целостности критических файлов)

## Что делает плагин

Создаёт контрольную сумму sha256 для критических файлов и по запросу сравнивает её, сообщая об изменённых, добавленных или удалённых файлах. Плагин только читает файлы и вычисляет хэши и метаданные: он никогда не читает содержимое, не изменяет проверяемые файлы, не повышает привилегии и не отправляет события. depth_level=basic, lifecycle=lazy, протокол kore.plugin.v1.

Методы чтения объявляют system:read; baseline, restore и schedule.set объявляют system:admin; на уровне плагина — system:read + system:admin (уровень метода только сужает права, никогда не расширяет).

## Ключевые моменты

- Единственная внешняя зависимость: github.com/pengtang1024/kore/pkg/pluginapi v0.1.1; остальное — стандартная библиотека.
- Ресурсы: memory_mb 6, cpu_quota 10%, pids_max 16; потоковое хэширование keeps резидентную память независимой от размера файла.
- Методы: baseline, baseline.list, restore, check, status, verify_file, schedule.set, schedule.get (полные таблицы параметров в DETAIL.md; имена методов и поля JSON не зависят от языка).
- Оповещения: file_removed и file_modified (critical), file_added и scan_incomplete (warning); возвращаются только в alerts[], не отправляются внешне.

## Установка и проверка

Установите `integrity` из маркетплейса плагинов или импортируйте dist/integrity-0.6.0.tar.gz, собранный через make dist. Проверка: make check (gofmt, go vet, go test -timeout 200s).

---

简体中文原文见 [DETAIL.md](DETAIL.md)。
