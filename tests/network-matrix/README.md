# Запуск сетевой матрицы

В этой папке находятся инструменты для сбора диагностики по матрице приёмки VALDEN:

- `LAN ↔ LAN`
- `Дом ↔ Дом`
- `Дом ↔ Мобильная сеть (CGNAT)`
- `UDP заблокирован`
- `TURN принудительно`
- `Передача 5GB`

## Использование

Запуск базовых проверок и сбор диагностики по сценариям, где уже есть `session_id`:

```bash
python3 tests/network-matrix/run_matrix.py
```

Для сбора конкретных сценариев передайте переменные окружения:

```bash
SESSION_ID_TURN_FORCED="<session-id>" \
SESSION_ID_FILE_TRANSFER_5GB="<session-id>" \
python3 tests/network-matrix/run_matrix.py
```

Опциональные endpoint-адреса:

```bash
SIGNAL_BASE="https://signal.valden.space" SITE_BASE="https://valden.space" python3 tests/network-matrix/run_matrix.py
```

## Выходные файлы

Артефакты сохраняются в:

`tests/network-matrix/reports/<метка-времени-UTC>/`

- `matrix-report.json`
- `matrix-report.md`
- диагностические JSON-файлы по каждому сценарию, если передан `session_id`

## Важно

Скрипт не подделывает результаты сценариев. Если для сценария не указан реальный `session_id`, он помечается как `заблокировано`.
