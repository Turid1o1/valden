#!/usr/bin/env python3
import datetime as dt
import json
import os
import pathlib
import ssl
import urllib.error
import urllib.request


SCENARIOS = [
    ("LAN_LAN", "LAN ↔ LAN", "SESSION_ID_LAN_LAN"),
    ("HOME_HOME", "Дом ↔ Дом", "SESSION_ID_HOME_HOME"),
    ("HOME_MOBILE_CGNAT", "Дом ↔ Мобильная сеть (CGNAT)", "SESSION_ID_HOME_MOBILE_CGNAT"),
    ("UDP_BLOCKED", "UDP заблокирован", "SESSION_ID_UDP_BLOCKED"),
    ("TURN_FORCED", "TURN принудительно", "SESSION_ID_TURN_FORCED"),
    ("FILE_TRANSFER_5GB", "Передача 5GB", "SESSION_ID_FILE_TRANSFER_5GB"),
]


def http_get_json(url: str):
    req = urllib.request.Request(url, headers={"User-Agent": "VALDEN-matrix-runner/1.0"})
    with urllib.request.urlopen(req, timeout=20) as resp:
        body = resp.read().decode("utf-8")
        return resp.status, json.loads(body) if body else {}


def http_status(url: str):
    req = urllib.request.Request(url, headers={"User-Agent": "VALDEN-matrix-runner/1.0"})
    with urllib.request.urlopen(req, timeout=20) as resp:
        return resp.status


def now_utc_iso():
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def main():
    signal_base = os.environ.get("SIGNAL_BASE", "https://signal.valden.space").rstrip("/")
    site_base = os.environ.get("SITE_BASE", "https://valden.space").rstrip("/")

    run_id = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d-%H%M%S")
    out_dir = pathlib.Path(__file__).resolve().parent / "reports" / run_id
    out_dir.mkdir(parents=True, exist_ok=True)

    report = {
        "generated_at": now_utc_iso(),
        "signal_base": signal_base,
        "site_base": site_base,
        "baseline": {},
        "scenarios": [],
    }

    # Базовые проверки
    try:
        status, payload = http_get_json(f"{signal_base}/healthz")
        report["baseline"]["signal_healthz"] = {
            "status": "passed" if status == 200 and payload.get("status") == "ok" else "failed",
            "http_status": status,
            "payload": payload,
        }
    except Exception as exc:
        report["baseline"]["signal_healthz"] = {
            "status": "failed",
            "error": str(exc),
        }

    try:
        status = http_status(site_base)
        report["baseline"]["site_https"] = {
            "status": "passed" if status == 200 else "failed",
            "http_status": status,
        }
    except Exception as exc:
        report["baseline"]["site_https"] = {
            "status": "failed",
            "error": str(exc),
        }

    # Сбор диагностики по сценариям
    for code, name, env_key in SCENARIOS:
        session_id = os.environ.get(env_key, "").strip()
        item = {
            "code": code,
            "name": name,
            "session_id": session_id or None,
            "status": "blocked",
            "notes": "",
            "diagnostics_file": None,
        }

        if not session_id:
            item["notes"] = f"Отсутствует {env_key}. Укажите реальный session_id из завершённого прогона для этой топологии."
            report["scenarios"].append(item)
            continue

        diag_path = out_dir / f"{code.lower()}-diagnostics.json"
        try:
            status, payload = http_get_json(f"{signal_base}/v1/diagnostics/session/{session_id}")
            with diag_path.open("w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False, indent=2)

            events = payload.get("events", [])
            item["diagnostics_file"] = str(diag_path)
            item["event_count"] = len(events)
            if status == 200 and isinstance(events, list) and len(events) > 0:
                item["status"] = "collected"
                item["notes"] = "Диагностика собрана. Сверьте транспорт и целостность вручную с целями сценария."
            else:
                item["status"] = "failed"
                item["notes"] = f"Неожиданный ответ диагностики (status={status})."
        except Exception as exc:
            item["status"] = "failed"
            item["notes"] = f"Не удалось получить диагностику: {exc}"

        report["scenarios"].append(item)

    json_path = out_dir / "matrix-report.json"
    with json_path.open("w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    status_label = {
        "passed": "успех",
        "failed": "ошибка",
        "blocked": "заблокировано",
        "collected": "собрано",
        "unknown": "неизвестно",
    }

    md_lines = [
        "# Отчёт сетевой матрицы VALDEN",
        "",
        f"- Сформирован: `{report['generated_at']}`",
        f"- Сигналинг: `{signal_base}`",
        f"- Сайт: `{site_base}`",
        "",
        "## Базовые проверки",
        "",
        "- signal `/healthz`: "
        f"`{status_label.get(report['baseline'].get('signal_healthz', {}).get('status', 'unknown'), 'неизвестно')}`",
        "- HTTPS сайта: "
        f"`{status_label.get(report['baseline'].get('site_https', {}).get('status', 'unknown'), 'неизвестно')}`",
        "",
        "## Сценарии",
        "",
        "| Сценарий | Статус | Session ID | Примечания |",
        "|---|---|---|---|",
    ]

    for item in report["scenarios"]:
        sid = item["session_id"] or "-"
        notes = item["notes"].replace("|", "\\|")
        md_lines.append(
            f"| {item['name']} | `{status_label.get(item['status'], item['status'])}` | `{sid}` | {notes} |"
        )

    md_path = out_dir / "matrix-report.md"
    md_path.write_text("\n".join(md_lines) + "\n", encoding="utf-8")

    print(str(json_path))
    print(str(md_path))


if __name__ == "__main__":
    # По умолчанию проверка HTTPS-сертификата включена.
    ssl.create_default_context()
    main()
