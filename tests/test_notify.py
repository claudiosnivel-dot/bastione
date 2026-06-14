"""Test del package `bastione/notify/` (§19) — il NOTIFIER, canale Telegram (O01).

Tutto OFFLINE: il confine I/O verso l'API Telegram (`_send_message`) è
monkeypatchato e NON tocca mai la rete. I test coprono:

- la registrazione (`register_notifier` popola `NOTIFIERS`) e il dispatch che
  sceglie il notifier per nome di canale;
- `build_run_summary` che mappa counts/drift_count/report_path dai dati della run;
- `TelegramNotifier.send`: con env presenti chiama `_send_message` con un testo
  compatto che cita target/score/#NEW/#DRIFT/link al report; con env assenti è un
  no-op loggato (niente crash, nessuna POST);
- la RESILIENZA di `dispatch`: canale ignoto / send che solleva → loggato come
  warning e NON propaga (la notifica è best-effort, la run è già riuscita);
- P8: nessun segreto grezzo nel messaggio.
"""

from __future__ import annotations

import logging

import pytest

from bastione.models import RunSummary, TargetConfig
from bastione.notify.base import (
    NOTIFIERS,
    Notifier,
    build_run_summary,
    dispatch,
    register_notifier,
)
from bastione.notify.telegram import (
    BOT_TOKEN_ENV,
    CHAT_ID_ENV,
    TelegramNotifier,
)
from bastione.notify import telegram as telegram_mod


def _cfg(channel: str = "telegram") -> TargetConfig:
    return TargetConfig(
        name="g",
        base_url="https://staging.example",
        environment="staging",
        ownership="owned",
        notify_channel=channel,
    )


def _summary(**over) -> RunSummary:
    base = dict(
        target="g",
        posture_score=87.5,
        counts={
            "new": 2, "known": 1, "fixed": 0, "drift": 1,
            "by_severity": {"critical": 0, "high": 1, "medium": 1, "low": 0, "info": 0},
            "new_by_severity": {"critical": 0, "high": 1, "medium": 1, "low": 0, "info": 0},
        },
        drift_count=1,
        report_path="runs/g/20260614T000000_000000Z/report.html",
    )
    base.update(over)
    return RunSummary(**base)


# ─── registry + dispatch ─────────────────────────────────────────────────────

def test_telegram_is_registered():
    # L'import di notify.telegram registra "telegram" via @register_notifier.
    assert "telegram" in NOTIFIERS
    assert NOTIFIERS["telegram"] is TelegramNotifier


def test_register_notifier_populates_registry():
    @register_notifier
    class _Dummy(Notifier):
        channel = "dummy-test"

        def send(self, summary):  # pragma: no cover - non invocato qui
            pass

    assert NOTIFIERS.get("dummy-test") is _Dummy
    # pulizia: non lasciare il canale fittizio nel registry globale
    NOTIFIERS.pop("dummy-test", None)


def test_dispatch_selects_telegram(monkeypatch):
    sent = {}

    def _fake_send(self, summary):
        sent["target"] = summary.target

    monkeypatch.setattr(TelegramNotifier, "send", _fake_send, raising=True)
    dispatch(_cfg("telegram"), _summary())
    assert sent.get("target") == "g"


# ─── build_run_summary ───────────────────────────────────────────────────────

def test_build_run_summary_maps_fields():
    counts = {
        "new": 3, "known": 0, "fixed": 1, "drift": 2,
        "by_severity": {"critical": 1, "high": 2, "medium": 0, "low": 0, "info": 0},
        "new_by_severity": {"critical": 1, "high": 2, "medium": 0, "low": 0, "info": 0},
    }
    summary = build_run_summary(
        target="g",
        posture_score=42.0,
        counts=counts,
        report_path="runs/g/ts/report.html",
    )
    assert isinstance(summary, RunSummary)
    assert summary.target == "g"
    assert summary.posture_score == 42.0
    assert summary.counts == counts
    assert summary.drift_count == 2            # derivato da counts["drift"]
    assert summary.report_path == "runs/g/ts/report.html"


def test_build_run_summary_drift_defaults_zero():
    counts = {"new": 0, "known": 0, "fixed": 0,
              "by_severity": {}, "new_by_severity": {}}  # senza chiave "drift"
    summary = build_run_summary(
        target="g", posture_score=100.0, counts=counts, report_path="r.html")
    assert summary.drift_count == 0


# ─── TelegramNotifier.send: confine monkeypatchato ───────────────────────────

def test_send_with_env_calls_boundary(monkeypatch):
    captured = {}

    def _fake_send_message(token, chat_id, text):
        captured["token"] = token
        captured["chat_id"] = chat_id
        captured["text"] = text

    monkeypatch.setenv(BOT_TOKEN_ENV, "secret-bot-token-123")
    monkeypatch.setenv(CHAT_ID_ENV, "999")
    monkeypatch.setattr(telegram_mod, "_send_message", _fake_send_message, raising=True)

    TelegramNotifier().send(_summary())

    assert captured["token"] == "secret-bot-token-123"
    assert captured["chat_id"] == "999"
    text = captured["text"]
    # Contenuto compatto §19: target, score, #NEW, #DRIFT, link al report.
    assert "g" in text
    assert "87.5" in text
    assert "2" in text                          # #NEW totale
    assert "DRIFT" in text or "drift" in text
    assert "report.html" in text


def test_send_message_text_breaks_new_by_severity(monkeypatch):
    # §19: il messaggio mostra i NEW per severità (almeno le severità con conteggio).
    captured = {}
    monkeypatch.setenv(BOT_TOKEN_ENV, "t")
    monkeypatch.setenv(CHAT_ID_ENV, "1")
    monkeypatch.setattr(
        telegram_mod, "_send_message",
        lambda token, chat_id, text: captured.__setitem__("text", text),
        raising=True)
    TelegramNotifier().send(_summary())
    text = captured["text"].lower()
    assert "high" in text                       # 1 NEW high → citato nel breakdown


def test_send_without_env_is_noop(monkeypatch, caplog):
    # Env assenti → no-op + warning, nessuna POST, nessun crash.
    monkeypatch.delenv(BOT_TOKEN_ENV, raising=False)
    monkeypatch.delenv(CHAT_ID_ENV, raising=False)

    called = {"n": 0}

    def _boom(*a, **k):  # non deve mai essere chiamato
        called["n"] += 1
        raise AssertionError("la POST non deve partire senza env")

    monkeypatch.setattr(telegram_mod, "_send_message", _boom, raising=True)

    with caplog.at_level(logging.WARNING):
        TelegramNotifier().send(_summary())   # NON deve sollevare

    assert called["n"] == 0
    assert any("telegram" in r.message.lower() or "BASTIONE_TELEGRAM" in r.message
               for r in caplog.records)


def test_send_no_secret_token_in_message(monkeypatch):
    # P8: il BOT_TOKEN (un segreto) non deve MAI finire nel testo del messaggio.
    captured = {}
    monkeypatch.setenv(BOT_TOKEN_ENV, "SUPER-SECRET-TOKEN-XYZ")
    monkeypatch.setenv(CHAT_ID_ENV, "1")
    monkeypatch.setattr(
        telegram_mod, "_send_message",
        lambda token, chat_id, text: captured.__setitem__("text", text),
        raising=True)
    TelegramNotifier().send(_summary())
    assert "SUPER-SECRET-TOKEN-XYZ" not in captured["text"]


# ─── resilienza del dispatch ─────────────────────────────────────────────────

def test_dispatch_unknown_channel_does_not_raise(caplog):
    # Canale ignoto → loggato come warning, nessuna eccezione propagata.
    with caplog.at_level(logging.WARNING):
        dispatch(_cfg("carrier-pigeon"), _summary())   # NON deve sollevare
    assert any("carrier-pigeon" in r.message or "canale" in r.message.lower()
               for r in caplog.records)


def test_dispatch_channel_none_is_silent(monkeypatch):
    # channel "none": dispatch è un no-op silenzioso (nessun notifier istanziato).
    def _boom(self, summary):  # pragma: no cover
        raise AssertionError("nessun send con channel=none")

    monkeypatch.setattr(TelegramNotifier, "send", _boom, raising=True)
    dispatch(_cfg("none"), _summary())   # NON deve sollevare né chiamare send


def test_dispatch_send_raises_is_swallowed(monkeypatch, caplog):
    # Un send che solleva (rete giù, env corrotto, …) → loggato, NON propaga.
    def _boom(self, summary):
        raise RuntimeError("rete giù")

    monkeypatch.setattr(TelegramNotifier, "send", _boom, raising=True)
    with caplog.at_level(logging.WARNING):
        dispatch(_cfg("telegram"), _summary())   # NON deve sollevare
    assert any(r.levelno >= logging.WARNING for r in caplog.records)


def test_send_message_degrades_if_httpx_post_fails(monkeypatch, caplog):
    # Il confine reale `_send_message` deve degradare con grazia se la POST fallisce
    # (httpx assente o errore di rete): logga e ritorna, NON solleva.
    class _FakeHttpxError(Exception):
        pass

    class _FakeHttpx:
        HTTPError = _FakeHttpxError

        @staticmethod
        def post(*a, **k):
            raise _FakeHttpxError("connessione rifiutata")

    monkeypatch.setitem(__import__("sys").modules, "httpx", _FakeHttpx)
    with caplog.at_level(logging.WARNING):
        # non deve sollevare nemmeno chiamando il confine reale
        telegram_mod._send_message("tok", "1", "ciao")
    assert any(r.levelno >= logging.WARNING for r in caplog.records)
