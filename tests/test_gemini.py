from masxai import constants as C
from masxai.gemini import baseline_forecast, gemini_timeout
from masxai.protocol import ForecastSynapse


def test_baseline_forecast_is_no_answer():
    synapse = ForecastSynapse(forecast_id="f-1", event_type="significant_bittensor_event")

    forecast = baseline_forecast(synapse)

    assert forecast["forecast_id"] == "f-1"
    assert forecast["prediction"] is None
    assert forecast["confidence"] is None
    assert forecast["probability"] is None


def test_gemini_timeout_defaults_when_unset(monkeypatch):
    monkeypatch.delenv("GEMINI_TIMEOUT", raising=False)

    assert gemini_timeout() == float(C.GEMINI_TIMEOUT)


def test_gemini_timeout_uses_valid_override(monkeypatch):
    monkeypatch.setenv("GEMINI_TIMEOUT", "12.5")

    assert gemini_timeout() == 12.5


def test_gemini_timeout_falls_back_on_malformed_value(monkeypatch):
    monkeypatch.setenv("GEMINI_TIMEOUT", "not-a-number")

    assert gemini_timeout() == float(C.GEMINI_TIMEOUT)


def test_gemini_timeout_falls_back_on_non_positive_value(monkeypatch):
    monkeypatch.setenv("GEMINI_TIMEOUT", "0")
    assert gemini_timeout() == float(C.GEMINI_TIMEOUT)

    monkeypatch.setenv("GEMINI_TIMEOUT", "-5")
    assert gemini_timeout() == float(C.GEMINI_TIMEOUT)
