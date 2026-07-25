from masxai.gemini import baseline_forecast
from masxai.protocol import ForecastSynapse


def test_baseline_forecast_is_no_answer():
    synapse = ForecastSynapse(forecast_id="f-1", event_type="significant_bittensor_event")

    forecast = baseline_forecast(synapse)

    assert forecast["forecast_id"] == "f-1"
    assert forecast["prediction"] is None
    assert forecast["confidence"] is None
    assert forecast["probability"] is None
