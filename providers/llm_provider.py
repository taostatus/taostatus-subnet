from __future__ import annotations

"""Gemini-backed local task generation with strict JSON parsing."""

import json
from typing import Any

from config import Settings
from models import as_utc, utcnow
from providers.base import ProviderTask


class LLMTaskProvider:
    def __init__(self, settings: Settings):
        self.settings = settings

    async def fetch_tasks(self) -> list[ProviderTask]:
        try:
            from google import genai
            from google.genai import types
        except Exception as exc:
            raise RuntimeError(
                "TASK_SOURCE=llm requires the google-genai package to be installed"
            ) from exc

        client = genai.Client(api_key=self.settings.gemini_api_key)
        prompt = self._prompt()
        response = await client.aio.models.generate_content(
            model=self.settings.gemini_model,
            contents=prompt,
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                temperature=0.7,
            ),
        )
        raw_text = response.text or ""
        payload = json.loads(raw_text)
        if not isinstance(payload, dict) or not isinstance(payload.get("tasks"), list):
            raise ValueError("Gemini response must be a JSON object with a tasks array")
        return [self._normalize_task(item) for item in payload["tasks"]]

    def _prompt(self) -> str:
        categories = ", ".join(self.settings.llm_task_category_mix)
        return (
            "Generate Bittensor-focused binary forecasting tasks as strict JSON only. "
            "Do not include markdown, prose, or code fences. "
            "Return exactly this shape: "
            '{"tasks":[{"task_id":"llm-unique-id","question":"...","category":"...",'
            '"deadline":"2026-08-01T00:00:00Z","resolution_hint":"...",'
            '"schema_version":"1.0","created_at":"...","updated_at":"..."}]}. '
            f"Generate {self.settings.llm_tasks_per_batch} tasks across: {categories}. "
            "Every question must be about Bittensor, TAO, subnet registrations, "
            "subnet emissions, validator/miner behavior, metagraph changes, on-chain "
            "governance, or Bittensor ecosystem milestones. "
            "Each question must have a binary yes/no outcome, a future UTC deadline, "
            "and a resolution_hint that names an objective source such as subtensor "
            "chain state, metagraph data, official Bittensor governance records, "
            "or a public TAO market data source."
        )

    def _normalize_task(self, item: dict[str, Any]) -> ProviderTask:
        return ProviderTask(
            task_id=str(item["task_id"]),
            question=str(item["question"]),
            category=str(item.get("category") or "general"),
            deadline=as_utc(item["deadline"]),
            resolution_hint=str(item.get("resolution_hint") or ""),
            source="llm",
            schema_version=str(item.get("schema_version") or "1.0"),
            created_at=as_utc(item.get("created_at")) or utcnow(),
            updated_at=as_utc(item.get("updated_at")) or utcnow(),
        )
