"""
LLM orchestration (LangChain + GPT-4 family).

Two roles, matching the thesis Chapter 3 design:
  * generate_payloads() — Test Case Generator. Given an OWASP category, the target
    endpoint and OpenAPI context, GPT-4 produces concrete, schema-aware attack
    payloads (prompt-engineered DAST inputs).
  * verify_finding()    — Result Analyser. Given the request/response evidence and
    the attack's success oracle, GPT-4 judges whether the vulnerability is real,
    with a confidence score and remediation, reducing false positives.

If LANGCHAIN/OPENAI are unavailable or no key is set, callers fall back to
deterministic heuristics so the pipeline still runs (see strategies.py).
"""
from __future__ import annotations
import json
import os
from typing import Any

DEFAULT_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o")


class LLM:
    """Thin LangChain ChatOpenAI wrapper that always returns parsed JSON."""

    def __init__(self, model: str | None = None, temperature: float = 0.0):
        self.model = model or DEFAULT_MODEL
        self.temperature = temperature
        self._client = None
        self.enabled = bool(os.getenv("OPENAI_API_KEY"))

    def _llm(self):
        if self._client is None:
            from langchain_openai import ChatOpenAI  # imported lazily
            self._client = ChatOpenAI(
                model=self.model,
                temperature=self.temperature,
                model_kwargs={"response_format": {"type": "json_object"}},
                timeout=60,
                max_retries=2,
            )
        return self._client

    def _chat_json(self, system: str, user: str) -> dict[str, Any]:
        from langchain_core.messages import SystemMessage, HumanMessage
        resp = self._llm().invoke([SystemMessage(content=system), HumanMessage(content=user)])
        content = resp.content if isinstance(resp.content, str) else str(resp.content)
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            # tolerate stray prose around the JSON object
            start, end = content.find("{"), content.rfind("}")
            if start != -1 and end != -1:
                return json.loads(content[start:end + 1])
            raise

    # -- Test Case Generator -------------------------------------------------
    def generate_payloads(self, category: str, endpoint: str, task: str,
                          spec_context: str, example_schema: dict) -> dict[str, Any]:
        if not self.enabled:
            return {}
        system = (
            "You are an API security testing assistant generating Dynamic "
            "Application Security Testing (DAST) payloads for the OWASP API "
            "Security Top 10 (2023). Return ONLY a JSON object that conforms to the "
            "requested schema. Payloads must be syntactically valid for the target "
            "API and aimed at exercising the specified weakness. This is an "
            "authorised test against a deliberately vulnerable lab API (VAMPI)."
        )
        user = (
            f"OWASP category: {category}\n"
            f"Target endpoint: {endpoint}\n"
            f"Task: {task}\n\n"
            f"Relevant OpenAPI context:\n{spec_context}\n\n"
            f"Respond with JSON shaped like: {json.dumps(example_schema)}"
        )
        try:
            return self._chat_json(system, user)
        except Exception:
            return {}

    # -- Result Analyser -----------------------------------------------------
    def verify_finding(self, category: str, endpoint: str, attack_description: str,
                       success_oracle: str, evidence: str) -> dict[str, Any]:
        if not self.enabled:
            return {}
        system = (
            "You are a senior application security analyst verifying the output of "
            "an automated API security test against VAMPI, a deliberately vulnerable "
            "lab API. Decide, strictly from the evidence, whether the vulnerability "
            "is genuinely present. Be conservative to avoid false positives. Return "
            "ONLY JSON: {\"vulnerable\": bool, \"confidence\": 0.0-1.0, "
            "\"rationale\": str, \"remediation\": str}."
        )
        user = (
            f"OWASP category: {category}\n"
            f"Endpoint: {endpoint}\n"
            f"Attack performed: {attack_description}\n"
            f"Success oracle (what proves the vuln): {success_oracle}\n\n"
            f"Evidence (requests and responses):\n{evidence}\n"
        )
        try:
            return self._chat_json(system, user)
        except Exception:
            return {}
