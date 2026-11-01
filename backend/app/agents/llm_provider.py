import json
import logging
from typing import Dict, Any, Optional
from app.config import settings

logger = logging.getLogger("sentinel.llm")

class ModularLLMProvider:
    def __init__(self):
        self.mode = "mock"
        if settings.OPENAI_API_KEY and settings.LLM_PROVIDER == "openai":
            try:
                from openai import OpenAI
                self.client = OpenAI(api_key=settings.OPENAI_API_KEY)
                self.mode = "openai"
                logger.info(f"Initialized OpenAI provider with model {settings.OPENAI_MODEL}")
            except Exception as e:
                logger.warning(f"Failed to initialize OpenAI client: {e}. Falling back to structured mock mode.")
                self.mode = "mock"
        else:
            self.mode = "mock"

    def generate_chat(self, system_prompt: str, user_prompt: str, response_format_schema: Optional[Dict[str, Any]] = None) -> str:
        """
        Executes LLM request via OpenAI or fallback mock reasoning engine.
        """
        if self.mode == "openai":
            try:
                messages = [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ]
                kwargs = {
                    "model": settings.OPENAI_MODEL,
                    "messages": messages,
                    "temperature": 0.1
                }
                if response_format_schema:
                    kwargs["response_format"] = {"type": "json_object"}

                completion = self.client.chat.completions.create(**kwargs)
                return completion.choices[0].message.content or ""
            except Exception as e:
                logger.error(f"OpenAI completion call error: {e}. Falling back to mock reasoning.")

        # In mock mode, callers use structured deterministic reasoning helpers
        return ""

llm_provider = ModularLLMProvider()
