import os
import json
import httpx
import logging

class LLMWorker:
    def __init__(self, name, model="qwen3:1.7b", tools=None, prompt=None, tool_params=None):
        self.name = name
        self.model = model
        self.tools = tools or {}
        self.prompt = prompt
        self.tool_params = tool_params or {}
        self.OLLAMA_URL = "http://ollama:11434/api/chat"
        logging.basicConfig(level=logging.DEBUG)
        self.logger = logging.getLogger(__name__)

    async def llm(self, messages):
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                self.OLLAMA_URL,
                json={"model": self.model, "messages": messages, "stream": False},
                timeout=int(os.environ.get("REQUEST_TIMEOUT", 60)),
            )
            resp_data = resp.json()["message"]["content"]
            resp.aclose()
            return resp_data

    async def act(self, incoming_message=None):
        messages = []
        if self.prompt:
            messages.append({"role": "system", "content": self.prompt})

        # Skip if incoming message already contains a tool_result
        #if incoming_message and "tool_result" in incoming_message:
        #    self.logger.debug(f"{self.name}: Skipping duplicate tool call, already has tool_result.")
        #    return [{"type": "pass_through", "worker": self.name, "content": incoming_message, "complete": True}]

        if incoming_message:
            messages.append({
                "role": "user",
                "content": (
                    f"Upstream result from MCP or tool agents to analyze:\n{incoming_message}\n"
                    "If a tool call is required, output TOOL:<toolname>:<json args>. "
                    "Otherwise summarize and mark complete."
                )
            })
        else:
            messages.append({"role": "user", "content": "Start your assigned workflow task."})

        llm_output = await self.llm(messages)
        self.logger.debug(f"{self.name} LLM output: {llm_output}")

        if llm_output.startswith("TOOL:"):
            try:
                _, tool_name, tool_args_str = llm_output.split(":", 2)
                tool_name = tool_name.strip()
                tool_args = json.loads(tool_args_str) if tool_args_str.strip() else {}
            except Exception:
                self.logger.warning(f"{self.name}: Tool parsing failed, skipping.")
                return [{"type": "pass_through", "worker": self.name, "content": incoming_message, "complete": True}]

            if tool_name in self.tools:
                result = await self.tools[tool_name](**tool_args)
                self.logger.info(f"{self.name}: Tool '{tool_name}' executed successfully.")
                return [{
                    "type": "tool_result",
                    "worker": self.name,
                    "tool": tool_name,
                    "args": tool_args,
                    "result": result,
                    "complete": True
                }]
            else:
                self.logger.warning(f"{self.name}: Tool '{tool_name}' not found.")
                return [{"type": "pass_through", "worker": self.name, "content": incoming_message, "complete": True}]
        else:
            # No tool call detected, just return text
            return [{"type": "pass_through", "worker": self.name, "content": llm_output, "complete": True}]
