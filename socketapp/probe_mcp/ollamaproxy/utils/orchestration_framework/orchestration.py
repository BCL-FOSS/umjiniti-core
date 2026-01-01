import asyncio
import logging

logger = logging.getLogger(__name__)


class Worker:
    def __init__(self, name, tools=None, tool_params=None):
        """
        A worker represents a single agent node in the flow.
        - name: Agent node ID
        - tools: dict mapping tool names to callable functions (e.g., {"flow_call_mcp": flow_call_mcp})
        - prompt: text prompt for context (not used here for orchestration)
        - tool_params: dict mapping tool names to argument payloads
        - model: optional (for compatibility)
        """
        self.name = name
        self.tools = tools or {}
        self.tool_params = tool_params or {}

    async def execute(self):
        """
        Executes the worker's assigned tools sequentially (only one tool per worker in this flow).
        """
        results = {}
        for tool_name, tool_func in self.tools.items():
            params = self.tool_params.get(tool_name)
            if not params:
                logger.warning(f"[Worker:{self.name}] No params for tool '{tool_name}'. Skipping.")
                continue

            logger.info(f"[Worker:{self.name}] Running tool: {tool_name}")
            try:
                # Each param set can be a list of tool call payloads
                if isinstance(params, list):
                    all_tool_results = []
                    for p in params:
                        if asyncio.iscoroutinefunction(tool_func):
                            result = await tool_func(**p)
                        else:
                            result = tool_func(**p)
                        all_tool_results.append(result)
                    results[tool_name] = all_tool_results
                else:
                    if asyncio.iscoroutinefunction(tool_func):
                        result = await tool_func(**params)
                    else:
                        result = tool_func(**params)
                    results[tool_name] = result

            except Exception as e:
                logger.error(f"[Worker:{self.name}] Error executing {tool_name}: {e}", exc_info=True)
                results[tool_name] = {"error": str(e)}

        logger.info(f"[Worker:{self.name}] Finished execution.")
        return results


class Supervisor:
    def __init__(self, workers):
        """
        Supervisor executes all workers sequentially according to static_graph.
        - workers: list of Worker objects
        - supervisor_prompt: optional string, not used here for orchestration
        """
        self.workers = {worker.name: worker for worker in workers}

    async def orchestrate(self, static_graph):
        """
        Execute workers in the order provided by static_graph.
        """
        results = {}
        logger.info("[Supervisor] Starting sequential execution of static graph.")

        static_graph = static_graph or list(self.workers.keys())

        for node_id in static_graph:
            worker = self.workers.get(str(node_id))
            if not worker:
                logger.warning(f"[Supervisor] No worker found for node {node_id}. Skipping.")
                continue

            logger.info(f"[Supervisor] Executing worker: {worker.name}")
            worker_result = await worker.execute()
            results[worker.name] = worker_result

        logger.info("[Supervisor] Workflow execution complete.")
        return results
