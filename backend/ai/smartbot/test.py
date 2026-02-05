@app.route("/v1/tools", methods=["POST"])
async def tools():
    data = await request.get_json()
    logger.info(f"Incoming request: {data}")

    model = data.get("model")
    instructions = data.get("instructions")
    user_input = data.get("usr_input")
    tools = data.get("tools")
    user = data.get("user")
    api_key = data.get("api_key")
    headers['x-api-key'] = api_key
    logger.info(headers)

    # --- Step A: Collect tool schemas from MCP servers ---
    tool_schemas = []
    for t in tools:
        if t.get("type") == "mcp":
            mcp_tools = await fetch_mcp_tools(server_url=t["server_url"])
            if mcp_tools is None:
                return {'Error': f"Failed to fetch tools from {t['server_url']}"}
            for tool in mcp_tools:
                tool_schemas.append({
                    "server_label": t["server_label"],
                    "server_url": t["server_url"],
                    "schema": tool
                })

    logger.info(tool_schemas)
    # --- Step B: Build tool instructions for the LLM ---
    tool_instructions = ""
    if tool_schemas:
        tool_instructions += (
            "You have access to the following tools. "
            "When using them, respond ONLY with a JSON object in this format:\n"
            '{"name": "<tool_name>", "arguments": {"param1": "value1", "param2": "value2"}}\n\n'
            "Arguments must always be concrete values, not schemas or descriptions.\n\n"
            "✅ Valid example:\n"
            '{"name": "controller_system_data", "arguments": {"user": "hollow", "ip": "ubnt.baughcl.tech"}}\n\n'
            "❌ Invalid example:\n"
            '{"name": "controller_system_data", "arguments": [{"properties": {"user": {...}, "ip": {...}}}]}\n\n'
            "Available tools:\n"
        )
        for ts in tool_schemas:
            sch = ts["schema"]
            tool_instructions += f"- {sch['name']}: {sch['description']}\n"
            tool_instructions += f"  Parameters: {json.dumps(sch['inputSchema'])}\n"

    # --- Step C: Send conversation to Ollama ---
    conversation = [
        {"role": "system", "content": instructions + "\n" + tool_instructions},
        {"role": "user", "content": user_input},
    ]

    async with httpx.AsyncClient() as client:
        resp = await client.post(
            OLLAMA_URL,
            json={"model": model, "messages": conversation, "stream": False},
            timeout=int(os.environ.get('REQUEST_TIMEOUT')),
        )
      
        ollama_json = resp.json()
        ollama_out = ollama_json.get("message", {}).get("content", "")
        logger.info(f"Ollama output (raw): {ollama_out}")
        #await resp.aclose()

    # --- Step D: Parse model output ---
    ollama_out_clean = clean_ollama_output(ollama_out)

    if 'model trained and developed by Baugh Consulting & Lab L.L.C.'.lower() in ollama_out_clean.lower():
        logger.info(tools[0].get('server_url'))

        response_payload={
            "id": f"resp:{user}:{tools[0].get('server_url')}:{datetime.now(timezone.utc)}:{uuid.uuid4()}",
            "user_msg": user_input,
            "output_text": ollama_out_clean
        }

        logger.info(response_payload)

        return jsonify(response_payload)

    parsed = None
    try:
        parsed = json.loads(ollama_out_clean)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", ollama_out_clean, re.S)
        if match:
            try:
                parsed = json.loads(match.group())
            except Exception as e:
                logger.warning(f"Could not parse JSON block: {e}")

    # --- Step E: Handle tool calls with retry on bad format ---
    tool_outputs = []
    final_output = ""

    def is_valid_arguments(obj):
        return isinstance(obj.get("arguments", {}), dict)

    # Helper: re-prompt Ollama when output is invalid
    async def retry_with_clarification(conversation, reason, bad_output):
        logger.warning(f"Bad tool call output detected. Reason: {reason}")
        logger.warning(f"--- BAD OUTPUT ---\n{bad_output}\n-----------------")

        conversation.append({
            "role": "system",
            "content": (
                f"Your previous output could not be parsed because: {reason}. "
                "Please retry by returning ONLY a JSON object with concrete argument values, like:\n"
                '{"name": "tool_name", "arguments": {"param": "value"}}\n'
                "Do NOT return schemas, descriptions, or wrap arguments in arrays."
            )
        })
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                OLLAMA_URL,
                json={"model": model, "messages": conversation, "stream": False},
                timeout=int(os.environ.get('REQUEST_TIMEOUT')),
            )
            #resp.raise_for_status()
            retry_json = resp.json()
            retry_out = retry_json.get("message", {}).get("content", "")
            logger.info(f"--- RETRY OUTPUT ---\n{retry_out}\n-------------------")
            #await resp.aclose()
            return clean_ollama_output(retry_out)

    # If parsed is bad or arguments are schema instead of values
    if not (isinstance(parsed, dict) and "name" in parsed and is_valid_arguments(parsed)):
        reason = "Arguments were not a dict of values"
        retry_output = await retry_with_clarification(conversation, reason, ollama_out_clean)
        logger.info(retry_output)

        if retry_output.lower() == REQUIRED_OUT_OF_SCOPE_MSG.lower():
            error_payload={
                "output_text": retry_output
            }

            logger.info(error_payload)

            return jsonify(error_payload)

        try:
            parsed = json.loads(retry_output)
        except json.JSONDecodeError:
            match = re.search(r"\{.*\}", retry_output, re.S)
            if match:
                try:
                    parsed = json.loads(match.group())
                except Exception as e:
                    logger.warning(f"Retry also failed to parse JSON: {e}")

    # After retry, try tool call again
    if isinstance(parsed, dict) and "name" in parsed and is_valid_arguments(parsed):
        tool_name = parsed["name"]
        server_url = None
        for ts in tool_schemas:
            if ts["schema"]["name"] == tool_name:
                server_url = ts["server_url"]
                break

        if server_url:
            result = await call_mcp(server_url=server_url, tool_call=parsed)
            tool_outputs.append({"tool": tool_name, "output": result})
            final_output = json.dumps(result)
        else:
            final_output = REQUIRED_OUT_OF_SCOPE_MSG
    else:
        logger.warning("Model did not return a valid tool call after retry.")
        #final_output = ollama_out_clean
        final_output = REQUIRED_OUT_OF_SCOPE_MSG

    """
    response_payload = {
        "id": f"resp:{user}:{server_url}:{datetime.now(timezone.utc)}:{uuid.uuid4()}",
        "object": "response",
        "output": [{"content": [{"type": "output_text", "text": final_output}]}],
        "user_msg": user_input,
        "output_text": final_output,
        "tool_outputs": tool_outputs,
    }
    """
    response_payload={
        "id": f"resp:{user}:{server_url}:{datetime.now(timezone.utc)}:{uuid.uuid4()}",
        "user_msg": user_input,
        "output_text": final_output
    }

    logger.info(response_payload)

    return jsonify(response_payload)