"""
                    resp = await client.responses.create(
                                model="deepseek-r1:1.5b",
                                tools=[
                                    {
                                        "type": "mcp",
                                        "server_label": "netadmin_mcp_server",
                                        "server_url": f"{message['url']}",
                                        "require_approval": "never",
                                    },
                                ],
                                input=f"{message['msg']}",
                                instructions=INSTRUCTIONS,
                                api_key=api,
                            )

                    # Extract agent response
                    logger.info(resp)
                    logger.info(resp.output[0].content[0].text)
                    #logger.info(resp.output)

                    agnt_msg = resp.output[0].content[0].text   

                    if agnt_msg is None:
                        # fallback to plain text
                        agnt_msg = resp.output_text or "[No output]"
                    
                    """
@app.route("/messages", methods=["POST"])
async def messages():
    """ Retrieve the chat history for selected user and connected AI agent """
    logger.info(request.args)
    if request.args is not None:
        jwt_token = request.args.get("token")
        id   = request.args.get("id")
        user  = request.args.get("unm")
    
    if user and id is not None or "":
                    
        await cl_auth_db.connect_db()
        await cl_sess_db.connect_db()

        if await cl_auth_db.get_all_data(match=f'*{user}*', cnfrm=True) and await cl_sess_db.get_all_data(match=f'{id}', cnfrm=True) is True:
                        
            account_data = await cl_auth_db.get_all_data(match=f'*{user}*')
            if account_data is None:
                return jsonify({"error": "Authentication Error"})
                            
            logger.info(account_data)
            sub_dict = next(iter(account_data.values()))
            logger.info(sub_dict)

            jwt_key = sub_dict.get('usr_jwt_secret')
            logger.info(jwt_key)
            decoded_token = jwt.decode(jwt=jwt_token, key=jwt_key , algorithms=["HS256"])
            logger.info(decoded_token)

            if decoded_token.get('rand') != sub_dict.get('usr_rand'):
                return jsonify({"error": "Authentication Error"})
            else:
                data = await request.get_json()
            
                key=f'chat:{data['mcpurl']}:{data['usr']}'
                messages = await pubsub_redis.lrange(key, 0, -1)
                messages = [json.loads(m) for m in reversed(messages)]  # oldest first
                return jsonify(messages)

@app.route("/send_message", methods=["POST"])
async def send_message():
    """Add new user messages to chat stream in redis and trigger agent response via websocket"""
    logger.info(request.args)
    if request.args is not None:
        jwt_token = request.args.get("token")
        id   = request.args.get("id")
        user  = request.args.get("unm")
      
    if user and id is not None or "":
                    
        await cl_auth_db.connect_db()
        await cl_sess_db.connect_db()

        if await cl_auth_db.get_all_data(match=f'*{user}*', cnfrm=True) and await cl_sess_db.get_all_data(match=f'{id}', cnfrm=True) is True:
                        
            account_data = await cl_auth_db.get_all_data(match=f'*{user}*')
            if account_data is None:
                return jsonify({"error": "Authentication Error"})
                            
            logger.info(account_data)
            sub_dict = next(iter(account_data.values()))
            logger.info(sub_dict)

            jwt_key = sub_dict.get('usr_jwt_secret')
            logger.info(jwt_key)
            decoded_token = jwt.decode(jwt=jwt_token, key=jwt_key , algorithms=["HS256"])
            logger.info(decoded_token)

            if decoded_token.get('rand') != sub_dict.get('usr_rand'):
                return jsonify({"error": "Authentication Error"})
            else:
                data = await request.get_json()
                msg_data = {
                    "from": data["from"],
                    "msg": data["msg"]
                }
            
                key=f'chat:{data['url']}:{data['usr']}'
                stream=f'stream:{key}'
                await pubsub_redis.lpush(key, json.dumps(msg_data))
                await pubsub_redis.publish(f"{stream}", json.dumps(msg_data))

                ws_json= {"act":"llm","url":{data['url']},"usr":{data['usr']}, "msg": data['msg']}
                await broker.publish(ws_json)
                # await websocket.send(json.dumps(ws_json))
                return jsonify({"status": "ok"})



def _get_ubnt_schema(response_json: Union[dict, list]) -> dict:
    """Extracts a schema definition from an API response."""
    if isinstance(response_json, list):
        response_json = response_json[0] if response_json else {}
    return {key: type(value).__name__ for key, value in response_json.items()}

def _get_ubnt_api_spec() -> str:
    """
    Retrieves API specs for the Ubiquiti UniFi Network Controller API, including
    GET, POST, PUT, and DELETE support for all known endpoints.
    """
    unifi_host = os.environ.get('UNIFI_CONTROLLER_HOST', 'https://<unifi-controller>:8443')
    username = os.environ.get('UNIFI_USERNAME', 'admin')
    password = os.environ.get('UNIFI_PASSWORD', 'password')

    login_url = f"{unifi_host}/api/login"
    headers = {"Content-Type": "application/json"}
    
    session = requests.Session()
    
    # Authenticate with UniFi Controller
    login_payload = {"username": username, "password": password}
    response = session.post(login_url, json=login_payload, headers=headers, verify=False)  # Ignore SSL issues

    if response.status_code != 200:
        raise Exception("Failed to authenticate with UniFi Controller.")

    # Define known API endpoints
    endpoints = {
        # System Information & Health
        "/api/stat/device": {"summary": "Retrieve device statistics", "methods": ["GET"]},
        "/api/stat/health": {"summary": "Retrieve system health information", "methods": ["GET"]},
        "/api/s/default/stat/sysinfo": {"summary": "Retrieve UniFi system info", "methods": ["GET"]},
        "/api/s/default/stat/alarm": {"summary": "Retrieve system alarms", "methods": ["GET", "DELETE"]},

        # Site & Network Configuration
        "/api/s/default/stat/sites": {"summary": "Retrieve UniFi sites", "methods": ["GET"]},
        "/api/s/default/cmd/sitemgr": {"summary": "Manage sites (rename, delete)", "methods": ["POST"]},
        "/api/s/default/rest/networkconf": {"summary": "Manage network configurations", "methods": ["GET", "POST", "PUT", "DELETE"]},
        "/api/s/default/rest/wlanconf": {"summary": "Manage wireless network configurations", "methods": ["GET", "POST", "PUT", "DELETE"]},
        "/api/s/default/rest/wlangroup": {"summary": "Manage WLAN groups", "methods": ["GET", "POST", "PUT", "DELETE"]},

        # Client & Device Management
        "/api/s/default/stat/sta": {"summary": "Retrieve list of connected clients", "methods": ["GET"]},
        "/api/s/default/stat/rogueap": {"summary": "Retrieve list of rogue APs", "methods": ["GET"]},
        "/api/s/default/cmd/stamgr": {"summary": "Manage client devices (e.g., block/unblock)", "methods": ["POST"]},
        "/api/s/default/cmd/devmgr": {"summary": "Manage network devices (e.g., reboot, locate)", "methods": ["POST"]},

        # Guest & Hotspot Management
        "/api/s/default/stat/voucher": {"summary": "Retrieve guest vouchers", "methods": ["GET"]},
        "/api/s/default/cmd/hotspot": {"summary": "Manage guest vouchers", "methods": ["POST"]},

        # Security & Firewall
        "/api/s/default/rest/firewallrule": {"summary": "Manage firewall rules", "methods": ["GET", "POST", "PUT", "DELETE"]},
        "/api/s/default/rest/dhcpoption": {"summary": "Manage DHCP options", "methods": ["GET", "POST", "PUT", "DELETE"]},
        "/api/s/default/rest/radiusprofile": {"summary": "Manage RADIUS profiles", "methods": ["GET", "POST", "PUT", "DELETE"]},

        # User & Authorization Management
        "/api/s/default/rest/user": {"summary": "Manage users", "methods": ["GET", "POST", "PUT", "DELETE"]},
    }

    openapi_spec: Dict[str, Any] = {
        "openapi": "1.0.0",
        "info": {"title": "Ubiquiti UniFi Network API", "version": "1.0.0"},
        "servers": [{"url": unifi_host}],
        "paths": {},
    }

    # Iterate over defined endpoints
    for endpoint, details in endpoints.items():
        api_url = f"{unifi_host}{endpoint}"
        openapi_spec["paths"][endpoint] = {}

        # Try GET request to infer response schema
        if "GET" in details["methods"]:
            response = session.get(api_url, headers=headers, verify=False)
            schema = _get_ubnt_schema(response.json()) if response.status_code == 200 else {}

            openapi_spec["paths"][endpoint]["get"] = {
                "summary": details["summary"],
                "responses": {
                    "200": {
                        "description": "Successful response",
                        "content": {
                            "application/json": {"schema": {"type": "object", "properties": schema}}
                        },
                    }
                },
            }

        # Define request body schema for POST/PUT
        request_body_schema = {
            "required": True,
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "properties": {
                            "key": {"type": "string", "example": "value"}  # Generic placeholder
                        }
                    }
                }
            }
        }

        # Add POST support
        if "POST" in details["methods"]:
            openapi_spec["paths"][endpoint]["post"] = {
                "summary": f"Create or update {endpoint.split('/')[-1]}",
                "requestBody": request_body_schema,
                "responses": {
                    "201": {"description": "Resource created or updated"},
                },
            }

        # Add PUT support
        if "PUT" in details["methods"]:
            openapi_spec["paths"][endpoint]["put"] = {
                "summary": f"Update {endpoint.split('/')[-1]}",
                "requestBody": request_body_schema,
                "responses": {
                    "200": {"description": "Resource updated"},
                },
            }

        # Add DELETE support
        if "DELETE" in details["methods"]:
            openapi_spec["paths"][endpoint]["delete"] = {
                "summary": f"Delete {endpoint.split('/')[-1]}",
                "responses": {
                    "204": {"description": "Resource deleted"},
                },
            }

    return yaml.dump(openapi_spec, sort_keys=False)
