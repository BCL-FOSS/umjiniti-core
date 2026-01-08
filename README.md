# umjiniti-core #

Network Management System that leverages open source LLMs to proactively monitor, visualize and troubleshoot on-prem and cloud environments via distributed probes.

<p align="center">
  <img width="300" height="300" src="https://github.com/BCL-FOSS/umjiniti-core/blob/main/agentapp/static/img/bcl/umjiniti.png?raw=true">
</p>

### Get Started ###

1. Set the necessary environment variables in the included .env
```bash
# onetimesecret API credentials for sending OTP links
OTS_USER= # onetimesecret.com user email
OTS_KEY= # onetimesecret.com API key
OTS_TTL=300 # Time to live for OTP links in seconds (default 5 minutes)

# SMTP email server settings for sending OTP links
SMTP_SERVER=
SMTP_PORT=
SMTP_SENDER=
SMTP_SENDER_APP_PASSWORD=
SMTP_RECEIVER=

# Set server URL here (must be FQDN)
SERVER_NAME=umj.baughlabs.tech
#SOCKET_SERVER_NAME=socket.baughlabs.tech

# Enter your MCP server urls here for use within umjiniti
MCP_URLS='["https://user.mcp1.com/mcp/", "https://user.mcp2.com/mcp/"]'

# Set how many SDN controllers (UniFi, TP Link Omada) and alert contacts you want to allow
sdn_count=1
alert_count=3

# No need to edit anything below this comment
IP_BAN_DB=ipbanredis
IP_BAN_DB_PORT=5379
CLIENT_DATA_DB=clientdatadb
CLIENT_DATA_DB_PORT=6369
CLIENT_AUTH_DB=clientauthdb
CLIENT_AUTH_DB_PORT=7369
CLIENT_SESS_DB=clientsessdb
CLIENT_SESS_DB_PORT=8369
RATE_LIMIT_DB=ratelimitdb
RATE_LIMIT_DB_PORT=9379
REQUEST_TIMEOUT=600
API_TOKEN_NAME=wkflw_token
```