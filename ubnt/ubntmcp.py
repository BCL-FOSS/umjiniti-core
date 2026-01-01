from fastmcp import FastMCP
from utils.UniFiNetAPI import UniFiNetAPI
from utils.RedisDB import RedisDB
import logging
from starlette.requests import Request
from starlette.responses import JSONResponse
import os
from passlib.hash import bcrypt
import json
from fastmcp.server.auth import TokenVerifier
from typing import Annotated
import ast

mcp = FastMCP(name="UniFiAutomation")

logging.basicConfig(level=logging.DEBUG)
logging.getLogger('passlib').setLevel(logging.ERROR)
logger = logging.getLogger(__name__)

# Redis DB initialization
cl_auth_db = RedisDB(hostname=os.environ.get('CLIENT_AUTH_DB'), 
                                 port=os.environ.get('CLIENT_AUTH_DB_PORT'))

@mcp.tool
async def controller_system_data(user: Annotated[str, "User to find the correct Ubiquiti UniFi Controller credentials"], ip: Annotated[str, "URL of the Ubiquiti UniFi Controller"]) -> dict:
    """Use for Ubiquiti UniFi controller metadata/system info"""

    await cl_auth_db.connect_db()
    cl_auth_data = await cl_auth_db.get_all_data(match=f'*{user}*')
    if not cl_auth_data:
        return {"error": f"User {user} not found"}

    # Retrieve UniFi credentials for the specified user
    outer_key = next(iter(cl_auth_data))  
    inner_dict = cl_auth_data[outer_key]
    data = inner_dict[f'ubnt:{ip}']
    ubnt_dict = ast.literal_eval(data)
    logger.info(ubnt_dict)

    ubnt = UniFiNetAPI(
        controller_ip=ubnt_dict["ip"],
        controller_port='8443',
        username=ubnt_dict["user"],
        password=ubnt_dict["pwd"],
    )

    auth_result=await ubnt.authenticate()
    logger.debug(auth_result)

    cntlr_hlth_data=await ubnt.get_sysinfo()
    logger.debug(cntlr_hlth_data)

    await ubnt.sign_out()
    
    return cntlr_hlth_data

@mcp.tool
async def controller_admins(user: Annotated[str, "User to find the correct Ubiquiti UniFi Controller credentials"], ip: Annotated[str, "URL of the Ubiquiti UniFi Controller"], site: Annotated[str, "Site on the Ubiquiti UniFi Controller"]) -> dict:
    """List all administrators and permission for this site"""

    await cl_auth_db.connect_db()
    cl_auth_data = await cl_auth_db.get_all_data(match=f'*{user}*')
    if not cl_auth_data:
        return {"error": f"User {user} not found"}

    # Retrieve UniFi credentials for the specified user
    outer_key = next(iter(cl_auth_data))  
    inner_dict = cl_auth_data[outer_key]
    data = inner_dict[f'ubnt:{ip}']
    ubnt_dict = ast.literal_eval(data)
    logger.info(ubnt_dict)

    ubnt = UniFiNetAPI(
        controller_ip=ubnt_dict["ip"],
        controller_port='8443',
        username=ubnt_dict["user"],
        password=ubnt_dict["pwd"],
    )

    auth_result=await ubnt.authenticate()
    logger.debug(auth_result)

    cntlr_adm=await ubnt.get_site_admins(site=site)
    logger.debug(cntlr_adm)

    await ubnt.sign_out()
    return cntlr_adm

@mcp.tool
async def all_sites(user: Annotated[str, "User to find the correct Ubiquiti UniFi Controller credentials"], ip: Annotated[str, "URL of the Ubiquiti UniFi Controller"]) -> dict:
    """Get basic information for all sites on this controller"""

    await cl_auth_db.connect_db()
    cl_auth_data = await cl_auth_db.get_all_data(match=f'*{user}*')
    if not cl_auth_data:
        return {"error": f"User {user} not found"}

    # Retrieve UniFi credentials for the specified user
    outer_key = next(iter(cl_auth_data))  
    inner_dict = cl_auth_data[outer_key]
    data = inner_dict[f'ubnt:{ip}']
    ubnt_dict = ast.literal_eval(data)
    logger.info(ubnt_dict)

    ubnt = UniFiNetAPI(
        controller_ip=ubnt_dict["ip"],
        controller_port='8443',
        username=ubnt_dict["user"],
        password=ubnt_dict["pwd"],
    )

    auth_result=await ubnt.authenticate()
    logger.debug(auth_result)

    cntlr_sites=await ubnt.sites()
    logger.debug(cntlr_sites)

    await ubnt.sign_out()
    return cntlr_sites

if __name__ == "__main__":
    mcp.run(
        transport="http",
        host="0.0.0.0",
        port=6000,
        path="/ubnt/mcp/",
        log_level="debug",
    )