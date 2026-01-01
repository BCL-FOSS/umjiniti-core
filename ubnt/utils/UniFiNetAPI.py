import aiohttp
import uuid
import aiohttp
import logging
import httpx
import json

logging.basicConfig(level=logging.DEBUG)
logging.getLogger('passlib').setLevel(logging.ERROR)

class UniFiNetAPI():

    def __init__(self, is_udm=False, **kwargs):
        self.base_url = f"https://{kwargs.get('controller_ip')}:{kwargs.get('controller_port')}"
        self.url = kwargs.get('controller_ip')
        self.inform_url = f"https://{kwargs.get('controller_ip')}:8080/inform"
        self.port = kwargs.get('controller_port')
        self.username = kwargs.get('username')
        self.password = kwargs.get('password')
        self.token = None
        self.is_udm = is_udm
        self.auth_check = False
        self.id = ''
        self.name = ''
        self.ubiquipy_client_session = aiohttp.ClientSession()
        #self.url_string = f"{self.base_url}/api/s/" if self.is_udm else f"{self.base_url}/proxy/network/api/"
        self.logger = logging.getLogger(__name__)
        if self.is_udm is False:
            self.url_string = f"{self.base_url}/api/"
        else:
            self.url_string = f"{self.base_url}/proxy/network/api/"
     
        
    def get_profile_data(self):
        """
        Get the profile data of the initialized UniFiNetAPI object

        Returns:
            dict: a dict/json object of the unifi controller login credentials, url and csrf token of the UniFinetAPI object
        """
        return {
            "id": self.id,
            "profile_name": self.name,
            "base_url": self.base_url,
            "url": self.url,
            "inform_url": self.inform_url,
            "port" : self.port,
            "username": self.username,
            "token": self.token,
            "is_udm" : self.is_udm
        }
    
    def _gen_id(self):   
        id = uuid.uuid4()
        return str(id)
    
    async def _make_async_request(self, cmd='', url='', payload={}):
        headers={
                    'Content-Type':'application/json',
                    'Cookie':self.token
                }
      
        match cmd.strip():
            case 'e':
                self.logger.info("PUT")
                async with httpx.AsyncClient() as client:
                    resp = await client.put(
                                url,
                                headers=headers,
                                json=payload
                            )
                    resp.raise_for_status()
                    self.logger.info(resp.text)
                    return resp.text
                         
            case 'p':
                self.logger.info('POST')
                async with httpx.AsyncClient() as client:
                    resp = await client.post(
                                url,
                                headers=headers,
                                json=payload
                            )
                    resp.raise_for_status()
                    self.logger.info(resp.text)
                    return resp.text
                       
            case 'g':
                headers.pop('Content-Type')
                async with httpx.AsyncClient() as client:
                    resp = await client.get(
                                url,
                                headers=headers
                            )
                    resp.raise_for_status()
                    self.logger.info(resp.text)
                    return resp.text
            
    async def authenticate(self):
        """
        Authenticate connections with the specified UniFi Network controller. 

        Returns:
            dict: returns the results of the UniFiNetAPI object profile data. 
            Contains status code 200 for success and a cookie that is your session. 
        """

        if self.is_udm is True:
            auth_url = f"{self.base_url}/proxy/network/api/auth/login"
        else:
            auth_url = f"{self.base_url}/api/login"

        payload = {"username": self.username, "password": self.password}

        async with self.ubiquipy_client_session as session:
            try:
                # Asynchronous POST request to UniFi API
                async with session.post(url=auth_url, json=payload) as response:
                    self.logger.info(response.status)
                    if response.status == 200:
                        #response_data = await response.json()
                        header_data = response.headers.getall('Set-Cookie', [])
                        self.logger.info(header_data)
                        for cookie in header_data:
                            if 'unifises' in cookie:
                                unifises_token = cookie.split(';')[0].split('=')[1]
                                self.logger.info(unifises_token)
                                session_token = f"unifises={unifises_token}"
                                self.token = session_token
                                self.id = self._gen_id()
                                self.auth_check = True
                        
                        response.close()
                        #self.logger.debug({"message": "Authentication successful", "data": response_data, "token": session_token, "id": self.id})
                        return self.get_profile_data()
                    else:
                        response.close()
                        return {"message": "Authentication failed", "status_code": response.status}
            except aiohttp.ClientError as e:
                response.close()
                return {"error": str(e), "status_code": 500}
            except Exception as error:
                response.close()
                return {"error": str(error)}

    async def sign_out(self):
        """
        Destroys the server (Ubiquiti UniFi Network controller) side session id which will make future attempts with that cookie fail  

        Returns:
            dict: confirmation that the server side session id was destroyed
        """
        url = f"{self.url_string}logout"

        payload={"":""} 
        
        response = await self._make_async_request(url=url, payload=payload, cmd='p')

        self.ubiquipy_client_session.close()

        return response
            
    async def site_dpi_sorted_data(self, site='', type=False): 
        """
        Retrieves sorted deep packet inspection (DPI) statistics for the specified site from the Ubiquiti UniFi Controller 
        by either category or application

        Args:
            site (str): The site to retrieve DPI stats from
            type (bool): Whether to retrieve DPI stat data by application (False) or by category (True).

        Returns:
            dict: DPI stats for the specified site
        """

        url = f"{self.url_string}/s/{site}/stat/sitedpi"

        if type is False:
            payload = {'type': 'by_app'}
        else:
            payload = {'type': 'by_cat'}

        response = await self._make_async_request(url=url, payload=payload, cmd='p')

        self.logger.info(response)

        data = json.loads(response)
        self.logger.info(data['data'][0])
        nested_data=data['data'][0]

        return nested_data
            
    async def site_dpi_data(self, site=''): 
        """
        Retrieves the deep packet inspection (DPI) statistics for the specified site from the Ubiquiti UniFi Controller

        Args:
            site (str): The site to retrieve DPI stats from

        Returns:
            dict: DPI stats for the specified site
        """

        url = f"{self.url_string}/s/{site}/stat/sitedpi"

        response = await self._make_async_request(url=url, cmd='g')

        self.logger.info(response)

        data = json.loads(response)
        self.logger.info(data['data'][0])
        nested_data=data['data'][0]

        return nested_data

    async def client_dpi_data(self, site='', type=False, macs=[]):
        """
        Retrieves the deep packet inspection (DPI) statistics for the specified Ubiquiti UniFi network switches and APs from the
        specified site from the Ubiquiti UniFi Controller

        Args:
            site (str): The site to look for the specified Ubiquiti UniFi Network switches or APs
            type (bool): Whether to retrieve DPI stat data by application (False) or by category (True).
            macs (list): The specified Ubiquiti UniFi switches or APs to retrieve the DPI stats for

        Returns:
            dict: DPI stats for the specified Ubiquiti UniFi Network switches or APs
        """

        if type is False and macs != []:
            payload = {'type': 'by_app',
                       'macs': macs}
        elif type is True and macs != []:
            payload = {'type': 'by_cat',
                       'macs': macs}
        elif type is False:
            payload = {'type': 'by_app'}
        else:
            payload = {'type': 'by_cat'}

        url = f"{self.url_string}/s/{site}/stat/stadpi"
        
        response = await self._make_async_request(url=url, payload=payload, cmd='p')

        self.logger.info(response)

        data = json.loads(response)
        self.logger.info(data['data'][0])
        nested_data=data['data'][0]

        return nested_data

    async def event_data(self, site=''):
        """
        Retrieves network events for the specified site by most recent first

        Args:
            site (str): The site to retrieve network events for

        Returns:
            dict: Network events for the specified site
        """

        url = f"{self.url_string}/s/{site}/stat/event"
        
        response = await self._make_async_request(url=url, cmd='g')

        self.logger.info(response)

        data = json.loads(response)
        self.logger.info(data['data'][0])
        nested_data=data['data'][0]

        return nested_data

    async def alarm_data(self, site=''):
        """
        Retrieves network alarms for the specified site by most recent first

        Args:
            site (str): The site to retrieve network alarms for

        Returns:
            dict: Network alarms for the specified site
        """

        url = f"{self.url_string}/s/{site}/stat/alarm"

        response = await self._make_async_request(url=url, cmd='g')

        self.logger.info(response)

        data = json.loads(response)
        self.logger.info(data['data'][0])
        nested_data=data['data'][0]

        return nested_data

    async def health_data(self, site=''):
        """
        Retrieve Health status of the site

        Args:
            site (str): The site to retrieve health status for

        Returns:
            dict: Health status of the site
        """

        url = f"{self.url_string}/s/{site}/stat/health"

        response = await self._make_async_request(url=url, cmd='g')

        self.logger.info(response)

        data = json.loads(response)
        self.logger.info(data['data'][0])
        nested_data=data['data'][0]

        return nested_data

    async def site_stats(self):
        """
        Retrieve health and new alerts for all sites

        Returns:
            dict: Health and new alerts for all sites
        """

        url = f"{self.url_string}/stat/sites"

        response = await self._make_async_request(url=url, cmd='g')

        self.logger.info(response)

        data = json.loads(response)
        self.logger.info(data['data'][0])
        nested_data=data['data'][0]

        return nested_data

    async def sites(self):
        """
        Get basic information for all sites on this controller

        Returns:
            dict: Information for all sites on this controller
        """

        url = f"{self.url_string}/self/sites"

        response = await self._make_async_request(url=url, cmd='g')

        self.logger.info(response)

        data = json.loads(response)
        self.logger.info(data['data'][0])
        nested_data=data['data'][0]

        return nested_data

    async def list_admins(self):
        """
        List administrators and permissions for all sites

        Returns:
            dict: List of administrators and permissions for all sites
        """

        url = f"{self.url_string}/stat/admin"

        response = await self._make_async_request(url=url, cmd='g')

        self.logger.info(response)

        data = json.loads(response)
        self.logger.info(data['data'][0])
        nested_data=data['data'][0]

        return nested_data

    async def udm_poweroff(self):
        """
        Turns off the UDM. X-CSRF-Token header required (from e.g. the login response) + Super Admin access rights

        Returns:
            dict: Confirmation of the UDM being powered off
        """

        if self.is_udm is True:

            url = f"{self.url_string}/system/poweroff"

        else:
            return {"Controller Compatability Error":"This command does not work with self hosted controllers. Please reinitialize the object with is_udm=True and set the URL as the IP address of the UDM or hardware Cloud Gateway"}
        
        payload = {"":""}

        response = await self._make_async_request(url=url, payload=payload, cmd='p')

        self.logger.info(response)

        data = json.loads(response)
        self.logger.info(data['data'][0])
        nested_data=data['data'][0]

        return nested_data

    async def udm_reboot(self):
        """
        Reboot the UDM. X-CSRF-Token header required (from e.g. the login response) + Super Admin access rights

        Returns:
            dict: Confirmation of the UDM being powercycled
        """

        if self.is_udm is True:

            url = f"{self.url_string}/system/reboot"

        else:
            return {"Controller Compatability Error":"This command does not work with self hosted controllers. Please reinitialize the object with is_udm=True and set the URL as the IP address of the UDM or hardware Cloud Gateway"}

        payload = {"":""}

        response = await self._make_async_request(url=url, payload=payload, cmd='p')

        self.logger.info(response)

        data = json.loads(response)
        self.logger.info(data['data'][0])
        nested_data=data['data'][0]

        return nested_data

    async def get_sysinfo(self):
        """
        Some high-level information about the Ubiquiti UniFi controller

        Returns:
            dict: high-level information about the Ubiquiti UniFi controller
        """

        url = f"{self.url_string}s/default/stat/sysinfo"

        response = await self._make_async_request(url=url, cmd='g')

        self.logger.info(response)

        data = json.loads(response)
        self.logger.info(data['data'][0])
        nested_data=data['data'][0]

        return nested_data

    async def active_clients(self, site=''):
        """
        List of all _active_ clients on the site

        Args:
            site (str): The site to retrieve clients from

        Returns:
            dict: List of all _active_ clients on the site
        """

        url = f"{self.url_string}/s/{site}/stat/sta"

        response = await self._make_async_request(url=url, cmd='g')

        self.logger.info(response)

        data = json.loads(response)
        self.logger.info(data['data'][0])
        nested_data=data['data'][0]

        return nested_data

    async def all_clients(self, site=''):
        """
        List of all configured/known clients on the site

        Args:
            site (str): The site to retrieve all all configured/known clients from

        Returns:
            dict: List of all configured/known clients on the site
        """

        url = f"{self.url_string}/s/{site}/rest/user"

        response = await self._make_async_request(url=url, cmd='g')

        self.logger.info(response)

        data = json.loads(response)
        self.logger.info(data['data'][0])
        nested_data=data['data'][0]

        return nested_data

    async def device_data_basic(self, site=''):
        """
        List of site devices with only 'adopted', 'disabled', 'mac', 'state', 'type' keys, useful for filtering on type

        Args:
            site (str): The site to retrieve device(s) data from

        Returns:
            dict: List of site devices with only 'adopted', 'disabled', 'mac', 'state', 'type' keys
        """

        url = f"{self.url_string}/s/{site}/stat/device-basic"

        response = await self._make_async_request(url=url, cmd='g')

        self.logger.info(response)

        data = json.loads(response)
        self.logger.info(data['data'][0])
        nested_data=data['data'][0]

        return nested_data

    async def device_data(self, macs=[], site=''):
        """
        Detailed list of all devices on site. (Controller only) Can be filtered by POSTing {"macs": ["mac1", ... ]}
        (UDM only) Detailed list of device filtered by single mac address

        Args:
            site (str): The site to retrieve detailed device data from
            macs (list): Device MAC addresses to filter device data query (optional)

        Returns:
            dict: Detailed list of all devices on site.
        """

        url = f"{self.url_string}/s/{site}/stat/device"

        if self.is_udm is False and macs != []: 
            payload = {'macs': macs} 

            response = await self._make_async_request(url=url, payload=payload, cmd='p')

            nested_data = response['data']

            return nested_data
        
        if self.is_udm is True and macs !=[]:
            url = f"{self.url_string}/s/{site}/stat/device/{macs[0]}"        
        
        response = await self._make_async_request(url=url, cmd='g')

        self.logger.info(response)

        data = json.loads(response)
        self.logger.info(data['data'][0])
        nested_data=data['data'][0]

        return nested_data

    async def site_settings_update(self, key='', id='', site=''):
        """
        Update site settings for the selected site

        Args:
            site (str): The site to update site settings for
            key (str): Site setting to update (optional)
            id (str): Site setting to update (optional)

        Returns:
            dict: Detailed site settings
        """

        if key and id is not ''.strip():
            url = f"{self.url_string}/s/{site}/rest/setting/{key}/{id}"

   
            payload = {'': ''}
            response = await self._make_async_request(url=url, payload=payload, cmd='e')

            self.logger.info(response)

            data = json.loads(response)
            self.logger.info(data['data'][0])
            nested_data=data['data'][0]

            return nested_data
            
    async def site_settings(self, site=''):
        """
        Retrieve detailed site settings

        Args:
            site (str): The site to retrieve site settings from

        Returns:
            dict: Detailed site settings
        """
   
        url = f"{self.url_string}/s/{site}/rest/setting"

        response = await self._make_async_request(url=url, cmd='g')

        self.logger.info(response)

        data = json.loads(response)
        self.logger.info(data['data'][0])
        nested_data=data['data'][0]

        return nested_data

    async def active_routes(self, site=''):
        """
        Retrieves all active routes on the selected 

        Args:
            site (str): The site to retrieve active routes from

        Returns:
            dict: All active routes on the device for the selected site
        """

        url = f"{self.url_string}/s/{site}/stat/routing"

        response = await self._make_async_request(url=url, cmd='g')

        self.logger.info(response)

        data = json.loads(response)
        self.logger.info(data['data'][0])
        nested_data=data['data'][0]

        return nested_data

    async def firewall_rules(self, site=''):
        """
        Retrieve all user defined firewall rules 

        Args:
            site (str): The site to retrieve firewall rules from

        Returns:
            dict: Site firewall rules
        """

        url = f"{self.url_string}/s/{site}/rest/firewallrule"

        response = await self._make_async_request(url=url, cmd='g')

        self.logger.info(response)

        data = json.loads(response)
        self.logger.info(data['data'][0])
        nested_data=data['data'][0]

        return nested_data

    async def firewall_groups(self, site=''):
        """
        Retrieve all user defined firewall groups

        Args:
            site (str): The site to retrieve firewall groups from

        Returns:
            dict: Site firewall groups
        """

        url = f"{self.url_string}/s/{site}/rest/firewallgroup"

        response = await self._make_async_request(url=url, cmd='g')

        self.logger.info(response)

        data = json.loads(response)
        self.logger.info(data['data'][0])
        nested_data=data['data'][0]

        return nested_data

    async def create_wifi(self, wlan_name='', psswd='', site_id='', site='', ug_id='', apg_id='', apg_mode='all', net_id=''):
        """
        Create WiFi network in the specified site

        Args:
            site (str): Site to manage WiFi network(s) for
            wlan_name (str): Name for new WiFi network 
            psswd (str): Password for new WiFi network 
            site_id (str): ID of site to add new WiFi network to 
            ug_id (str): ID of usergroup to add new WiFi network to 
            apg_id (str): ID of AP group to select which accesspoints broadcast the new WiFi network 
            apg_mode (str): Choose whether to broadcast the new WiFi network on all, specific or group of APs 
            net_id (str): ID of network the WiFi network should acess 

        Returns:
            dict: Confirmation of WiFi network creation
        """

        payload = {
                "name": wlan_name,
                "password": psswd,
                "site_id": site_id,
                "usergroup_id": ug_id,
                "ap_group_ids": [
                    apg_id
                ],
                "ap_group_mode": apg_mode,
                "wpa_mode": "wpa2",
                "x_passphrase": psswd,
                "networkconf_id": net_id,
            }

        url = f"{self.url_string}/s/{site}/rest/wlanconfs"

        response = await self._make_async_request(url=url, payload=payload, cmd='p')

        self.logger.info(response)

        data = json.loads(response)
        self.logger.info(data['data'][0])
        nested_data=data['data'][0]

        return nested_data
            
    async def modify_wifi(self, wlan_name='', psswd='', site_id='', wlan_id='', site='', ug_id='', apg_id='', apg_mode='all', net_id=''):
        """
        Modify the WiFi network specified by wlan_id in the specified site 

        Args:
            site (str): Site to manage WiFi network(s) for
            wlan_name (str): Name for new WiFi network (optional)
            psswd (str): Password for new WiFi network (optional)
            site_id (str): ID of site to add new WiFi network to (optional)
            wlan_id (str): ID of the WiFi network to modify
            ug_id (str): ID of usergroup to add new WiFi network to (optional)
            apg_id (str): ID of AP group to select which accesspoints broadcast the new WiFi network (optional)
            apg_mode (str): Choose whether to broadcast the new WiFi network on all, specific or group of APs (optional)
            net_id (str): ID of network the WiFi network should acess (optional)

        Returns:
            dict: Confirmation of WiFi network modification
        """

        payload = {
                "name": wlan_name,
                "password": psswd,
                "site_id": site_id,
                "usergroup_id": ug_id,
                "ap_group_ids": [
                    apg_id
                ],
                "ap_group_mode": apg_mode,
                "wpa_mode": "wpa2",
                "x_passphrase": psswd,
                "networkconf_id": net_id,
            }

        url = f"{self.url_string}/s/{site}/rest/wlanconf/{wlan_id}"

        response = await self._make_async_request(url=url, payload=payload, cmd='e')

        self.logger.info(response)

        data = json.loads(response)
        self.logger.info(data['data'][0])
        nested_data=data['data'][0]

        return nested_data
            
    async def list_wifi(self, site=''):
        """
        List the WiFi networks in the specified sites

        Args:
            site (str): Site to manage WiFi network(s) for

        Returns:
            dict: WiFi networks in the specified sites
        """

        url = f"{self.url_string}/s/{site}/rest/wlanconfs"

        response = await self._make_async_request(url=url, cmd='g')

        self.logger.info(response)

        data = json.loads(response)
        self.logger.info(data['data'][0])
        nested_data=data['data'][0]

        return nested_data

    async def rogue_aps(self, seen_last=0, site=''):   
        """
        Find unmanaged APs broadcasting same SSID as APs managed by the Ubiquiti UniFi controller

        Args:
            site (str): The site to retrieve health status for
            seen_last (int): Rogue APs seen in the last x hours (optional)

        Returns:
            dict: All found rogue APs
        """

        url = f"{self.url_string}/s/{site}/stat/rogueap"
        
        if seen_last != 0: 
                    
            payload = {'within': seen_last}

            response = await self._make_async_request(url=url, payload=payload, cmd='p')

        else:
            
            response = await self._make_async_request(url=url, payload=payload, cmd='g')

        self.logger.info(response)

        data = json.loads(response)
        self.logger.info(data['data'][0])
        nested_data=data['data'][0]

        return nested_data

    async def dynamic_dns_info(self, site=''):
        """
        Retrieve DynamicDNS information and status like current ip, last changed, and status from the specified site

        Args:
            site (str): The site to retrieve DynamicDNS information from

        Returns:
            dict: DynamicDNS information for the specified site
        """

        url = f"{self.url_string}/s/{site}/stat/dynamicdns"

        response = await self._make_async_request(url=url, cmd='g')

        self.logger.info(response)

        data = json.loads(response)
        self.logger.info(data['data'][0])
        nested_data=data['data'][0]

        return nested_data

    async def dynamic_dns_config(self, site=''):
        """
        Retrieve DynamicDNS configuration from the specified site

        Args:
            site (str): The site to retrieve DynamicDNS configuration data from

        Returns:
            dict: DynamicDNS configuration for the selected site
        """

        url = f"{self.url_string}/s/{site}/rest/dynamicdns"

        response = await self._make_async_request(url=url, cmd='g')

        self.logger.info(response)

        data = json.loads(response)
        self.logger.info(data['data'][0])
        nested_data=data['data'][0]

        return nested_data

    async def list_port_profiles(self, site=''):
        """
        Retrieve Switch port profiles from the selected site

        Args:
            site (str): The site to retrieve switch port profiles from

        Returns:
            dict: Switch port profiles
        """

        url = f"{self.url_string}/s/{site}/rest/portconf"

        response = await self._make_async_request(url=url, cmd='g')

        self.logger.info(response)

        data = json.loads(response)
        self.logger.info(data['data'][0])
        nested_data=data['data'][0]

        return nested_data

    async def rf_scan_results(self, mac='', site=''):
        """
        Get RF (Radio Frequency) scan results, can be for a specific mac by appending to endpoint.
        Used to conduct WiFi network analysis by scanning the airwaves to see what channels nearby devices are using. 
        The goal is to figure out where the "noise" is so your UniFi access points (APs) can avoid it. 

        Args:
            site (str): The site to retrieve switch port profiles from
            mac (str): accesspoint MAC address to retrieve RF scan results from

        Returns:
            dict: RF Scan results
        """
        if mac is not ''.strip():
            url = f"{self.url_string}/s/{site}/stat/spectrumscan/{mac}"
        else:
            url = f"{self.url_string}/s/{site}/stat/spectrumscan"

        response = await self._make_async_request(url=url, cmd='g')

        self.logger.info(response)

        data = json.loads(response)
        self.logger.info(data['data'][0])
        nested_data=data['data'][0]

        return nested_data

    async def create_radius_profiles(self, cmd='', site='', ip='', pwd='', name='', site_id='', port=1812):
        """
        Create RADIUS profiles for the selected site

        Args:
            site (str): The site to modify radius profiles for
            cmd (str): choose whether to retrieve (g), modify (e) or create (p) radius profiles for the selected site
            ip (str): IP address of the radius server (optional)
            pwd (str): password to connect to radius server (optional)
            name (str): radius profile name (optional)
            site_id (str): site to add radius profile to (optional)
            port (int): port of radius server (default 1812)

        Returns:
            dict: radius profile managemtnt results
        """

        url = f"{self.url_string}/s/{site}/rest/radiusprofile"

        payload = {
                    "interim_update_interval": 3600,
                    "auth_servers": [
                        {
                            "port": port,
                            "ip": ip,
                            "x_secret": pwd
                        }
                    ],
                    "name": name,
                    "site_id": site_id,
                    "acct_servers": [],
                    "_id": ""
                }

        response = await self._make_async_request(url=url, payload=payload, cmd='p')

        self.logger.info(response)

        data = json.loads(response)
        self.logger.info(data['data'][0])
        nested_data=data['data'][0]

        return nested_data
            
    async def list_radius_profiles(self, site=''):
        """
        Retrieve RADIUS profiles for the selected site

        Args:
            site (str): The site to retrieve radius profiles from
        
        Returns:
            dict: radius profile managemtnt results
        """

        url = f"{self.url_string}/s/{site}/rest/radiusprofile"

        response = await self._make_async_request(url=url, cmd='g')

        self.logger.info(response)

        data = json.loads(response)
        self.logger.info(data['data'][0])
        nested_data=data['data'][0]

        return nested_data
            
    async def radius_accounts(self, site=''):
        """
        Retrieve all radius accounts from the selected site

        Args:
            site (str): The site to retrieve radius accounts from

        Returns:
            dict: radius accounts in the selected site
        """

        url = f"{self.url_string}/s/{site}/rest/account"

        response = await self._make_async_request(url=url, cmd='g')

        self.logger.info(response)

        data = json.loads(response)
        self.logger.info(data['data'][0])
        nested_data=data['data'][0]

        return nested_data

    async def port_forwards(self, site=''):
        """
        List all port forwards configured on the site

        Args:
            site (str): The site to retrieve configured port forwards from

        Returns:
            dict: configured port forwards
        """

        url = f"{self.url_string}/s/{site}/rest/portforward"

        response = await self._make_async_request(url=url, cmd='g')

        self.logger.info(response)

        data = json.loads(response)
        self.logger.info(data['data'][0])
        nested_data=data['data'][0]

        return nested_data

    async def reports(self, interval='5minutes', type='site', returned_data=["bytes", "num_sta", "time"], macs=[], site='', start=0, end=0):
        """
        Retrieve status reports of traffic users, APs and site from the selected site
        Intervals are '5minutes', 'hourly', and 'daily'. Report types are 'site', 'user', and 'ap'. 
        Must specify attributes to be returned 'bytes', 'wan-tx_bytes', 'wan-rx_bytes', 'wlan_bytes', 'num_sta', 'lan-num_sta', 'wlan-num_sta', 'time', 'rx_bytes', 'tx_bytes'. 
        Can be filtered with 'macs': […]

        Args:
            site (str): The site to retrieve network traffic statistic report from
            interval (str): interval of reported traffic stats
            type (str): type of report to retrieve. Either 'site', 'user' or 'ap'
            returned_data (str): network traffic atributes to return in the report
            macs (list): filter AP network traffic stats by specified mac addresses
            start (int): timestamp to start report from
            end (int): timestamp to end report

        Returns:
            dict: Health status of the site
        """

        url = f"{self.url_string}/s/{site}/stat/report/{interval}.{type}"
       
        if macs != []:
            payload = {
                "attrs": returned_data,
                "start": start,
                "end": end,
                "macs": macs
            }

            response = await self._make_async_request(url=url, cmd='p', payload=payload)

        else:
            payload = {
                "attrs": returned_data,
                "start": start,
                "end": end
            }

            response = await self._make_async_request(url=url, cmd='p', payload=payload)

        self.logger.info(response)

        data = json.loads(response)
        self.logger.info(data['data'][0])
        nested_data=data['data'][0]

        return nested_data

    async def authentication_audit(self, start='', end='', site=''):
        """
        Audit who has signed in and made changes to the UniFi controller and specified site in the specified timeframe 

        Args:
            site (str): The site to retrieve authentication audit from
            start (str): start timestamp
            end (str): end timestamp

        Returns:
            dict: authentication audit results
        """

        url = f"{self.url_string}/s/{site}/stat/authorization/"

        payload = {'start': start, 'end': end}

        response = await self._make_async_request(url=url, cmd='p', payload=payload)

        self.logger.info(response)

        data = json.loads(response)
        self.logger.info(data['data'][0])
        nested_data=data['data'][0]

        return nested_data   

    async def get_site_admins(self, site=""):
        """
        List all administrators and permission for this site

        Args:
            site (str): The site to retrieve admins and permissions from

        Returns:
            dict: site admins and permissions
        """

        url = f"{self.url_string}/s/{site}/cmd/sitemgr/"

        payload = {'cmd': 'get-admins'}
                    
        response = await self._make_async_request(url=url, cmd='p', payload=payload)

        self.logger.info(response)

        data = json.loads(response)
        self.logger.info(data['data'][0])
        nested_data=data['data'][0]

        return nested_data 
    
    async def add_site(self, name="", desc=""):
        """
        Create a new site on the Ubiquiti UniFi controller

        Args:
          desc (str): Descriptive name  
          name (str): shortname, in the URL

        Returns:
            dict: site creation confirmation
        """

        url = f"{self.url_string}/s/default/cmd/sitemgr/"
       
        payload = {'cmd': 'add-site', 'name': name, 'desc': desc}
                    
        response = await self._make_async_request(url=url, cmd='p', payload=payload)

        self.logger.info(response)

        data = json.loads(response)
        self.logger.info(data['data'][0])
        nested_data=data['data'][0]

        return nested_data 
    
    async def update_site(self, site='', desc=''):
        """
        Update the descriptive name of the specified site

        Args:
            desc (str): descriptive name 

        Returns:
            dict: site update confirmation
        """

        url = f"{self.url_string}/s/{site}/cmd/sitemgr/"

        
             
        payload = {'cmd': 'update-site',
                    'desc': desc
                    }
                          
        response = await self._make_async_request(url=url, cmd='p', payload=payload)

        self.logger.info(response)

        data = json.loads(response)
        self.logger.info(data['data'][0])
        nested_data=data['data'][0]

        return nested_data 
    
    async def delete_site(self, name=''):
        """
        Delete the specified site

        Args:
            name (str): name of the site to delete

        Returns:
            dict: confirmation of site deletion
        """

        url = f"{self.url_string}/s/default/cmd/sitemgr/"

       
        payload = {'cmd': 'delete-site',
                    'name': name}
                    
        response = await self._make_async_request(url=url, cmd='p', payload=payload)

        self.logger.info(response)

        data = json.loads(response)
        self.logger.info(data['data'][0])
        nested_data=data['data'][0]

        return nested_data 
    
    async def move_device(self, site='', mac='', site_id=''):
        """
        Move Ubiquiti UniFi network switch or AP from the current site (site) to a new site (site_id)

        Args:
            site (str): Site containing device to move
            site_id (str): Site ID to move the device to
            mac (str): Mac address of the device to move

        Returns:
            dict: Device move confirmation
        """

        url = f"{self.url_string}/s/{site}/cmd/sitemgr/"

        payload = {'cmd': 'move-device',
                    'mac': mac,
                    'site_id': site_id}
                    
        response = await self._make_async_request(url=url, cmd='p', payload=payload)

        self.logger.info(response)

        data = json.loads(response)
        self.logger.info(data['data'][0])
        nested_data=data['data'][0]

        return nested_data 
    
    async def delete_device(self, site='', mac=''):
        """
        Delete the specified device from the specified site

        Args:
            site (str): The site to delete the device from
            mac (str): Device to delete from the specified site 

        Returns:
            dict: device deletion confirmation
        """

        url = f"{self.url_string}/s/{site}/cmd/sitemgr/"

        payload = {'cmd': 'delete-device',
                    'mac': mac}
                    
        response = await self._make_async_request(url=url, cmd='p', payload=payload)

        self.logger.info(response)

        data = json.loads(response)
        self.logger.info(data['data'][0])
        nested_data=data['data'][0]

        return nested_data 

    async def block_clients(self, site='', mac=''):
        """
        Block client from the network at the specified site

        Args:
            site (str): The site containing the device to be blocked
            mac (str): The mac address of the device to block

        Returns:
            dict: result of device blocking
        """

        url = f"{self.url_string}/s/{site}/cmd/stamgr/"

        
        payload = {'cmd': 'block-sta',
                    'mac': mac}
                
        response = await self._make_async_request(url=url, cmd='p', payload=payload)

        self.logger.info(response)

        data = json.loads(response)
        self.logger.info(data['data'][0])
        nested_data=data['data'][0]

        return nested_data
    
    async def kick_clients(self, site='', mac=''):
        """
        Kick client from the network at the specified site

        Args:
            site (str): The site to kick client from
            mac (str): The mac address of the device to kick

        Returns:
            dict: result of device kicking
        """

        url = f"{self.url_string}/s/{site}/cmd/stamgr/"

      
        payload = {'cmd': 'kick-sta',
                    'mac': mac}
                
        response = await self._make_async_request(url=url, cmd='p', payload=payload)

        self.logger.info(response)

        data = json.loads(response)
        self.logger.info(data['data'][0])
        nested_data=data['data'][0]

        return nested_data
    
    async def unblock_clients(self, site='', mac=''):
        """
        Unblock client on the network at the specified site

        Args:
            site (str): The site to retrieve health status for
            mac (str): The mac address of the device to unblock

        Returns:
            dict: result of device unblocking
        """

        url = f"{self.url_string}/s/{site}/cmd/stamgr/"

  
        payload = {'cmd': 'unblock-sta',
                    'mac': mac}
                
        response = await self._make_async_request(url=url, cmd='p', payload=payload)

        self.logger.info(response)

        data = json.loads(response)
        self.logger.info(data['data'][0])
        nested_data=data['data'][0]

        return nested_data
    
    async def forget_clients(self, site='', mac=''):
        """
        Forget client on the network at the specified site

        Args:
            site (str): The site to forget the client from
            mac (str): The mac address of the client to forget

        Returns:
            dict: result of forgetting the client
        """

        url = f"{self.url_string}/s/{site}/cmd/stamgr/"

       
        payload = {'cmd': 'forget-sta',
                    'mac': mac}
                    
                
        response = await self._make_async_request(url=url, cmd='p', payload=payload)

        self.logger.info(response)

        data = json.loads(response)
        self.logger.info(data['data'][0])
        nested_data=data['data'][0]

        return nested_data
    
    async def unauthorize_clients(self, site='', mac=''):
        """
        Unauthorize client from the specified network

        Args:
            site (str): The site to unauthorize the client from
            mac (str): mac address of the device to unauthorize

        Returns:
            dict: result of client unauthorization
        """

        url = f"{self.url_string}/s/{site}/cmd/stamgr/"

        payload = {'cmd': 'unauthorize-guest',
                    'mac': mac}
                
        response = await self._make_async_request(url=url, cmd='p', payload=payload)

        self.logger.info(response)

        data = json.loads(response)
        self.logger.info(data['data'][0])
        nested_data=data['data'][0]

        return nested_data

    async def adopt_devices(self, site='', mac=''):
        """
        Adopt Ubiquiti UniFi switch or AP to the specified site

        Args:
            site (str): The site to adopt UniFi device to
            mac (str): mac address of the device to adopt

        Returns:
            dict: device adoption status
        """

        url = f"{self.url_string}/s/{site}/cmd/devmgr/"

        payload = {'cmd': 'adopt',
                    'mac': mac}
                    
        response = await self._make_async_request(url=url, cmd='p', payload=payload)

        self.logger.info(response)

        data = json.loads(response)
        self.logger.info(data['data'][0])
        nested_data=data['data'][0]

        return nested_data
    
    async def restart_devices(self, site='', mac=''):
        """
        Restart Ubiquiti UniFi switch or AP in the specified site

        Args:
            site (str): The site containing the UniFi device to restart
            mac (str): mac address of the device to restart

        Returns:
            dict: device adoption status
        """

        url = f"{self.url_string}/s/{site}/cmd/devmgr/"

     
        payload = {'cmd': 'restart',
                    'mac': mac}
               
                    
        response = await self._make_async_request(url=url, cmd='p', payload=payload)

        self.logger.info(response)

        data = json.loads(response)
        self.logger.info(data['data'][0])
        nested_data=data['data'][0]

        return nested_data
    
    async def provision_devices(self, site='', mac=''):
        """
        Provision Ubiquiti UniFi switch or AP in the specified site

        Args:
            site (str): The site containing the UniFi device to provision
            mac (str): mac address of the device to provision

        Returns:
            dict: device adoption status
        """

        url = f"{self.url_string}/s/{site}/cmd/devmgr/"
     
        payload = {'cmd': 'force-provision',
                    'mac': mac}
                    
        response = await self._make_async_request(url=url, cmd='p', payload=payload)

        self.logger.info(response)

        data = json.loads(response)
        self.logger.info(data['data'][0])
        nested_data=data['data'][0]

        return nested_data
    
    async def powercycle_devices(self, site='', mac='', port=''):
        """
        Powercycle port on Ubiquiti UniFi switch in the specified site

        Args:
            site (str): The site containing the UniFi device to restart
            mac (str): mac address of the device to restart
            port (str): The ID of the port on the UniFi switch to powercycle

        Returns:
            dict: device adoption status
        """

        url = f"{self.url_string}/s/{site}/cmd/devmgr/"

      
        payload = {'cmd': 'power-cycle',
                    'mac': mac,
                    'port_idx': port}
               
                    
        response = await self._make_async_request(url=url, cmd='p', payload=payload)

        self.logger.info(response)

        data = json.loads(response)
        self.logger.info(data['data'][0])
        nested_data=data['data'][0]

        return nested_data
    
    async def speedtest_devices(self, site='', mac=''):
        """
        Run a speedtest on Ubiquiti UniFi switch or AP in the specified site

        Args:
            site (str): The site containing the UniFi device to run a speedtest on
            mac (str): mac address of the device to speedtest

        Returns:
            dict: device speedtest status
        """

        url = f"{self.url_string}/s/{site}/cmd/devmgr/"

        
        payload = {'cmd': 'speedtest',
                    'mac': mac}
                
                    
        response = await self._make_async_request(url=url, cmd='p', payload=payload)

        self.logger.info(response)

        data = json.loads(response)
        self.logger.info(data['data'][0])
        nested_data=data['data'][0]

        return nested_data

    async def speedtest_status_devices(self, site='', mac=''):
        """
        get status of speedtest run on Ubiquiti UniFi switch or AP in the specified site

        Args:
            site (str): The site containing the UniFi device to get speedtest status from
            mac (str): mac address of the device to get speedtest status

        Returns:
            dict: device speedtest status
        """

        url = f"{self.url_string}/s/{site}/cmd/devmgr/"

        payload = {'cmd': 'speedtest-status',
                    'mac': mac}
                    
        response = await self._make_async_request(url=url, cmd='p', payload=payload)

        self.logger.info(response)

        data = json.loads(response)
        self.logger.info(data['data'][0])
        nested_data=data['data'][0]

        return nested_data

    async def set_locate_devices(self, site='', mac=''):
        """
        Set locate beacon for Ubiquiti UniFi switch or AP in the specified site

        Args:
            site (str): The site containing the UniFi device to set locate beacon
            mac (str): mac address of the device to set locate beacon on

        Returns:
            dict: device set location beacon enable status
        """

        url = f"{self.url_string}/s/{site}/cmd/devmgr/"

        payload = {'cmd': 'set-locate',
                    'mac': mac}

        response = await self._make_async_request(url=url, cmd='p', payload=payload)

        self.logger.info(response)

        data = json.loads(response)
        self.logger.info(data['data'][0])
        nested_data=data['data'][0]

        return nested_data

    async def unset_locate_devices(self, site='', mac=''):
        """
        Unset locate beacon for Ubiquiti UniFi switch or AP in the specified site

        Args:
            site (str): The site containing the UniFi device to unset locate beacon
            mac (str): mac address of the device to unset locate beacon on

        Returns:
            dict: device unset location beacon enable status
        """

        url = f"{self.url_string}/s/{site}/cmd/devmgr/"

        payload = {'cmd': 'unset-locate',
                    'mac': mac}
                    
        response = await self._make_async_request(url=url, cmd='p', payload=payload)

        self.logger.info(response)

        data = json.loads(response)
        self.logger.info(data['data'][0])
        nested_data=data['data'][0]

        return nested_data
    
    async def upgrade_devices(self, site='', mac='', url=''):
        """
        Upgrade Ubiquiti UniFi switch or AP in the specified site

        Args:
            site (str): The site containing the UniFi device to upgrade
            mac (str): mac address of the device to upgrade
            url (str): url to download upgrade package from for Ubiquiti UniFi Network device (optional)

        Returns:
            dict: device upgrade status
        """

        url = f"{self.url_string}/s/{site}/cmd/devmgr/"

        if url.strip() == '':
            payload = {'cmd': 'upgrade-external',
                        'mac': mac,
                        'url': url}
                       
        else:         
            payload = {'cmd': 'upgrade',
                    'mac': mac}
                    
        response = await self._make_async_request(url=url, cmd='p', payload=payload)

        self.logger.info(response)

        data = json.loads(response)
        self.logger.info(data['data'][0])
        nested_data=data['data'][0]

        return nested_data

    async def migrate_devices(self, site='', mac=''):
        """
        Migrate specified unmanaged UniFi devices to the current UniFi Network Controller

        Args:
            site (str): The site to migrate the new Ubiquiti UniFi device to
            mac (str): mac address of the device to migrate

        Returns:
            dict: device migration status
        """

        url = f"{self.url_string}/s/{site}/cmd/devmgr/"

        payload = {'cmd': 'migrate',
                    'mac': mac,
                    'inform_url': self.inform_url}
                    
        response = await self._make_async_request(url=url, cmd='p', payload=payload)

        self.logger.info(response)

        data = json.loads(response)
        self.logger.info(data['data'][0])
        nested_data=data['data'][0]

        return nested_data

    async def cancel_migrate_devices(self, site='', mac=''):
        """
        Cancel device migration to the current UniFi Network Controller

        Args:
            site (str): The site to cancel migration of the new Ubiquiti UniFi device 
            mac (str): mac address of the device to cancel migration

        Returns:
            dict: device migration cancellation status
        """

        url = f"{self.url_string}/s/{site}/cmd/devmgr/"

        payload = {'cmd': 'cancel-migrate',
                    'mac': mac}
                    
        response = await self._make_async_request(url=url, cmd='p', payload=payload)

        self.logger.info(response)

        data = json.loads(response)
        self.logger.info(data['data'][0])
        nested_data=data['data'][0]

        return nested_data

    async def start_spectrum_scan_devices(self, site='', mac=''):
        """
        Start spectrum scan (WiFi channel usage analysis) on the specified Ubiquiti UniFi AP
        in the specified site

        Args:
            site (str): The site containing the UniFi AP to start spectrum scan on
            mac (str): mac address of the UniFi AP to start spectrum scan on

        Returns:
            dict: device spectrum scan start confirmation
        """

        url = f"{self.url_string}/s/{site}/cmd/devmgr/"

       
        payload = {'cmd': 'spectrum-scan',
                    'mac': mac}
                    
        response = await self._make_async_request(url=url, cmd='p', payload=payload)

        self.logger.info(response)

        data = json.loads(response)
        self.logger.info(data['data'][0])
        nested_data=data['data'][0]

        return nested_data

    async def list_backups(self, site=''):
        """
        Retrieves list of autobackup files for specified site

        Args:
            site (str): The site for the backup file

        Returns:
            dict: list of autobackup files
        """

        url = f"{self.url_string}/s/{site}/cmd/backup/"
        payload={'cmd':'list-backups'}
                    
        response = await self._make_async_request(url=url, cmd='p', payload=payload)

        self.logger.info(response)

        data = json.loads(response)
        self.logger.info(data['data'][0])
        nested_data=data['data'][0]

        return nested_data
    
    async def delete_backups(self, site='', filename=''):
        """
        Delete specified backup file for specified site

        Args:
            site (str): The site to delete backup for
            filename (str): filename of the backup file to delete

        Returns:
            dict: backup file deletion confirmation
        """

        url = f"{self.url_string}/s/{site}/cmd/backup/"
        payload={'cmd': 'delete-backup',
            'filename':filename}
                    
        response = await self._make_async_request(url=url, cmd='p', payload=payload)

        self.logger.info(response)

        data = json.loads(response)
        self.logger.info(data['data'][0])
        nested_data=data['data'][0]

        return nested_data
    
    async def create_backup(self, site=''):
        """
        Create backup for specified site

        Args:
            site (str): The site to create backup for

        Returns:
            dict: backup file deletion confirmation
        """

        url = f"{self.url_string}/s/{site}/cmd/system/"
        payload={'cmd': 'backup'}
                    
        response = await self._make_async_request(url=url, cmd='p', payload=payload)

        self.logger.info(response)

        data = json.loads(response)
        self.logger.info(data['data'][0])
        nested_data=data['data'][0]

        return nested_data