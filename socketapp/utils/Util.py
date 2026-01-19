import uuid
import re
from wtforms.validators import ValidationError
import string
import random
from quart import flash
import logging
import os
import sys
from pathlib import Path
import subprocess
import asyncio
from quart import (flash, redirect, url_for)
import logging
import os
import jwt
from datetime import datetime, timedelta, timezone
from tzlocal import get_localzone
import jwt
import re
from typing import Tuple

class Util:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def generate_ephemeral_token(self, id: str, rand: str,  secret_key: str, expire: int = 3, type: str = None) -> str:

        local_tz = get_localzone()  
        now = datetime.now(tz=timezone.utc)

        if type == 'prb':
            expire_value = timedelta(minutes=30)
        else:
            expire_value = timedelta(hours=expire)
        
        payload = {
            'iss': f"https://{os.environ.get('SERVER_NAME')}",
            'id': id,
            'rand': rand,
            'exp': now + expire_value,
        }

        encoded_jwt = jwt.encode(payload=payload, key=secret_key, algorithm="HS256")

        return encoded_jwt
    
    def generate_api_key(self) -> str:
        return str(uuid.uuid4())
    
    def key_gen(self, size=6, chars=string.ascii_uppercase + string.digits):
        return ''.join(random.SystemRandom().choice(chars) for _ in range(size))
    
    def extract_after_analysis(self, text: str) -> str:
        marker = "Analysis:"
        index = text.find(marker)

        if index == -1:
            return ""

        return text[index + len(marker):]

    def split_analysis(self, text: str) -> Tuple[str, str]:
        pattern = re.compile(r'analysis\s*:\s*', re.IGNORECASE)

        match = pattern.search(text)
        if not match:
            return text, ""

        cleaned_text = text[:match.start()].rstrip()
        analysis_text = text[match.end():].lstrip()

        return cleaned_text, analysis_text




        
    


    
        
        
        
        




