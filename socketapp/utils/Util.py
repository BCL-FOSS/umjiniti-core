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

class Util:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def generate_ephemeral_token(self, id: str, rand: str,  secret_key: str, expire: int = 3) -> str:

        local_tz = get_localzone()  
        now = datetime.now(tz=timezone.utc)
        
        payload = {
            'iss': 'https://baughcl.tech/',
            'id': id,
            'rand': rand,
            'exp': now + timedelta(hours=expire),
        }

        encoded_jwt = jwt.encode(payload=payload, key=secret_key, algorithm="HS256")

        return encoded_jwt
    
    def generate_api_key(self) -> str:
        return str(uuid.uuid4())
    
    def key_gen(self, size=6, chars=string.ascii_uppercase + string.digits):
        return ''.join(random.SystemRandom().choice(chars) for _ in range(size))
    
    def extract_output_text_line_by_line(self, tool_results):
        lines_out = []

        for item in tool_results:
            if not isinstance(item, dict):
                continue
            output_field = item.get("output")
            if output_field is None:
                continue

            text_parts = []

            # If output is a list, prefer index 1 if it's a non-empty string; otherwise collect any string parts.
            if isinstance(output_field, list):
                if len(output_field) > 1 and isinstance(output_field[1], str) and output_field[1].strip():
                    text_parts.append(output_field[1])
                else:
                    for part in output_field:
                        if isinstance(part, str) and part.strip():
                            text_parts.append(part)
            # If output is a single string, use it directly.
            elif isinstance(output_field, str):
                if output_field.strip():
                    text_parts.append(output_field)
            else:
                # Unknown shape: skip
                continue

            # Normalize escaped newlines (unicode escape sequences) and split into lines.
            for part in text_parts:
                try:
                    decoded = part.encode("utf-8").decode("unicode_escape")
                except Exception:
                    decoded = part
                # splitlines preserves line ordering without keeping trailing '\n'
                for ln in decoded.splitlines():
                    lines_out.append(ln)

        # Join lines and ensure a trailing newline if we produced any lines.
        if not lines_out:
            return ""
        return "\n".join(lines_out) + "\n"


        
    


    
        
        
        
        




