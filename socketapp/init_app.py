from quart import Quart
import nest_asyncio
import logging
import secrets
import nest_asyncio
import logging
from quart_rate_limiter import (RateLimiter, RateLimit, timedelta)
import logging
import os

logging.basicConfig(level=logging.DEBUG)
logging.getLogger('passlib').setLevel(logging.ERROR)
logger = logging.getLogger(__name__)

app = Quart(__name__)
app.config.from_object("config")
app.config['SECRET_KEY'] = secrets.token_urlsafe()
app.config['SECURITY_PASSWORD_SALT'] = str(secrets.SystemRandom().getrandbits(128))

# Trust Proxy Headers (IMPORTANT for reverse proxy)
# app.config["SERVER_NAME"] = os.environ.get('SOCKET_SERVER_NAME')

folder_name = 'appdata'

# data folder directories
data_dir_path = os.path.join(app.instance_path, folder_name)

if os.path.exists(data_dir_path) is False:
    os.makedirs(data_dir_path, exist_ok=True)

APP_DATA_DIR = data_dir_path

app.config['APP_DATA_DIR'] = APP_DATA_DIR

nest_asyncio.apply()

RateLimiter(
    app,
    default_limits=[
        RateLimit(1, timedelta(seconds=1)),
        RateLimit(20, timedelta(minutes=1)),
    ],
)


