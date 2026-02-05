import pyotp
import qrcode
import io
import base64
from qrcode.image.pure import PyPNGImage
from pathlib import Path
@app.route('/otp_vld/<string:email>', methods=['GET', 'POST'])
async def otp_vld(email):
    try:
        otp_form = await OTPForm.create_form()
            
        await cl_auth_db.connect_db()

        if await cl_auth_db.get_all_data(match=f'*{email}*', cnfrm=True) is True:
            account_data = await cl_auth_db.get_all_data(match=f'*{email}*')
            logger.info(account_data)
            sub_dict = next(iter(account_data.values()))
            logger.info(sub_dict)
            usr_otp_secret = pyotp.TOTP(sub_dict.get('otp_secret'))
            logger.info(sub_dict.get('otp_secret'))
        else:
            await flash(message='Account does not exist.', category='danger')
            return redirect(url_for('register'))

        if await otp_form.validate_on_submit():
            usr_otp_to_cnfrm = otp_form.otp_code_cnfrm.data

            if usr_otp_secret.verify(usr_otp_to_cnfrm):
                
                
                if sub_dict.get('otp_configured') == 'False' and sub_dict.get('adm_key'):
                    key  = f'adm-{sub_dict.get('db_id')}'   
                    logger.info(key)
                    otp_confirmed = {'otp_configured' : True}
                    if await cl_auth_db.upload_db_data(id=key, data=otp_confirmed) > 0:
                        logger.info(f'otp configured for {email}')
                    else:
                        logger.error(f'otp configuration failed for {email}')

                elif sub_dict.get('otp_configured') == 'False':     
                    key = f'{sub_dict.get('db_id')}'
                    logger.info(key)
                    otp_confirmed = {'otp_configured' : True}
                    if await cl_auth_db.upload_db_data(id=key, data=otp_confirmed) > 0:
                        logger.info(f'otp configured for {email}')
                    else:
                        logger.error(f'otp configuration failed for {email}')

                
            else:
                logger.error(f'2FA configuration for {sub_dict.get('eml')} failed.')
                await flash(message=f'2FA configuration for {sub_dict.get('eml')} failed. Try again...', category='danger')    
                return redirect(url_for('otp_vld', usr_key=sub_dict.get('db_id')))
        else:
            await flash(message='Account does not exist.', category='danger')
            return redirect(url_for('register'))

        return await render_template('index/otp_vld.html', form=otp_form, email=email)
    except Exception as e:
        logger.error( json.dumps({
            'status': 'error',
            'message': str(e)
        }), exc_info=True)

        return redirect(url_for('login'))

@app.route('/otp_gen/<string:email>', methods=['GET', 'POST'])
async def otp_gen(email):
    try:    
        await cl_auth_db.connect_db()

        if await cl_auth_db.get_all_data(match=f'*{email}*', cnfrm=True) is True:
            account_data = await cl_auth_db.get_all_data(match=f'*{email}*')
            logger.info(account_data)
            sub_dict = next(iter(account_data.values()))
            logger.info(sub_dict)
            usr_otp_secret = pyotp.totp.TOTP(sub_dict.get('otp_secret'))
            logger.info(sub_dict.get('otp_secret'))
        else:
            await flash(message='Account does not exist.', category='danger')
            return redirect(url_for('register'))
        
        # file name for generated qr code
        qr_code_file_name = f'{email}_otp_qr.png'

        # qr codes dir path
        static_path = f'static/img/bcl/qrcodes'

        if os.path.exists(static_path) is False:
            os.makedirs(static_path, exist_ok=True)

        if os.path.exists(os.path.join(static_path, qr_code_file_name)) is False:
            # Generate a QR code for Authenticator App
            uri = usr_otp_secret.provisioning_uri(name=f"{sub_dict.get('unm')}_otp_qr", issuer_name="umjiniti by Baugh Consulting & Lab L.L.C.")
            qr = qrcode.make(data=uri, image_factory=PyPNGImage)
            qr.save(f'{qr_code_file_name}')

        if os.path.exists(qr_code_file_name):
            shutil.move(src=qr_code_file_name, dst=static_path)

        main_path = Path(static_path).rglob('*.png')
        if main_path:
            for file_path in main_path:
                logger.info(file_path)
                qr_path = f"img/bcl/qrcodes/{qr_code_file_name}" if file_path.name == qr_code_file_name else None
        
        if qr_path is None:
            logger.error(f'qr code generaton failed for {qr_code_file_name}')
                
        return await render_template('index/otp_gen.html', qr_code=qr_path, email=email)
    except Exception as e:
        logger.error( json.dumps({
            'status': 'error',
            'message': str(e)
        }), exc_info=True)

        return redirect(url_for('login'))

template = """
        {subdomain}.baughcl.com {{
            @websockets {{
                header Connection *Upgrade*
                header Upgrade    websocket
            }}

            handle /chat* {{
                reverse_proxy @websockets socketapp:8443 {{
                    transport http {{
                        tls
                        tls_insecure_skip_verify
                    }}
                }}
            }}
        }}
        """

        docker_compose_template = """

        services:
            umj_prb_{subdomain}:
                restart: always
                build:
                context: .
                dockerfile: app/Dockerfile
                container_name: umj-prb-{subdomain}
                env_file: "umj-prb-{subdomain}.env"
                depends_on:
                - client_auth_redis
                - client_data_redis
                - admin_redis
                - client_sess_redis
                volumes:
                - app_data:/home/quart/instance/apps
                - ssh_keys:/home/quart/.ssh

            caddy-{subdomain}:
                image: caddy:latest
                container_name: caddy-{subdomain}
                volumes:
                - {save_dir}/Caddyfile-{subdomain}:/etc/caddy/Caddyfile
                - caddy-{subdomain}-data:/data
                - caddy-{subdomain}-config:/config
                ports:
                - \"{proxy_port_a}:80\"
                - \"{proxy_port_b}:443\"
                restart: always

            umj_prb_{subdomain}_db:
                image: redis:latest
                container_name: umj-prb-{subdomain}-db
                command: ["redis-server", "--port", "8389", "--appendonly", "yes"]
                volumes:
                - client_auth_data:/data 

            volumes:
            caddy-{subdomain}-data:
            caddy-{subdomain}-config:
        """

        env_template="""
        REDIS_PRB_DB=umj-prb-{subdomain}-db
        REDIS_PRB_DB_PORT=8389
        SERVER_NAME={subdomain}
        """

        # Generate .env file
        env_content = env_template.format(subdomain=subdomain)
        env_path = os.path.join(SAVE_DIR, f"umj-prb-{subdomain}.env")
        with open(env_path, "w") as f:
            f.write(env_content)
        
        # Generate Caddyfile
        caddyfile_content = template.format(subdomain=subdomain)
        caddyfile_path = os.path.join(SAVE_DIR, f"Caddyfile-{subdomain}")
        with open(caddyfile_path, "w") as f:
            f.write(caddyfile_content)
        
        # Generate Docker Compose file
        docker_compose_content = docker_compose_template.format(subdomain=subdomain,proxy_port_a=port_a, proxy_port_b=port_b,save_dir=SAVE_DIR)
        docker_compose_path = os.path.join(SAVE_DIR, f"docker-compose-{subdomain}.yml")
        with open(docker_compose_path, "w") as f:
            f.write(docker_compose_content)


<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Live Terminal Output</title>
    <style>
        body {
            margin: 0;
            padding: 1rem;
            font-family: sans-serif;
            background: #121212;
            color: #fff;
        }

        .terminal {
            background-color: #1e1e1e;
            color: #d4d4d4;
            font-family: 'Courier New', Courier, monospace;
            padding: 1rem;
            border-radius: 10px;
            white-space: pre-wrap;
            overflow-y: auto;
            max-height: 80vh;
            line-height: 1.5;
            font-size: 0.9rem;
        }

        @media (max-width: 600px) {
            .terminal {
                font-size: 0.8rem;
                padding: 0.5rem;
            }
        }
    </style>
</head>
<body>
    <h2>Live Terminal Output</h2>
    <div class="terminal" id="terminal-output"></div>

    <script>
        const terminal = document.getElementById("terminal-output");
        const ws = new WebSocket(`ws://${location.host}/ws/stream`);

        ws.onmessage = (event) => {
            const line = event.data;
            terminal.textContent += line + '\n';
            terminal.scrollTop = terminal.scrollHeight;
        };

        ws.onclose = () => {
            terminal.textContent += "\n--- Connection closed ---\n";
        };
    </script>
</body>
</html>


from quart import Quart, render_template, websocket
import asyncio

app = Quart(__name__)

@app.route("/")
async def index():
    return await render_template("terminal.html")

@app.websocket("/ws/stream")
async def stream_terminal():
    # Simulated output — replace with real subprocess if needed
    lines = [
        "$ echo Hello, world!",
        "Hello, world!",
        "",
        "$ ls -la",
        "drwxr-xr-x  3 user user   4096 Apr  9 12:00 .",
        "drwxr-xr-x 15 user user   4096 Apr  9 11:59 ..",
        "-rw-r--r--  1 user user    123 Apr  9 12:00 file.txt",
        "",
        "$ uname -a",
        "Linux server 5.15.0-1031-gcp #37~20.04 SMP x86_64 GNU/Linux"
    ]

    for line in lines:
        await websocket.send(line)
        await asyncio.sleep(1)  # simulate delay between outputs


from quart import Quart, render_template, websocket
import asyncssh
import asyncio

app = Quart(__name__)

REMOTE_HOST = "your.remote.server.ip"
USERNAME = "youruser"
PRIVATE_KEY_PATH = "/path/to/your/private_key"  # like ~/.ssh/id_rsa
REMOTE_COMMAND = "ping -c 5 google.com"  # or any long-running script

@app.route("/")
async def index():
    return await render_template("terminal.html")

@app.websocket("/ws/stream")
async def ws_stream():
    try:
        async with asyncssh.connect(REMOTE_HOST, username=USERNAME, client_keys=[PRIVATE_KEY_PATH]) as conn:
            process = await conn.create_process(REMOTE_COMMAND)

            async for line in process.stdout:
                await websocket.send(line.rstrip())

            # Optionally handle stderr too
            async for line in process.stderr:
                await websocket.send(f"ERR: {line.rstrip()}")

    except (OSError, asyncssh.Error) as exc:
        await websocket.send(f"Connection failed: {exc}")
