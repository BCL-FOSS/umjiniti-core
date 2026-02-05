FROM python:3.12

RUN adduser quart --disabled-password 

RUN apt-get update -y

RUN apt-get upgrade -y

WORKDIR /home/quart

COPY frontend/requirements.txt ./

RUN pip install --no-cache-dir -r requirements.txt

COPY frontend/ /home/quart/

RUN chmod +x boot.sh

ENTRYPOINT ["sh", "./boot.sh"]