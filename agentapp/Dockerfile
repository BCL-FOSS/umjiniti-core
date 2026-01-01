FROM python:3.12

RUN adduser quart --disabled-password 

RUN apt-get update -y

RUN apt-get upgrade -y

WORKDIR /home/quart

COPY agentapp/requirements.txt ./

RUN pip install --no-cache-dir -r requirements.txt

COPY agentapp/ /home/quart/

RUN chmod +x boot.sh

ENTRYPOINT ["sh", "./boot.sh"]