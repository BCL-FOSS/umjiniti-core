FROM python:3.12

RUN adduser quart --disabled-password 

WORKDIR /home/quart

RUN apt-get update -y

RUN apt-get upgrade -y

COPY socketapp/requirements.txt ./

RUN pip install --no-cache-dir -r requirements.txt

COPY socketapp/ /home/quart/

RUN chmod +x boot.sh 

ENTRYPOINT ["sh", "./boot.sh"]