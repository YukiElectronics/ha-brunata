FROM mcr.microsoft.com/devcontainers/python:1-3.12

RUN apt update && \
  apt upgrade -y

RUN apt install -y pre-commit

COPY requirements.txt /

RUN pip install -U 'pip<23.2,>=21.3.1' && \
  pip install -U setuptools wheel && \
  pip install -U -r /requirements.txt
