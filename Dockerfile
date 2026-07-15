FROM python:3.12-slim

WORKDIR /app

COPY requirements-docker.txt .
RUN pip install --no-cache-dir -r requirements-docker.txt

COPY app.py .
COPY sapdante2nmos/ sapdante2nmos/

# config.py resolves the Linux config dir from XDG_CONFIG_HOME
ENV XDG_CONFIG_HOME=/config
VOLUME /config

EXPOSE 8085 8086

CMD ["python", "app.py", "--headless"]
