FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      awscli postgresql-client curl && rm -rf /var/lib/apt/lists/*
WORKDIR /srv
COPY agent/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY agent/agent.py /srv/agent.py
COPY dashboard /srv/dashboard
COPY app /app
CMD ["python", "-u", "/srv/agent.py"]
