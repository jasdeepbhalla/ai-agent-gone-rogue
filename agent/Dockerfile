FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      awscli postgresql-client curl && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY agent/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY agent/agent.py /app/agent.py
COPY dashboard /app/dashboard
COPY app /app/app
CMD ["python", "-u", "/app/agent.py"]
