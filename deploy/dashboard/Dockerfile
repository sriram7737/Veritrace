FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir fastapi uvicorn[standard] httpx jinja2 redis
COPY app.py .
COPY templates/ templates/
ENV DASHBOARD_PORT=8501
EXPOSE 8501
HEALTHCHECK --interval=15s --timeout=5s CMD curl -f http://localhost:${DASHBOARD_PORT}/health || exit 1
CMD ["sh", "-c", "uvicorn app:app --host 0.0.0.0 --port ${DASHBOARD_PORT}"]
