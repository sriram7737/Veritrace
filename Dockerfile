FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY pyproject.toml README.md ./
COPY veritrace ./veritrace

RUN pip install --no-cache-dir -e ".[api,encrypted]"

EXPOSE 8000

CMD ["python", "-m", "uvicorn", "veritrace.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
