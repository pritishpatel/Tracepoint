FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY pyproject.toml README.md ./
COPY tracepoint ./tracepoint
COPY alembic ./alembic
COPY alembic.ini ./alembic.ini
COPY config ./config
COPY scripts ./scripts
COPY sample_data ./sample_data

RUN pip install --no-cache-dir -e .

EXPOSE 8000
CMD ["uvicorn", "tracepoint.app:app", "--host", "0.0.0.0", "--port", "8000"]
