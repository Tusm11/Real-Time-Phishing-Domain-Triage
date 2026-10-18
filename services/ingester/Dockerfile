FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_DEFAULT_TIMEOUT=180 \
    PIP_RETRIES=10

WORKDIR /app

# System deps for websockets + healthcheck wget
RUN apt-get update && apt-get install -y --no-install-recommends \
      wget \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

# Non-root
RUN useradd -r -u 1000 app && chown -R app:app /app
USER app

EXPOSE 9101
CMD ["python", "-u", "main.py"]
