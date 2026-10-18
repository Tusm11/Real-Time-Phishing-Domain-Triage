FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_DEFAULT_TIMEOUT=300 \
    PIP_RETRIES=10 \
    HF_HOME=/app/.cache/huggingface \
    SENTENCE_TRANSFORMERS_HOME=/app/.cache/huggingface

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
      wget build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
# Single-pass install. The --extra-index-url in requirements.txt points pip
# at the CPU-only PyTorch wheels so we skip the ~2GB of CUDA libraries.
RUN pip install --prefer-binary -r requirements.txt

# Warm the embedding model into the image so first container start is fast.
RUN python -c "from sentence_transformers import SentenceTransformer; \
    SentenceTransformer('sentence-transformers/all-MiniLM-L6-v2')"

COPY . .

RUN useradd -r -u 1000 app && chown -R app:app /app
USER app

EXPOSE 9102
CMD ["python", "-u", "main.py"]
