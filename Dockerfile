FROM python:3.13-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    LTA_DATA_DIR=/app/.lta_data \
    LTA_HOST_HOME=/host-home \
    LTA_COMMAND_TARGET=host \
    LTA_MAX_TOKENS=4096 \
    LTA_TEMPERATURE=0.2 \
    LTA_TOP_P=0.95 \
    LTA_TOP_K=40 \
    LTA_REPEAT_PENALTY=1.1 \
    LLAMA_CPP_BASE_URL=http://127.0.0.1:11435/v1 \
    LLAMA_CPP_MODEL=local-model

RUN apt-get update \
    && apt-get install -y --no-install-recommends util-linux ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml README.md ./
COPY prompts ./prompts
COPY src ./src

RUN pip install --no-cache-dir .

VOLUME ["/app/.lta_data"]
VOLUME ["/host-home"]

EXPOSE 28765

CMD ["python", "-m", "linux_troubleshoot_agent.web", "--host", "0.0.0.0", "--port", "28765"]
