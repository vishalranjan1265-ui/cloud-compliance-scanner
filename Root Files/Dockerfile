FROM python:3.11-slim AS builder
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

FROM python:3.11-slim AS runner
WORKDIR /workspace
RUN groupadd -g 10001 scanner-group && \
    useradd -u 10001 -g scanner-group -s /bin/bash -m scanner-user
COPY --from=builder /root/.local /home/scanner-user/.local
COPY config.yaml .
COPY src/ ./src/
RUN mkdir -p reports && chown -R scanner-user:scanner-group /workspace
USER 10001
ENV PATH=/home/scanner-user/.local/bin:$PATH
ENV PYTHONPATH=/workspace/src
ENTRYPOINT ["python", "src/main.py"]