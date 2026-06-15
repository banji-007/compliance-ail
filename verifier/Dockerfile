FROM python:3.11-slim
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .

# Non-root user; verifier-state volume is owned by root at mount time,
# so the container runs as root to write the state file. In a hardened
# deployment replace with a named uid and chown the volume at init.
EXPOSE 8003

CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8003", "--workers", "1"]
