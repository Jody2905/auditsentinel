FROM python:3.12-slim

# Don't write .pyc files, and print logs immediately
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    AUDITSENTINEL_HOST=0.0.0.0

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Run as an ordinary user, not root, so a bug in the app can't take over the container
RUN useradd --create-home sentinel && chown -R sentinel:sentinel /app
USER sentinel

EXPOSE 5000

# Build a fresh demo database, then start the dashboard
CMD ["sh", "-c", "python -c 'from db import init_db; init_db(reset=True)' && python generate_logs.py && python ingest.py && python detect.py && python app.py"]
