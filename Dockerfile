FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

RUN apt-get update && apt-get install -y sqlite3 && rm -rf /var/lib/apt/lists/*

CMD ["gunicorn", "--bind", "0.0.0.0:5001", "--workers", "2", "--log-level", "debug", "--timeout", "3600", "app:app"]
