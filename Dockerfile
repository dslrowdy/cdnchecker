# Use a more modern and still-slim base image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies (sqlite3 + any others you might need)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/*

# Copy and install requirements first (better layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Expose port (informational – not strictly required)
EXPOSE 5001

# Run with gunicorn + gevent for real concurrency
CMD ["gunicorn", \
     "--worker-class", "gevent", \
     "--workers", "3", \
     "--threads", "20", \
     "--worker-connections", "100", \
     "--timeout", "900", \
     "--graceful-timeout", "30", \
     "--bind", "0.0.0.0:5001", \
     "--log-level", "debug", \
     "app:app"]
