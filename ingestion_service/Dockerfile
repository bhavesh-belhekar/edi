FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements from parent
COPY requirements.txt /app/requirements.txt

# Install Python dependencies
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copy entire app (mounted via docker-compose)
COPY . /app

# Set environment
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

# Create state and logs directories
RUN mkdir -p /app/state /app/logs

# Run ingestion service
CMD ["python", "/app/ingestion_service/main.py"]
