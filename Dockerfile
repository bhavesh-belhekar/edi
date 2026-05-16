# Use stable Python 3.11 slim image for minimal footprint
FROM python:3.11-slim

# Set environment variables for non-interactive and unbuffered ops
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

# Set the working directory
WORKDIR /app

# Update system dependencies and clean up cache to keep image small
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt /app/
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy the source code into the container
# (In a true production build, we copy things; in dev, we will override this with a volume mount)
COPY . /app/

# By default, provide a help menu or simple entry prompt so the container doesn't immediately exit with an error. 
# We rely on 'docker compose run' to execute specific scripts.
CMD ["python", "synthetic_logs/generate_logs.py", "--help"]