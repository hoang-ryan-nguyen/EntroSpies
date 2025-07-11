FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /opt/opencti-connector-vietnam-credentials

# Copy requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy connector source
COPY src/ ./src/
COPY config.yml .

# Create non-root user
RUN groupadd -r opencti && useradd -r -g opencti opencti
RUN chown -R opencti:opencti /opt/opencti-connector-vietnam-credentials

# Switch to non-root user
USER opencti

# Set environment variables
ENV PYTHONPATH=/opt/opencti-connector-vietnam-credentials/src

# Run connector
CMD ["python3", "src/vietnam_credentials_connector.py"]