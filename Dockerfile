FROM python:3.11-slim

WORKDIR /app

# Install dependencies first to leverage Docker cache
COPY pyproject.toml .
# We need to copy the source to install the package properly
COPY src/ ./src/
COPY config/ ./config/
COPY README.md .

RUN pip install --no-cache-dir .

# Set config path for Docker environment
ENV DBL_GATEWAY_CONTEXT_CONFIG=/app/config/context.json

# Expose the default gateway port
EXPOSE 8010

# Run the gateway
CMD ["dbl-gateway", "serve", "--host", "0.0.0.0", "--port", "8010"]
