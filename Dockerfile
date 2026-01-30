# Use Python 3.11 as base image (matches local dev environment)
FROM python:3.11-slim-bookworm

# Set environment variables
ENV NODE_ENV=production
ENV PYTHONUNBUFFERED=1

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    libgl1 \
    libglib2.0-0 \
    libsm6 \
    libxext6 \
    libxrender1 \
    libgomp1 \
    ffmpeg \
    && rm -rf /var/lib/apt/lists/*

# Install Node.js 18
RUN curl -fsSL https://deb.nodesource.com/setup_18.x | bash - \
    && apt-get install -y nodejs

# Set working directory
WORKDIR /app

# Copy models directory first (rarely changes, better caching)
COPY models/ ./models/

# Copy Python requirements and install
COPY backend/requirements.txt ./backend/
RUN pip install --no-cache-dir -r backend/requirements.txt

# Copy Node.js package files and install
COPY backend/package.json backend/package-lock.json ./backend/
WORKDIR /app/backend
RUN npm ci --only=production

# Copy the rest of the backend code
COPY backend/ ./

# Create necessary directories
RUN mkdir -p answers professional_reports sessions local-uploads videos

# Set Python path for the application
ENV PYTHON_PATH=/usr/local/bin/python

# Expose the port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/test || exit 1

# Start the application
CMD ["node", "server.js"]
