FROM kalilinux/kali-rolling:latest

LABEL maintainer="AEGIS Team"
LABEL description="AEGIS — AI-Augmented Penetration Testing Assistant"

# Avoid prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies and security tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev \
    build-essential \
    # Security tools
    nmap \
    nikto \
    sqlmap \
    gobuster \
    dirb \
    hydra \
    john \
    hashcat \
    enum4linux \
    smbclient \
    sslscan \
    whatweb \
    wafw00f \
    whois \
    dnsutils \
    net-tools \
    curl \
    wget \
    netcat-traditional \
    # Additional tools
    wordlists \
    seclists \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /opt/aegis

# Copy project files
COPY requirements.txt .
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

COPY . .

# Create necessary directories
RUN mkdir -p reports logs data

# Expose API port
EXPOSE 8000

# Environment variables
ENV PYTHONUNBUFFERED=1
ENV LOG_LEVEL=INFO
ENV SAFE_MODE=true

# Default command: start the API server
CMD ["python3", "-m", "uvicorn", "aegis.api.server:app", "--host", "0.0.0.0", "--port", "8000"]
