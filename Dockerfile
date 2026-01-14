FROM python:3.12-slim

WORKDIR /app

# Clean up apt lists
RUN rm -rf /var/lib/apt/lists/*

# Copy project files
COPY pyproject.toml README.md ./
COPY src/ src/

# Install the package
RUN pip install --no-cache-dir .

# Create exports directory
RUN mkdir -p /app/exports

# Set environment for better terminal support
ENV TERM=xterm-256color
ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["python", "-m", "dnsviz_tui"]
