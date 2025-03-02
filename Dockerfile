FROM python:3.9-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Set environment variables
ENV FLASK_APP=main.py
ENV FLASK_ENV=production
ENV DEMO_MODE=True

# Create necessary directories
RUN mkdir -p templates static

# Expose the port the app runs on
EXPOSE 5000

# Command to run the application
CMD ["python", "main.py"] 