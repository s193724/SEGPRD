# Use the official Python image
FROM python:3.9-slim

# Set working directory in the container
WORKDIR /app

# Copy the requirements file and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the entire app directory into the container
COPY . .

# Expose the port for the Flask app
EXPOSE 5000

# Command to run the Flask app
CMD ["python", "app.py"]
