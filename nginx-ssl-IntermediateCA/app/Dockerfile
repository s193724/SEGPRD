FROM python:3.11-slim

# Set the working directory. This is where the code will be copied to.
# This is also the directory where the python script will be executed.
WORKDIR /app

# Install system dependencies
# Note: in this case we cannot insert openssl inside the requirements.txt since it is
# not a python package, but a system package. So we need to install it separately.
# Also, we need to remove the apt cache to reduce the image size.
RUN apt-get update && apt-get install -y openssl && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY intermediateCAServer.py .
# We should not copy the intermediateCA folder, but using it as a volume (specyfied in the Docker file) because 
# in this way we don't lose the changes made to the folder when we run the container.
# COPY ../PKI_Keys_Gen/intermediateCA /intermediateCA

# We set an environment variable to specify the base directory for the intermediate CA
# In this way, in our python code we can use os.environ['CA_BASE_DIR'] to get the value
# of the environment variable, without need to hardcode the path.
ENV CA_BASE_DIR=/intermediateCA

CMD ["python", "intermediateCAServer.py"]