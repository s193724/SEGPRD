FROM debian:bullseye

RUN apt-get update && apt-get install -y openssl && rm -rf /var/lib/apt/lists/*

WORKDIR /ocsp_server

# This command is used because the server is not started in the foreground
# and the container will exit immediately if it is not running in the foreground
# viene spesso usata nei Dockerfile di servizi “non interattivi” (come ad esempio un OCSP responder basato su openssl 
# da riga di comando) per evitare che il container si chiuda immediatamente quando non c’è un processo da eseguire di default.
CMD ["sleep", "infinity"]