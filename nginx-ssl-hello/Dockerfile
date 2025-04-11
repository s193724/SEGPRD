# Dockerfile
FROM nginx:alpine

# Copy Nginx config
COPY nginx/nginx.conf /etc/nginx/nginx.conf

# Copy SSL certs
COPY nginx/server4-chain.cert.pem /etc/nginx/ssl/fullchain.pem
COPY nginx/server4.key.pem /etc/nginx/ssl/key.pem
COPY nginx/intermediateCA.crl /etc/nginx/ssl/intermediateCA.crl
COPY nginx/intermediateCA.cert.pem /etc/nginx/ssl/intermediateCA.cert.pem

# Copy static HTML
COPY app/index.html /usr/share/nginx/html/index.html