# Dockerfile
FROM nginx:alpine

# Copy Nginx config
COPY nginx/nginx.conf /etc/nginx/nginx.conf

# Copy SSL certs
COPY nginx/server_with_crl-chain.cert.pem /etc/nginx/ssl/fullchain.pem
COPY nginx/server_with_crl.decrypted.key.pem /etc/nginx/ssl/key.pem

# Copy static HTML
COPY app/index.html /usr/share/nginx/html/index.html