# Dockerfile
FROM nginx:alpine

# Copy Nginx config
COPY nginx.conf /etc/nginx/nginx.conf

# Copy SSL certs
COPY server4-chain.cert.pem /etc/nginx/ssl/fullchain.pem
COPY server4.key.pem /etc/nginx/ssl/key.pem
COPY rootCA.cert.pem /etc/nginx/ssl/client-certificate.pem