# Dockerfile
FROM nginx:alpine

# Copy Nginx config
COPY nginx/nginx.conf /etc/nginx/nginx.conf

# Copy SSL certs
COPY nginx/server4-chain.cert.pem /etc/nginx/ssl/fullchain.pem
COPY nginx/server4.key.pem /etc/nginx/ssl/key.pem
COPY nginx/rootCA.cert.pem /etc/nginx/ssl/client-certificate.pem