# Use official Nginx image
FROM nginx:alpine

# Copy the NGINX config file and PKI directory into the container
COPY ./nginx/ejbca.conf /etc/nginx/conf.d/default.conf
COPY ../pki /etc/nginx/pki
# Expose HTTP and HTTPS ports
EXPOSE 80 443