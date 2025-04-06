# Use official Nginx image
FROM nginx:alpine

COPY ./ejbca.conf /etc/nginx/conf.d/default.conf
COPY ./ssl /etc/nginx/ssl


# Expose HTTP and HTTPS ports
EXPOSE 80 443
