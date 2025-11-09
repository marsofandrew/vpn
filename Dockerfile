FROM alpine:latest

# Install Xray
RUN apk update && apk add --no-cache ca-certificates wget
RUN wget https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip
RUN unzip Xray-linux-64.zip
RUN chmod +x xray
RUN mkdir -p /var/log/xray

# Add Xray configuration

# Expose port and run Xray
EXPOSE 443
ENTRYPOINT ["./xray"]
CMD ["-config", "/config.json"]
