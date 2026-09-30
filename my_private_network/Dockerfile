FROM ghcr.io/home-assistant/base:latest

# Python for the app, iputils ping for the reachability dots
# (busybox ping is not used because its options differ).
RUN apk add --no-cache python3 iputils-ping

WORKDIR /app
COPY mpn.py /app/mpn.py

# Persistent data (data.json, backup) lives in /data, which Home Assistant
# keeps across updates and includes in backups.
CMD ["python3", "-u", "/app/mpn.py", "--addon"]
