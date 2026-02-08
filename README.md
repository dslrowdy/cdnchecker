# CDN Checker App

## Installing on Another Machine

To set up the project on another machine, follow these steps.

### 1. Clone the Repository

Install Git and Docker:

```bash
git --version
docker --version
docker compose version
```

Install if missing (Ubuntu example):

```bash
sudo apt update
sudo apt install -y git docker.io docker-compose
sudo systemctl start docker
sudo systemctl enable docker
```

Clone the Repository:

```bash
git clone https://github.com/dslrowdy/cdnchecker.git
cd cdnchecker
```

### 2. Set Up Directory Structure

```bash
mkdir -p nginx/certs output data
chmod -R 777 output data
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout nginx/certs/nginx.key \
  -out nginx/certs/nginx.crt \
  -subj "/C=US/ST=State/L=City/O=Organization/OU=Unit/CN=localhost"
```

### 3. Build and Run

```bash
docker compose up --build -d

# Subsequent starts
docker compose up -d

# Verify both processes are running
docker ps -a
```

Ensure these containers are up:

* `cdnchecker-app`
* `nginx:latest`

### 4. Test the Application

Open `https://localhost` and accept the self-signed certificate warning.

Test with domains:

```text
opencart.thepacket.ninja
www.microsoft.com
```

Check `/results` for updates and `output/results.xlsx`.

Check logs:

```bash
docker compose -p cdnchecker logs app
or
docker compose logs app
```

### 5. Stop the Application

```bash
docker compose -p cdnchecker down
or
docker compose down
```

### Notes

* Included files: `app.py`, `Dockerfile`, `docker-compose.yml`, `nginx/nginx.conf`, `requirements.txt`, `.gitignore`
* Excluded files: `output/`, `data/`, `nginx/certs/`
* Streaming requires `nginx.conf` with:

```nginx
proxy_buffering off;
chunked_transfer_encoding on;
```

* DNS servers: 8.8.8.8, 8.8.4.4, 1.1.1.1 (3s timeout)
* Gunicorn timeout: 3600s, per-domain timeout: 40s

### Troubleshooting

**Git push fails:**

```bash
git push -u origin main
```

**Docker logs:**

```bash
docker compose -p cdn-checker-app logs app
docker compose -p cdn-checker-app logs nginx
```

**Test inside container:**

```bash
docker exec -it cdn-checker-app-app-1 curl http://localhost:5001
```
