Installing on Another Machine
To set up the project on another machine, follow these steps:
1. Clone the Repository

Install Git and Docker:

Ensure Git and Docker (with Docker Compose) are installed:
bash> git --version
bash> docker --version
bash> docker-compose --version

Install if missing (e.g., on Ubuntu):
bash> sudo apt update
bash> sudo apt install git docker.io docker-compose
bash> sudo systemctl start docker
bash> sudo systemctl enable docker


Clone the Repository:
bash> git clone https://github.com/dslrowdy/cdn-checker-app.git
cd cdnchecker


2. Set Up Directory Structure

Create Directories:
bash> mkdir -p nginx/certs output data
bash> chmod -R 777 output data

Generate Certificates:
bash> openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout nginx/certs/nginx.key -out nginx/certs/nginx.crt -subj "/C=US/ST=State/L=City/O=Organization/OU=Unit/CN=localhost"


3. Build and Run

Initial Build and Start:
bash> docker compose up --build -d

Subsequent starts:
bash> docker compose up -d

Verify Containers:
bash> docker ps -a

Ensure cdn-checker-app-app-1 and cdn-checker-app-nginx-1 are Up.



4. Test the Application

Access the App:

Open https://localhost (accept self-signed cert warning).
Test with 1 domain (e.g., opencart.thepacket.ninja):

Expect ATO: True, ATO-Evidence: Keyword detected in page text: login.


Test with www.microsoft.com:

Expect ATO: True, ATO-Evidence: Keyword detected in page text: sign in.


Test with 25 and 100 domains (avoid non-resolvable ones like baidu.com).
Check /results for real-time table updates and output/results.xlsx.


Check Logs:
bash> docker-compose -p cdn-checker-app logs app

Look for Extracted text for login check to verify login or sign in.



5. Stop the Application
bash> docker-compose -p cdn-checker-app down
Notes

Files Included: The GitHub repository will include app.py, Dockerfile, docker-compose.yml, nginx/nginx.conf, requirements.txt, and .gitignore. Generated files (output/, data/, nginx/certs/) are excluded via .gitignore.
Streaming: The current app.py uses JavaScript (appendResult) and time.sleep(0.05) for streaming. If the blank page persists, ensure nginx/nginx.conf has proxy_buffering off and chunked_transfer_encoding on.
DNS Failures: Previous logs showed issues with baidu.com. The app.py uses multiple DNS servers (8.8.8.8, 8.8.4.4, 1.1.1.1) with a 3-second timeout, handling failures gracefully.
100 Domains: The 3600-second Gunicorn timeout and 40-second per-domain timeout support 100 domains, capping slow ones like pornhub.com.

Troubleshooting
If pushing to GitHub fails:

Authentication:

Verify your GitHub credentials or token.
Use:
bash> git push -u origin main



Check Repository:

Ensure the repository exists and you have write access.
Visit https://github.com/your-username/cdn-checker-app.



If installation fails on another machine:

Check Logs:
bash> docker-compose -p cdn-checker-app logs app
docker-compose -p cdn-checker-app logs nginx

Look for EPIPE, WORKER TIMEOUT, or DNS errors.


Test App:
bash> docker exec -it cdn-checker-app-app-1 curl http://localhost:5001

Streaming:

Open https://localhost/results, press F12, and check Console/Network for errors.


Share Details:

GitHub repository URL.
Output of git status and git remote -v in /Users/rowdyscott/venv/cdn-checker-app_v3.
Logs from the new machine (docker-compose -p cdn-checker-app logs app).
results.xlsx rows for opencart.thepacket.ninja, www.microsoft.com.
First 5 domains from your 100, plus pornhub.com, baidu.com.



Please push the files to GitHub, share the repository URL, and confirm if the setup works on another machine! If you need specific GitHub commands or run into errors, let me know.
