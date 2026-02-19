from flask import Flask, request, Response, redirect, render_template_string, send_file, url_for
from werkzeug.utils import secure_filename
import dns.resolver
import requests
from requests.exceptions import RequestException
from bs4 import BeautifulSoup
import re
import socket
import time
import pandas as pd
import os
import logging
import gzip
import bisect
import json
import sqlite3
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Configure logging for application monitoring
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Setup absolute paths to preserve database file across deployments
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(BASE_DIR, 'output')
DB_DIR = os.path.join(BASE_DIR, 'db')

# Create necessary directories if they don't exist
os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(DB_DIR, exist_ok=True)

# Define database path for persistent storage
DB_PATH = os.path.join(DB_DIR, 'results.db')

# Configuration for file cleanup and uploads
MAX_FILE_AGE = 3600  # 1 hour in seconds
ALLOWED_EXTENSIONS = {'xlsx', 'xls'}
UPLOAD_FOLDER = './uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def cleanup_old_files():
    """
    Clean up Excel files older than MAX_FILE_AGE seconds.
    Prevents accumulation of old result files in the output directory.
    """
    now = time.time()
    if not os.path.exists(OUTPUT_DIR):
        return
    
    # Only process Excel files
    for f in os.listdir(OUTPUT_DIR):
        if not f.endswith(('.xlsx', '.xls')):
            continue

        path = os.path.join(OUTPUT_DIR, f)
        if os.path.isfile(path):
            age = now - os.path.getmtime(path)
            if age > MAX_FILE_AGE:
                try:
                    os.remove(path)
                    logger.info(f"Deleted old file: {f}")
                except Exception as e:
                    logger.warning(f"Failed to delete {f}: {e}")

def allowed_file(filename):
    """
    Check if uploaded file has an allowed extension.
    
    Args:
        filename (str): Name of the file to check
        
    Returns:
        bool: True if file extension is allowed, False otherwise
    """
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# DNS resolver configuration with public DNS servers for reliability
resolver = dns.resolver.Resolver()
resolver.nameservers = ['8.8.8.8', '8.8.4.4', '1.1.1.1']  # Google & Cloudflare DNS
resolver.timeout = 5
resolver.lifetime = 10

def load_asn_db():
    """
    Load IP to ASN mapping database from ip2asn.com.
    Downloads and extracts the database if not present locally.
    Returns sorted list of IP ranges with ASN information for fast lookups.
    """
    data_dir = './data'
    os.makedirs(data_dir, exist_ok=True)
    asn_file = os.path.join(data_dir, 'ip2asn-v4.tsv')

    # Download ASN database if not present
    if not os.path.exists(asn_file):
        logger.info("Downloading ip2asn-v4.tsv...")
        url = 'https://iptoasn.com/data/ip2asn-v4.tsv.gz'
        tmp_gz = asn_file + '.tmp.gz'
        tmp_tsv = asn_file + '.tmp'

        # Stream download to handle large files efficiently
        with requests.get(url, stream=True) as r:
            r.raise_for_status()
            with open(tmp_gz, 'wb') as f:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)

        # Extract gzipped file
        with gzip.open(tmp_gz, 'rb') as f_in, open(tmp_tsv, 'wb') as f_out:
            f_out.write(f_in.read())

        # Replace temporary file with final file
        os.replace(tmp_tsv, asn_file)
        os.remove(tmp_gz)
        logger.info("ASN DB downloaded and extracted.")

    # Load data into memory for fast lookups
    df = pd.read_csv(asn_file, sep='\t', names=['start_ip','end_ip','asn','country','asn_name'])
    ip_ranges = []
    
    # Convert IP addresses to integers for efficient range searching
    for _, row in df.iterrows():
        start_ip = int(''.join(f'{int(i):08b}' for i in row['start_ip'].split('.')), 2)
        end_ip = int(''.join(f'{int(i):08b}' for i in row['end_ip'].split('.')), 2)
        ip_ranges.append((start_ip, end_ip, row['asn'], row['asn_name']))
    
    ip_ranges.sort()  # Sort for binary search
    return ip_ranges

# Global variables for ASN database and results storage
asn_db = load_asn_db()
results = []

# CDN detection patterns - CNAME based detection
cdn_dict = {
    'Akamai': ['akamai.net','akamaiedge.net','edgesuite.net','edgekey.net','akamaitechnologies.com','akamaitech.net'],
    'Cloudfront': ['cloudfront.net'],
    'Fastly': ['fastly.net','fastlylb.net', 'fastly.com'],
    'Cloudflare': ['cloudflare.com','cloudflare.net'],
    'Imperva': ['incapdns.net','impervadns.net'],
    'Sucuri': ['sucuri.net'],
    'CDN77': ['cdn77.com'],
    'KeyCDN': ['kxcdn.com'],
    'Edgecast': ['edgecastcdn.net'],
    'Limelight': ['llnwd.net'],
    'Azure CDN': ['azureedge.net'],
    'Google Cloud CDN': ['googleusercontent.com','ghs.googlehosted.com'],
    'Verizon Digital Media': ['footprint.net'],
    'StackPath': ['cdn.jsdelivr.net','maxcdn.bootstrapcdn.com'],
}

# CDN detection patterns - HTTP header based detection
# Updated CDN header signatures with improved Fastly detection
cdn_header_sigs = {
    'Imperva': {
        'headers': ['x-iinfo', 'incap-ses'],
        'value_check': {'x-cdn': 'incapsula'},
        'server': 'incapsula'
    },
    'Akamai': {
        'headers': ['x-akamai-request-id', 'x-akamai-session-info', 'x-akamai-edgescape'],
        'server': 'akamai'
    },
    'Cloudflare': {
        'headers': ['cf-ray', 'cf-cache-status'],
        'server': 'cloudflare'
    },
    'Cloudfront': {
        'headers': ['x-amz-cf-pop', 'x-amz-cf-id', 'x-amz-id-2', 'x-amz-request-id'],
        'server': 'amazonaws'
    },
    'Fastly': {
        'headers': [
            'x-served-by',      # Most reliable indicator
            'x-cache',          # Very reliable
            'x-cache-hits',     # Very reliable
            'fastly-debug-path',
            'fastly-debug-ttl',
            'fastly-ff',
        ],
        'server_substrings': ['fastly'],  # Sometimes present in Server header
    },
    'Sucuri': {
        'headers': ['x-sucuri-id', 'x-sucuri-cache'],
        'server': 'sucuri/cloudproxy'
    },
    'Azure CDN': {
        'headers':['x-azure-ref'],
        'server':'microsoft-azure-application-gateway'
    },
    'Google Cloud CDN': {
        'headers':['x-goog-generation','x-goog-metageneration','x-goog-hash','x-goog-stored-content-length'],
        'server':'google frontend'
    },
}

def get_ip_and_asn(domain):
    """
    Resolve domain to IP address and lookup ASN information.
    
    Args:
        domain (str): Domain name to resolve
        
    Returns:
        tuple: (ip_address, asn_number, asn_name) or ('Unknown', 'Unknown', error_message)
    """
    try:
        ip = socket.gethostbyname(domain)
    except Exception:
        return 'Unknown','Unknown','Unknown'
    
    if not asn_db:
        return ip,'Unknown','ASN DB not loaded'
    
    # Convert IP to integer for range comparison
    ip_int = int(''.join(f'{int(i):08b}' for i in ip.split('.')),2)
    start_ips = [r[0] for r in asn_db]
    
    # Binary search for IP range
    idx = bisect.bisect_right(start_ips, ip_int)-1
    if idx>=0 and asn_db[idx][0]<=ip_int<=asn_db[idx][1]:
        return ip, str(asn_db[idx][2]), asn_db[idx][3]
    return ip,'Unknown','No ASN match'

def get_cnames(domain):
    """
    Recursively resolve CNAME records for a domain.
    
    Args:
        domain (str): Domain name to resolve CNAMEs for
        
    Returns:
        list: List of CNAME targets
    """
    cnames=[]
    current=domain.strip().lower()
    seen=set()
    
    # Follow CNAME chain until no more CNAMEs or cycle detected
    while current:
        if current in seen:
            break
        seen.add(current)
        try:
            answers = resolver.resolve(current, 'CNAME')
            for rdata in answers:
                target = str(rdata.target).rstrip('.').lower()
                cnames.append(target)
                current=target
                break
            else:
                break
        except:
            break
    return cnames

def detect_cdn(cnames, headers):
    """
    Detect CDN based on CNAMEs and HTTP response headers.
    Uses a two-step approach: CNAME checking (priority) then header checking.
    
    Args:
        cnames (list): List of CNAME records
        headers (dict): HTTP response headers
        
    Returns:
        tuple: (cdn_name, evidence_string)
    """
    # Step 1: CNAME check - highest priority
    best_match = None
    best_evidence = ''

    for cname in cnames:
        cname_lower = cname.lower()
        for cdn, patterns in cdn_dict.items():
            for pat in patterns:
                if pat in cname_lower:
                    # Prefer longer / more specific match
                    if best_match is None or len(cname) > len(best_evidence):
                        best_match = cdn
                        best_evidence = f"CNAME: {cname}"

    # If we found a solid CNAME match → trust it and return early
    if best_match:
        return best_match, best_evidence

    # Step 2: Only if no CNAME match → check headers
    lower_headers = {k.lower(): v for k, v in headers.items()}

    # Fastly detection - strong / specific indicators
    fastly_evidence = []

    if 'x-served-by' in lower_headers:
        val = headers.get('X-Served-By', '')
        if val.lower().startswith('cache-') or 'cache-' in val.lower():
            fastly_evidence.append(f"X-Served-By: {val}")

    # Fastly debug headers (if present)
    for debug_hdr in ['fastly-debug-path', 'fastly-debug-ttl', 'fastly-ff']:
        if debug_hdr in lower_headers:
            fastly_evidence.append(f"{debug_hdr.title()}: {headers.get(debug_hdr, '')[:60]}...")

    if fastly_evidence:
        return 'Fastly', ' | '.join(fastly_evidence)

    # Fastly fallback: Server header
    server = headers.get('Server', '').lower()
    if 'fastly' in server:
        return 'Fastly', f"Server: {headers.get('Server')}"

    # Generic header checks for other CDNs
    for cdn, sigs in cdn_header_sigs.items():
        if cdn == 'Fastly':  # already handled above
            continue

        matched = False
        evidence = ''

        # Server match
        if 'server' in sigs and sigs['server'] in server:
            matched = True
            evidence = f"Server: {headers.get('Server')}"

        # Any of the signature headers present
        if 'headers' in sigs:
            for h in sigs['headers']:
                if h.lower() in lower_headers:
                    matched = True
                    evidence = f"{h}: {headers.get(h, '')}"
                    break

        # Value-specific check (e.g. Imperva)
        if 'value_check' in sigs:
            for h, expected in sigs['value_check'].items():
                if h.lower() in lower_headers and expected.lower() in lower_headers[h.lower()]:
                    matched = True
                    evidence = f"{h}: {headers[h]}"
                    break

        if matched:
            return cdn, evidence or 'Matched header signature'

    # Final fallback: nothing found
    return 'Unknown', 'No matching CNAME or header'

def check_login_page(response):
    """
    Analyze HTML content to detect login pages.
    
    Args:
        response (requests.Response): HTTP response object
        
    Returns:
        tuple: (has_login_page, evidence_string)
    """
    try:
        soup=BeautifulSoup(response.text,'html.parser')
        text=' '.join(soup.get_text(strip=False).lower().split())
        
        # Common login-related keywords
        patterns=[r'(login|sign[- ]?in|signin|auth)', r'(username|password|account)', r'(remember me|forgot password|manage account)']
        for p in patterns:
            m=re.search(p,text,re.I)
            if m: 
                return True,f"Keyword detected:{m.group(0)}"
        
        # Check forms for login indicators
        forms=soup.find_all('form')
        for f in forms:
            action=f.get('action','').lower()
            if any(re.search(p,action,re.I) for p in patterns): 
                return True,f"Form action:{action}"
            
            inputs=f.find_all('input')
            has_text=False; has_pass=False
            
            # Look for username/password input fields
            for inp in inputs:
                t=inp.get('type','').lower(); n=inp.get('name','').lower()
                if t in ['text','email'] or 'username' in n or 'email' in n: 
                    has_text=True
                if t=='password' or 'password' in n: 
                    has_pass=True
            
            if has_text and has_pass: 
                return True,'Form with text/email and password detected'
        
        return False,'No login indicators found'
    except: 
        return False,'Error checking login page'

def check_payment_page(response):
    """
    Analyze HTML content to detect payment pages.
    
    Args:
        response (requests.Response): HTTP response object
        
    Returns:
        tuple: (has_payment_page, evidence_string)
    """
    try:
        soup=BeautifulSoup(response.text,'html.parser')
        text=soup.get_text().lower()
        
        # Payment-related keywords
        patterns=[
            r'\b(payment|checkout|billing|credit card|paypal|stripe)\b', 
            r'\b(card number|expiration date|cvv|cvc)\b', 
            r'\b(purchase|buy now|pay bill|shopping cart)\b'
        ]
        
        for p in patterns:
            m=re.search(p,text,re.I)
            if m: 
                return True,f"Keyword detected:{m.group(0)}"
        
        return False,'No payment indicators found'
    except: 
        return False,'Error checking payment page'

def process_domain(domain):
    """
    Process a single domain through all checks.
    
    Args:
        domain (str): Domain name to analyze
        
    Returns:
        dict: Dictionary containing analysis results
    """
    try:
        # Get IP and ASN information
        ip,asn,asn_name=get_ip_and_asn(domain)
        
        # Get CNAME records
        cnames = get_cnames(domain)
        
        # Fetch HTTP headers using multiple User-Agents
        headers = {}
        response = None
        session = requests.Session()
        session.max_redirects = 10
        
        # Try different User-Agents to handle various server responses
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
            'Mozilla/5.0 (Macintosh)',
            'Mozilla/5.0 (compatible; Googlebot/2.1)'
        ]
        
        for ua in user_agents:
            try:
                r=session.get(f'https://{domain}',timeout=10,headers={'User-Agent':ua})
                headers = r.headers
                response = r
                break
            except:
                try:
                    r = session.get(f'http://{domain}',timeout=10,headers={'User-Agent':ua})
                    headers = r.headers
                    response = r
                    break
                except:
                    continue

        # Detect CDN
        cdn,evidence = detect_cdn(cnames,headers)
        
        # Check for login and payment pages
        has_login, login_ev=check_login_page(response) if response else (False,'No response')
        has_pay,pay_ev = check_payment_page(response) if response else (False,'No response')
        
        return {
            'Site':domain,
            'CDN':cdn,
            'CDN-Evidence':evidence,
            'ATO Opp':has_login,
            'ATO-Evidence':login_ev,
            'CSP Opp':has_pay,
            'CSP-Evidence':pay_ev,
            'IP':ip,
            'ASN':asn,
            'ASN-Name':asn_name
        }
    except:
        return {
            'Site':domain,
            'CDN':'Unknown',
            'CDN-Evidence':'Error',
            'ATO Opp':False,
            'ATO-Evidence':'Error',
            'CSP Opp':False,
            'CSP-Evidence':'Error',
            'IP':'Unknown',
            'ASN':'Unknown',
            'ASN-Name':'Error'
        }

def stream_results(domains, batch_name, company_map=None):
    """
    Process domains and stream results to client as HTML.
    
    Args:
        domains (list): List of domain names to process
        batch_name (str): Name for this batch of domains
        company_map (dict): Mapping of domain -> company name
        
    Yields:
        str: HTML fragments with JavaScript to update results in real-time
    """
    if company_map is None:
        company_map = {}

    import uuid
    
    # Initial HTML template with JavaScript for dynamic updates
    yield '''
    <!DOCTYPE html>
    <html><head><title>Results</title>
    <style>
        table{border-collapse:collapse;width:100%}
        th,td{border:1px solid #ddd;padding:5px}
        th{background-color:#f2f2f2}
    </style>

    <script>
    function appendResult(res){
        let t = document.getElementById('results-tbody');
        let r = t.insertRow(-1);
        r.innerHTML = `
            <td>${res.AccountOwner || ''}</td>
            <td>${res.CompanyName || ''}</td>
            <td>${res.Site}</td>
            <td>${res.CDN}</td>
            <td>${res['CDN-Evidence'] || ''}</td>
            <td>${res['ATO Opp'] === true ? 'True' : 'False'}</td>
            <td>${res['ATO-Evidence'] || ''}</td>
            <td>${res['CSP Opp'] === true ? 'True' : 'False'}</td>
            <td>${res['CSP-Evidence'] || ''}</td>
            <td>${res['DDoS Opp'] === true ? 'True' : 'False'}</td>
            <td>${res.IP || ''}</td>
            <td>${res.ASN || ''}</td>
            <td>${res['ASN-Name'] || ''}</td>
        `;
    }

    function finish(file){
        document.getElementById('progress').style.display='none';
        let link=document.getElementById('download-link');
        link.href="/download?file="+file;
        document.getElementById('complete').style.display='block';
    }
    </script>

    </head><body>
    <h1>Processing Domains...</h1>
    <div id="progress">Processing...</div>
    <div id="complete" style="display:none">
        <p>Done. <a id="download-link" href="#" target="_blank">Download Excel</a></p>
        <p><a href="/">Search Again</a> – start a new CDN discovery</p>
        <p><a href="/view">View Database</a></p>
    </div>
    <table><thead><tr>
        <th>AccountOwner</th>
        <th>CompanyName</th>
        <th>Site</th><th>CDN</th>
        <th>CDN-Evidence</th>
        <th>ATO Opp</th>
        <th>ATO-Evidence</th>
        <th>CSP Opp</th>
        <th>CSP-Evidence</th>
        <th>DDoS Opp</th>
        <th>IP</th>
        <th>ASN</th>
        <th>ASN-Name</th>
    </tr></thead><tbody id="results-tbody"></tbody></table>
    '''

    output_dir = './output'
    os.makedirs(output_dir, exist_ok=True)

    # Generate unique filename for Excel output
    excel_filename = f'results_{uuid.uuid4().hex}.xlsx'
    excel_path = os.path.join(output_dir, excel_filename)

    batch_results = []
    
    # Process each domain and stream results
    for domain in domains:
        res = process_domain(domain)
        res['AccountOwner'] = batch_name
        company = company_map.get(domain, batch_name) # fallback to batch_name
        res['CompanyName'] = company

        # DDoS Check - Compare CompanyName vs ASN-Name for 5-char sequence
        company_clean = re.sub(r'[^a-z]', '', (company or '').lower())
        asn_clean = re.sub(r'[^a-z]', '', (res.get('ASN-Name') or '').lower())
        has_match = False
        if len(company_clean) >= 5 and len(asn_clean) >= 5:
            for i in range(len(company_clean) - 4):
                substring = company_clean[i:i+5]
                if substring in asn_clean:
                    has_match = True
                    break
        res['DDoS Opp'] = has_match   # ← this MUST be indented here (same level as has_match = False)

        batch_results.append(res)
        results.append(res)
        yield f'<script>appendResult({json.dumps(res)});</script>\n'
        time.sleep(0.05)  # Small delay to prevent overwhelming the client

    # Save results to Excel file
    try:
        df = pd.DataFrame(batch_results)
        # Convert DDoS Opp to "True"/"False" string
        if 'DDoS Opp' in df.columns:
            df['DDoS Opp'] = df['DDoS Opp'].map({True: 'True', False: 'False'})

        # Reorder columns for consistency
        cols = [
            'AccountOwner', 'CompanyName', 'Site', 'CDN', 'CDN-Evidence',
            'ATO Opp', 'ATO-Evidence', 'CSP Opp', 'CSP-Evidence',
            'DDoS Opp', 'IP', 'ASN', 'ASN-Name'
        ]

        # Only include columns that exist
        existing_cols = [c for c in cols if c in df.columns]
        df = df[existing_cols]
        df.to_excel(excel_path, index=False)

    except Exception as e:
        yield f'<div style="color:red;">Error saving Excel: {e}</div>'

    # Save results to SQLite database
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        
        # Create table if it doesn't exist
        c.execute('''CREATE TABLE IF NOT EXISTS domain_results(
            AccountOwner TEXT,
            CompanyName TEXT,
            Site TEXT PRIMARY KEY,
            CDN TEXT,
            "CDN-Evidence" TEXT,
            "ATO Opp" TEXT,
            "ATO-Evidence" TEXT,
            "CSP Opp" TEXT,
            "CSP-Evidence" TEXT,
            "DDoS Opp" TEXT,
            IP TEXT,
            ASN TEXT,
            "ASN-Name" TEXT,
            Timestamp TEXT DEFAULT CURRENT_TIMESTAMP
        )''')
        
        # Insert or update results
        for r in results:
            c.execute('''INSERT OR REPLACE INTO domain_results
                (AccountOwner, CompanyName, Site, CDN, "CDN-Evidence", "ATO Opp", "ATO-Evidence", "CSP Opp", "CSP-Evidence", "DDoS Opp", IP, ASN, "ASN-Name", Timestamp)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?, datetime('now'))''',
                (r['AccountOwner'], r['CompanyName'], r['Site'], r['CDN'], r['CDN-Evidence'], str(r['ATO Opp']),
                 r['ATO-Evidence'], str(r['CSP Opp']), r['CSP-Evidence'], str(r['DDoS Opp']), r['IP'], r['ASN'], r['ASN-Name'])
            )
        conn.commit()
        conn.close()
    except Exception as e:
        yield f'<div style="color:red;">DB error: {e}</div>'

    # Signal completion to frontend
    yield f'''<script>finish("{excel_filename}");</script>
    </body></html>'''

# Flask routes
@app.route('/', methods=['GET', 'POST'])
def index():
    """
    Main page for submitting domains to analyze.
    Supports three input methods: textarea, paste from spreadsheet, or Excel upload.
    Handles both GET (show form) and POST (process domains) requests.
    """
    cleanup_old_files()
    
    if request.method == 'POST':
        batch_name = request.form.get('batch_name', '').strip()
        if not batch_name:
            return "Batch name required", 400

        domains = []
        company_map = {}  # domain → company name

        # Option 1: textarea - simple domain list
        domains_text = request.form.get('domains', '').strip()
        if domains_text:
            domains = [d.strip() for d in domains_text.splitlines() if d.strip()]
            for d in domains:
                company_map[d] = batch_name  # fallback to batch name

        # Option 2: Paste from spreadsheet (Company Name <tab> Domain Name)
        pasted_rows = request.form.get('company_domains', '').strip()
        if pasted_rows:
            for line in pasted_rows.splitlines():
                parts = line.split('\t')
                if len(parts) >= 2:
                    company = parts[0].strip()
                    domain = parts[1].strip()
                    if domain:
                        domains.append(domain)
                        company_map[domain] = company

        # Option 3: Excel file upload (takes priority if both provided)
        if 'file' in request.files:
            file = request.files['file']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)

                try:
                    df_upload = pd.read_excel(filepath)
                    # Expected columns (case insensitive)
                    df_upload.columns = df_upload.columns.str.strip().str.lower()
                    if 'domain name' in df_upload.columns and 'company name' in df_upload.columns:
                        for _, row in df_upload.iterrows():
                            domain = str(row['domain name']).strip()
                            company = str(row['company name']).strip()
                            if domain:
                                domains.append(domain)
                                company_map[domain] = company
                    else:
                        return "Excel must have columns 'Company Name' and 'Domain Name'", 400
                except Exception as e:
                    return f"Error reading Excel: {str(e)}", 400

        if not domains:
            return "Provide domains (textarea or Excel file)", 400

        # Pass company mapping to stream_results
        return Response(stream_results(domains, batch_name, company_map), mimetype='text/html')

    # GET - show form with all input options
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head><title>Domain CDN Checker</title></head>
    <body>
        <h1>Domain CDN Checker</h1>
        <p><a href="/view">View Database</a></p>

        <form method="post" enctype="multipart/form-data">
            <label>Account Owner:</label><br>
            <input type="text" name="batch_name" required placeholder="John Smith" style="width:100%"><br><br>

            <label>
                Option 1: Enter domains manually (one per line):
            <textarea name="domains" rows="6"
                placeholder="www.example.com
shop.example.com"
                style="width:100%"></textarea>
            <br><br>


            <label>
            Option 2: Paste from spreadsheet (Company Name ⇥ Domain Name):
            <br>
            <span style="color: #e63946; font-weight: bold; margin-left: 2px;">*</span>
            <small style="color: #555; font-style: italic;">
                Including <strong>Company Name</strong> helps uncover Network DDoS opps but is blocked by Zscaler
            </small>
            </label><br>
            <textarea name="company_domains" rows="6"
                placeholder="Acme Corp	www.acme.com
Widgets Inc	api.widgets.com"
                style="width:100%"></textarea><br><br>

            <label>Option 3: Upload Excel (.xlsx) with columns
                <b>Company Name</b> and <b>Domain Name</b>:
            <br>
            <span style="color: #e63946; font-weight: bold; margin-left: 2px;">*</span>
            <small style="color: #555; font-style: italic;">
                Including <strong>Company Name</strong> helps uncover Network DDoS opps but is blocked by Zscaler
            </small>
            </label><br>
            <input type="file" name="file" accept=".xlsx,.xls"><br><br>

            <button type="submit">Start Processing</button>
        </form>
    </body>
    </html>
    ''')

@app.route('/download')
def download_file():
    """
    Download generated Excel file.
    
    Query Parameters:
        file (str): Filename to download
        
    Returns:
        File response or error message
    """
    file = request.args.get('file')
    if not file:
        return "File parameter missing", 400
    
    path = os.path.join('./output', file)
    if os.path.exists(path):
        return send_file(path, as_attachment=True, download_name='results.xlsx')
    return "Results not found", 404

@app.route('/view')
def view_results():
    """
    View results stored in SQLite database with filtering capabilities.
    
    Query Parameters:
        owner (str): Filter by AccountOwner
        cdn (str): Filter by CDN
        
    Returns:
        HTML page with results table
    """
    cleanup_old_files()  # Keep database tidy
    
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    # Handle optional filtering
    owner = request.args.get('owner')
    cdn = request.args.get('cdn')

    query = "SELECT * FROM domain_results"
    filters = []
    params = []

    if owner:
        filters.append("AccountOwner = ?")
        params.append(owner)
    if cdn:
        filters.append("CDN = ?")
        params.append(cdn)

    if filters:
        query += " WHERE " + " AND ".join(filters)

    c.execute(query, params)
    rows = c.fetchall()
    conn.close()

    # Generate HTML response with filter form
    owner = request.args.get("owner", "")
    cdn = request.args.get("cdn", "")

    html = f"""
    <html><head><title>View Results</title></head><body>
    <h1>Domain Results</h1>
    <form method="get">
        Filter by Account Owner: <input type="text" name="owner" value="{owner}">
        &nbsp;&nbsp;
        Filter by CDN: <input type="text" name="cdn" value="{cdn}">
        &nbsp;&nbsp;
        Show only last
        <input type="number" name="days" value="30" min="1" max="365" style="width:60px">
        days
        &nbsp;&nbsp;
        <button type="submit">Filter</button>
        &nbsp;&nbsp;
        <a href="/view"><button type="button">Clear Filter</button></a>
    </form>
    <p>
        <a href="/download_filtered?owner={owner or ''}&cdn={cdn or ''}">Download Excel of filtered results</a>
    </p>
    <p><a href="/">Search Again</a> – start a new CDN discovery</p>
    <table border="1" cellpadding="5">
    <tr>
        <th>AccountOwner</th>

        <th>CompanyName</th>
        <th>Site</th>
        <th>CDN</th>
        <th>CDN-Evidence</th>
        <th>ATO Opp</th>
        <th>ATO-Evidence</th>
        <th>CSP Opp</th>
        <th>CSP-Evidence</th>
        <th>DDoS Opp</th>
        <th>IP</th>
        <th>ASN</th>
        <th>ASN-Name</th>
        <th>Timestamp</th>
    </tr>
    """.format(owner=owner or "", cdn=cdn or "")

    for row in rows:
        html += "<tr>" + "".join(f"<td>{row[col]}</td>" for col in row.keys()) + "</tr>"

    html += "</table></body></html>"
    return html

@app.route('/download_filtered')
def download_filtered():
    """
    Download filtered results as Excel file.
    
    Query Parameters:
        owner (str): Filter by AccountOwner
        cdn (str): Filter by CDN
        days (int): Filter by number of recent days
        
    Returns:
        Excel file download response
    """
    owner = request.args.get('owner')
    cdn = request.args.get('cdn')

    # Query database with filters
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    query = "SELECT * FROM domain_results"
    filters = []
    params = []

    if owner:
        filters.append("AccountOwner = ?")
        params.append(owner)
    if cdn:
        filters.append("CDN = ?")
        params.append(cdn)
    
    # Optional date filtering
    days = request.args.get('days')
    if days:
        try:
            days_int = int(days)
            if days_int > 0:
                filters.append("Timestamp >= datetime('now', ?)")
                params.append(f"-{days_int} days")
        except ValueError:
            pass  # ignore invalid days value
            
    if filters:
        query += " WHERE " + " AND ".join(filters)

    c.execute(query, params)
    rows = c.fetchall()
    conn.close()

    # Convert to DataFrame and save as Excel
    df = pd.DataFrame([dict(row) for row in rows])
    output_path = './output/temp_filtered.xlsx'
    df.to_excel(output_path, index=False)

    return send_file(output_path, as_attachment=True, download_name='filtered_results.xlsx')

if __name__=='__main__':
    app.run(host='0.0.0.0', port=5001)

