from flask import Flask, request, Response, render_template_string, send_file, url_for
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
import time

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Cleanup excel files after one hour when someone accesses
OUTPUT_DIR = './output'
MAX_FILE_AGE = 3600  # 1 hour in seconds

def cleanup_old_files():
    now = time.time()
    if not os.path.exists(OUTPUT_DIR):
        return
    for f in os.listdir(OUTPUT_DIR):
        path = os.path.join(OUTPUT_DIR, f)
        if os.path.isfile(path):
            age = now - os.path.getmtime(path)
            if age > MAX_FILE_AGE:
                try:
                    os.remove(path)
                    logger.info(f"Deleted old file: {f}")
                except Exception as e:
                    logger.warning(f"Failed to delete {f}: {e}")


# DNS resolver setup
resolver = dns.resolver.Resolver()
resolver.nameservers = ['8.8.8.8', '8.8.4.4', '1.1.1.1']
resolver.timeout = 5
resolver.lifetime = 10

# Load ip2asn database
def load_asn_db():
    data_dir = './data'
    os.makedirs(data_dir, exist_ok=True)
    asn_file = os.path.join(data_dir, 'ip2asn-v4.tsv')

    if not os.path.exists(asn_file):
        logger.info("Downloading ip2asn-v4.tsv...")
        url = 'https://iptoasn.com/data/ip2asn-v4.tsv.gz'
        tmp_gz = asn_file + '.tmp.gz'
        tmp_tsv = asn_file + '.tmp'

        with requests.get(url, stream=True) as r:
            r.raise_for_status()
            with open(tmp_gz, 'wb') as f:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)

        with gzip.open(tmp_gz, 'rb') as f_in, open(tmp_tsv, 'wb') as f_out:
            f_out.write(f_in.read())

        os.replace(tmp_tsv, asn_file)
        os.remove(tmp_gz)
        logger.info("ASN DB downloaded and extracted.")

    # Load into memory
    df = pd.read_csv(asn_file, sep='\t', names=['start_ip','end_ip','asn','country','asn_name'])
    ip_ranges = []
    for _, row in df.iterrows():
        start_ip = int(''.join(f'{int(i):08b}' for i in row['start_ip'].split('.')), 2)
        end_ip = int(''.join(f'{int(i):08b}' for i in row['end_ip'].split('.')), 2)
        ip_ranges.append((start_ip, end_ip, row['asn'], row['asn_name']))
    ip_ranges.sort()
    return ip_ranges

asn_db = load_asn_db()
results = []

# CDN detection patterns
cdn_dict = {
    'Akamai': ['akamai.net','akamaiedge.net','edgesuite.net','edgekey.net','akamaitechnologies.com','akamaitech.net'],
    'Cloudfront': ['cloudfront.net'],
    'Fastly': ['fastly.net','fastlylb.net'],
    'Cloudflare': ['cloudflare.com','cloudflare.net'],
    'Imperva': ['incapdns.net'],
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

cdn_header_sigs = {
    'Akamai': {'headers':['x-akamai-request-id','x-akamai-session-info','x-akamai-edgescape'], 'server':'akamai'},
    'Cloudfront': {'headers':['x-amz-cf-pop','x-amz-cf-id','x-amz-id-2','x-amz-request-id'], 'server':'amazonaws'},
    'Fastly': {'headers':['x-fastly-request-id','fastly-ff','fastly-debug'], 'server':'fastly'},
    'Cloudflare': {'headers':['cf-ray','cf-cache-status'], 'server':'cloudflare'},
    'Imperva': {'headers':['x-iinfo','incap-ses','x-sucuri-id','x-sucuri-cache'], 'value_check':{'x-cdn':'incapsula'}, 'server':'incapsula'},
    'CDN77': {'headers':['x-cache-lb','x-77-cache','x-77-nzt','x-77-pop'], 'server':'cdn77'},
    'KeyCDN': {'headers':['x-edge-ip','x-edge-location','x-pull'], 'server':'keycdn-engine'},
    'Edgecast': {'headers':['x-ec-debug'],'server':'ecacc'},
    'Limelight': {'headers':['x-llid'],'server':'limelight'},
    'Azure CDN': {'headers':['x-azure-ref'],'server':'microsoft-azure-application-gateway'},
    'Google Cloud CDN': {'headers':['x-goog-generation','x-goog-metageneration','x-goog-hash','x-goog-stored-content-length'],'server':'google frontend'},
    'Verizon Digital Media': {'server':'ecacc'},
    'StackPath': {'headers':['x-sp-edge'],'server':'stackpath'},
}

# Utility functions
def get_ip_and_asn(domain):
    try:
        ip = socket.gethostbyname(domain)
    except Exception:
        return 'Unknown','Unknown','Unknown'
    if not asn_db:
        return ip,'Unknown','ASN DB not loaded'
    ip_int = int(''.join(f'{int(i):08b}' for i in ip.split('.')),2)
    start_ips = [r[0] for r in asn_db]
    idx = bisect.bisect_right(start_ips, ip_int)-1
    if idx>=0 and asn_db[idx][0]<=ip_int<=asn_db[idx][1]:
        return ip, str(asn_db[idx][2]), asn_db[idx][3]
    return ip,'Unknown','No ASN match'

def get_cnames(domain):
    cnames=[]
    current=domain.strip().lower()
    seen=set()
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
    best_match=None
    best_evidence=''
    for cname in cnames:
        for cdn,patterns in cdn_dict.items():
            for pat in patterns:
                if pat in cname:
                    if best_match is None or len(cname)>len(best_evidence):
                        best_match=cdn
                        best_evidence=cname
    if best_match: return best_match, f"CNAME:{best_evidence}"
    lower_headers = {k.lower():v.lower() for k,v in headers.items()}
    server=headers.get('Server','').lower()
    for cdn,sigs in cdn_header_sigs.items():
        matched=False
        evidence=''
        if 'server' in sigs and sigs['server'] in server: matched=True; evidence=f"Server:{server}"
        if 'headers' in sigs:
            for h in sigs['headers']:
                if h.lower() in lower_headers:
                    matched=True
                    evidence=f"{h}:{headers[h]}"
                    break
        if 'value_check' in sigs:
            for h,v in sigs['value_check'].items():
                if h.lower() in lower_headers and v in lower_headers[h.lower()]:
                    matched=True
                    evidence=f"{h}:{headers[h]}"
                    break
        if matched: return cdn, evidence
    return 'None','No matching CNAME or header'

def check_login_page(response):
    try:
        soup=BeautifulSoup(response.text,'html.parser')
        text=' '.join(soup.get_text(strip=False).lower().split())
        patterns=[r'(login|sign[- ]?in|signin|auth)', r'(username|password|account)', r'(remember me|forgot password|manage account)']
        for p in patterns:
            m=re.search(p,text,re.I)
            if m: return True,f"Keyword detected:{m.group(0)}"
        forms=soup.find_all('form')
        for f in forms:
            action=f.get('action','').lower()
            if any(re.search(p,action,re.I) for p in patterns): return True,f"Form action:{action}"
            inputs=f.find_all('input')
            has_text=False; has_pass=False
            for inp in inputs:
                t=inp.get('type','').lower(); n=inp.get('name','').lower()
                if t in ['text','email'] or 'username' in n or 'email' in n: has_text=True
                if t=='password' or 'password' in n: has_pass=True
            if has_text and has_pass: return True,'Form with text/email and password detected'
        return False,'No login indicators found'
    except: return False,'Error checking login page'

def check_payment_page(response):
    try:
        soup=BeautifulSoup(response.text,'html.parser')
        text=soup.get_text().lower()
        patterns=[r'\b(payment|checkout|billing|credit card|paypal|stripe)\b', r'\b(card number|expiration date|cvv|cvc)\b', r'\b(purchase|buy now|pay bill|shopping cart)\b']
        for p in patterns:
            m=re.search(p,text,re.I)
            if m: return True,f"Keyword detected:{m.group(0)}"
        return False,'No payment indicators found'
    except: return False,'Error checking payment page'

def process_domain(domain):
    try:
        ip,asn,asn_name=get_ip_and_asn(domain)
        cnames=get_cnames(domain)
        headers={}
        response=None
        session=requests.Session()
        session.max_redirects=10
        user_agents=['Mozilla/5.0 (Windows NT 10.0; Win64; x64)','Mozilla/5.0 (Macintosh)','Mozilla/5.0 (compatible; Googlebot/2.1)']
        for ua in user_agents:
            try: r=session.get(f'https://{domain}',timeout=10,headers={'User-Agent':ua}); headers=r.headers; response=r; break
            except: 
                try: r=session.get(f'http://{domain}',timeout=10,headers={'User-Agent':ua}); headers=r.headers; response=r; break
                except: continue
        cdn,evidence=detect_cdn(cnames,headers)
        has_login,login_ev=check_login_page(response) if response else (False,'No response')
        has_pay,pay_ev=check_payment_page(response) if response else (False,'No response')
        return {'Site':domain,'CDN':cdn,'CDN-Evidence':evidence,'ATO':has_login,'ATO-Evidence':login_ev,
                'CSP':has_pay,'CSP-Evidence':pay_ev,'IP':ip,'ASN':asn,'ASN-Name':asn_name}
    except: return {'Site':domain,'CDN':'Unknown','CDN-Evidence':'Error','ATO':False,'ATO-Evidence':'Error',
                    'CSP':False,'CSP-Evidence':'Error','IP':'Unknown','ASN':'Unknown','ASN-Name':'Error'}

# Streaming results
def stream_results(domains, batch_name):
    import uuid
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
            let t=document.getElementById('results-tbody');
            let r=t.insertRow(-1);
            r.innerHTML=`<td>${res.AccountOwner}</td><td>${res.Site}</td><td>${res.CDN}</td><td>${res['CDN-Evidence']}</td>
            <td>${res.ATO}</td><td>${res['ATO-Evidence']}</td><td>${res.CSP}</td><td>${res['CSP-Evidence']}</td>
            <td>${res.IP}</td><td>${res.ASN}</td><td>${res['ASN-Name']}</td>`;
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
        <p><a href="/view">View Database</a></p>
    </div>
    <table><thead><tr>
    <th>AccountOwner</th><th>Site</th><th>CDN</th><th>CDN-Evidence</th><th>ATO</th><th>ATO-Evidence</th>
    <th>CSP</th><th>CSP-Evidence</th><th>IP</th><th>ASN</th><th>ASN-Name</th>
    </tr></thead><tbody id="results-tbody"></tbody></table>
    '''

    output_dir = './output'
    os.makedirs(output_dir, exist_ok=True)

    # Generate unique Excel filename
    excel_filename = f'results_{uuid.uuid4().hex}.xlsx'
    excel_path = os.path.join(output_dir, excel_filename)

    db_file = os.path.join(output_dir, 'results.db')

    batch_results = []

    # Process each domain
    for domain in domains:
        res = process_domain(domain)
        res['AccountOwner'] = batch_name
        batch_results.append(res)
        results.append(res)
        yield f'<script>appendResult({json.dumps(res)});</script>\n'
        time.sleep(0.05)

    # Save Excel for this batch
    try:
        df = pd.DataFrame(batch_results)

        # Reorder columns so AccountOwner is first
        cols = ['AccountOwner', 'Site', 'CDN', 'CDN-Evidence', 'ATO', 'ATO-Evidence',
                'CSP', 'CSP-Evidence', 'IP', 'ASN', 'ASN-Name']
        df = df[cols]

        df.to_excel(excel_path, index=False)

    except Exception as e:
        yield f'<div style="color:red;">Error saving Excel: {e}</div>'


    # Save to SQLite (optional, keep as-is)
    try:
        conn = sqlite3.connect(db_file)
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS domain_results(
            AccountOwner TEXT, Site TEXT PRIMARY KEY, CDN TEXT, "CDN-Evidence" TEXT, ATO INTEGER, "ATO-Evidence" TEXT,
            CSP INTEGER, "CSP-Evidence" TEXT, IP TEXT, ASN TEXT, "ASN-Name" TEXT
        )''')
        for r in results:
            c.execute('''INSERT OR REPLACE INTO domain_results
                (AccountOwner, Site, CDN, "CDN-Evidence", ATO, "ATO-Evidence", CSP, "CSP-Evidence", IP, ASN, "ASN-Name")
                VALUES (?,?,?,?,?,?,?,?,?,?,?)''',
                (r['AccountOwner'], r['Site'], r['CDN'], r['CDN-Evidence'], int(r['ATO']),
                 r['ATO-Evidence'], int(r['CSP']), r['CSP-Evidence'], r['IP'], r['ASN'], r['ASN-Name'])
            )
        conn.commit()
        conn.close()
    except Exception as e:
        yield f'<div style="color:red;">DB error: {e}</div>'

    # Signal frontend to show download link
    yield f'<script>finish("{excel_filename}");</script></body></html>'

# Routes
@app.route('/',methods=['GET','POST'])
def index():
    cleanup_old_files()
    if request.method=='POST':
        batch_name=request.form.get('batch_name','').strip()
        domains_raw=request.form.get('domains','').strip()
        if not batch_name: return "Batch name required",400
        domains=[d.strip() for d in domains_raw.splitlines() if d.strip()]
        if not domains: return "At least one domain required",400
        return Response(stream_results(domains,batch_name),mimetype='text/html')
    return render_template_string('''
    <html><head><title>Domain CDN Checker</title></head><body>
    <h1>Domain CDN Checker</h1>
    <p>
        <a href="/view">View Database</a>
    </p> 
    <form method="post">
    <label>Account Owner:</label><input type="text" name="batch_name" required style="width:100%"><br>
    <label>Domains (one per line):</label><textarea name="domains" rows="10" required style="width:100%"></textarea><br>
    <button type="submit">Start</button></form>
    </body></html>
    ''')

@app.route('/download')
def download_file():
    file = request.args.get('file')
    if not file:
        return "File parameter missing", 400
    path = os.path.join('./output', file)
    if os.path.exists(path):
        return send_file(path, as_attachment=True, download_name='results.xlsx')
    return "Results not found", 404

@app.route('/view')
def view_results():
    cleanup_old_files()  # optional, keep your DB tidy
    conn = sqlite3.connect('./output/results.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    # Optional filtering by AccountOwner or CDN via query parameters
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

    # Render as HTML table
    html = f"""
    <html><head><title>View Results</title></head><body>
    <h1>Domain Results</h1>
    <form method="get">
        Filter by Account Owner: <input type="text" name="owner" value="{owner}">
        Filter by CDN: <input type="text" name="cdn" value="{cdn}">
        <button type="submit">Filter</button>
    </form>
    <p>
        <a href="/download_filtered?owner={owner or ''}&cdn={cdn or ''}">Download Excel of filtered results</a>
    </p>
    <table border="1" cellpadding="5">
    <tr>
        <th>AccountOwner</th><th>Site</th><th>CDN</th><th>CDN-Evidence</th>
        <th>ATO</th><th>ATO-Evidence</th><th>CSP</th><th>CSP-Evidence</th>
        <th>IP</th><th>ASN</th><th>ASN-Name</th>
    </tr>
    """.format(owner=owner or "", cdn=cdn or "")

    for row in rows:
        html += "<tr>" + "".join(f"<td>{row[col]}</td>" for col in row.keys()) + "</tr>"

    html += "</table></body></html>"
    return html

@app.route('/download_filtered')
def download_filtered():
    owner = request.args.get('owner')
    cdn = request.args.get('cdn')

    conn = sqlite3.connect('./output/results.db')
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
    if filters:
        query += " WHERE " + " AND ".join(filters)

    c.execute(query, params)
    rows = c.fetchall()
    conn.close()

    df = pd.DataFrame([dict(row) for row in rows])
    output_path = './output/temp_filtered.xlsx'
    df.to_excel(output_path, index=False)

    return send_file(output_path, as_attachment=True, download_name='filtered_results.xlsx')


if __name__=='__main__':
    app.run(host='0.0.0.0',port=5001)


