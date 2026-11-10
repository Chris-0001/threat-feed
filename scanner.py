import time
import requests
import json
from pathlib import Path

VT_API_KEY = "YOUR_VIRUSTOTAL_API_KEY" # Replace this!
CACHE_FILE = Path("data/vt_cache.json")

def load_cache():
    if CACHE_FILE.exists():
        try:
            return json.loads(CACHE_FILE.read_text("utf-8"))
        except json.JSONDecodeError:
            return {}
    return {}

def save_cache(cache):
    CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
    CACHE_FILE.write_text(json.dumps(cache, indent=2), "utf-8")

def scan_url(url, error_log=None):
    cache = load_cache()
    if url in cache:
        return cache[url]

    headers = {"x-apikey": VT_API_KEY}
    is_malicious = False
    try:
        # Step 1: Submit URL
        res = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url})
        res.raise_for_status()
        scan_id = res.json()["data"]["id"]
        
        # Mandatory sleep to respect 4 req/minute limit
        time.sleep(15.5) 
        
        # Step 2: Get Analysis
        analysis = requests.get(f"https://www.virustotal.com/api/v3/analyses/{scan_id}", headers=headers)
        stats = analysis.json()["data"]["attributes"]["stats"]
        
        is_malicious = stats.get("malicious", 0) > 0 or stats.get("suspicious", 0) > 0
    except Exception as e:
        error_msg = f"VT Scan failed for {url}: {e}"
        print(error_msg)
        if error_log is not None:
            error_log.append(error_msg)

    result = {"malicious": is_malicious, "scanned": True}
    cache[url] = result
    save_cache(cache)
    return result