import csv, re, time
import urllib.request
import urllib.error
import ssl

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

claims = list(csv.DictReader(open("attribution_claims_final_v2.csv", encoding="utf-8")))

# Extract all URLs from evidence_report cells (format: "Name (url) | Name (url) ...")
url_pattern = re.compile(r"\((https?://[^\)]+)\)")

link_rows = []
for c in claims:
    ev = c.get("evidence_report", "")
    urls = url_pattern.findall(ev)
    for u in urls:
        link_rows.append({"claim_id": c["claim_id"], "label": c["label"], "url": u})

print(f"Total links to check: {len(link_rows)}")

def check_url(url, timeout=8):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    try:
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        return resp.getcode()
    except urllib.error.HTTPError as e:
        return e.code
    except Exception as e:
        return f"ERROR: {type(e).__name__}"

results = []
for i, row in enumerate(link_rows):
    code = check_url(row["url"])
    status = "OK" if code == 200 else ("REDIRECT/OK" if isinstance(code, int) and 300 <= code < 400 else "DEAD/CHECK")
    results.append({**row, "http_status": code, "status": status})
    if (i+1) % 20 == 0:
        print(f"  checked {i+1}/{len(link_rows)}")

with open("link_check_results.csv", "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=["claim_id", "label", "url", "http_status", "status"])
    w.writeheader()
    w.writerows(results)

dead = [r for r in results if r["status"] != "OK" and r["status"] != "REDIRECT/OK"]
print(f"\nDone. {len(dead)} of {len(results)} links flagged as dead/uncertain.")
for r in dead:
    print(f"  {r['claim_id']} [{r['label']}] {r['url']} -> {r['http_status']}")
