#!/usr/bin/env python3
import requests
import configparser
import csv
import ipaddress
from datetime import datetime

# ----------------------------
# Helpers
# ----------------------------

def is_local_ip(ip: str) -> bool:
    """Sprawdza czy adres należy do przestrzeni prywatnych (RFC1918)."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return True  # traktujemy błędne adresy jako "lokalne" -> pomijamy




# ----------------------------
# Config
# ----------------------------
cfg = configparser.ConfigParser()
cfg.read("config.cfg")

ES_URL = cfg.get("elasticsearch", "url")
ES_USER = cfg.get("elasticsearch", "user")
ES_PASS = cfg.get("elasticsearch", "pass")
ES_INDEX = cfg.get("elasticsearch", "index")

ABUSEIPDB_KEY = cfg.get("abuseipdb", "api_key", fallback=None)
MISP_URL = cfg.get("misp", "url", fallback=None)
MISP_KEY = cfg.get("misp", "api_key", fallback=None)
ALIENVAULT_KEY = cfg.get("alienvault", "api_key", fallback=None)
VT_KEY = cfg.get("virustotal", "api_key", fallback=None)
IPINFO_KEY = cfg.get("ipinfo", "api_key", fallback=None)

SKIP_LOCAL = cfg.getboolean("misc", "skip_local_ips", fallback=True)

DATE = datetime.now().strftime("%Y-%m-%d")
OUTPUT_HTML = f"ip_report_{DATE}.html"
OUTPUT_CSV = f"ip_report_{DATE}.csv"


def _parse_iso_or_timestamp(dt):
    """Pomocnicza: próbuje sparsować ISO albo unix timestamp; zwraca datetime lub None."""
    if dt is None:
        return None
    try:
        if isinstance(dt, (int, float)):
            return datetime.utcfromtimestamp(int(dt))
        if isinstance(dt, str) and dt.isdigit():
            return datetime.utcfromtimestamp(int(dt))
        # spróbuj ISO (np. "2023-08-27T14:00:00" lub z 'Z'/'+00:00')
        try:
            return datetime.strptime(dt[:19], "%Y-%m-%dT%H:%M:%S")
        except ValueError:
            try:
                return datetime.strptime(dt[:19], "%Y-%m-%d %H:%M:%S")
            except ValueError:
                return None
    except Exception:
        return None



# ----------------------------
# Integracje
# ----------------------------

def fetch_source_ips():
    """Pobiera unikalne srcip z Elasticsearch/Wazuh Indexer"""
    query = {
        "size": 0,
        "aggs": {
            "unique_ips": {
                "terms": {"field": "data.srcip", "size": 100}
            }
        }
    }
    r = requests.post(
        f"{ES_URL}/{ES_INDEX}/_search",
        json=query,
        auth=(ES_USER, ES_PASS),
        verify=False  # Wazuh zwykle self-signed
    )
    r.raise_for_status()
#    print (r)
    return [b["key"] for b in r.json()["aggregations"]["unique_ips"]["buckets"]]



def check_abuseipdb(ip):
    if not ABUSEIPDB_KEY:
        return None
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            params={"ipAddress": ip}
        )
        r.raise_for_status()
        d = r.json().get("data", {})
        return {
            "source": "AbuseIPDB",
            "confidence_score": d.get("abuseConfidenceScore", "N/A"),
            "last_reported": d.get("lastReportedAt", "N/A"),
            "reports": d.get("totalReports", "N/A"),
            "malicious": d.get("abuseConfidenceScore", 0) > 0
        }
    except Exception as e:
        return {"source": "AbuseIPDB", "confidence_score": "N/A",
                "last_reported": "N/A", "reports": "N/A",
                "malicious": False, "error": str(e)}


def check_misp(ip):
    if not (MISP_URL and MISP_KEY):
        return None
    try:
        r = requests.post(
            f"{MISP_URL}/attributes/restSearch",
            headers={"Authorization": MISP_KEY, "Accept": "application/json"},
            json={"type": "ip-dst", "value": ip},
            verify=False
        )
        r.raise_for_status()
        d = r.json()
        hits = d.get("response", {}).get("Attribute", [])
        return {
            "source": "MISP",
            "confidence_score": "N/A",
            "last_reported": "N/A",
            "reports": len(hits),
            "malicious": len(hits) > 0,
            "additional_info": f"Events: {[a.get('event_id') for a in hits]}"
        }
    except Exception as e:
        return {"source": "MISP", "confidence_score": "N/A",
                "last_reported": "N/A", "reports": "N/A",
                "malicious": False, "error": str(e)}

def check_alienvault(ip):
    """Bezpieczna integracja z OTX. Zawsze zwraca dict — nie umieszcza surowych wyjątków w raporcie."""
    if not ALIENVAULT_KEY:
        return None

    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
        r = requests.get(url, headers={"X-OTX-API-KEY": ALIENVAULT_KEY}, timeout=20)
        # jeśli status != 200 -> obsłużymy to poniżej
        r.raise_for_status()
        d = r.json() if r.content else {}

        pulse_info = d.get("pulse_info") or {}
        pulses_raw = pulse_info.get("pulses", [])

        # Normalizuj pulses do listy słowników
        pulses = []
        if isinstance(pulses_raw, list):
            pulses = [p for p in pulses_raw if isinstance(p, dict)]
        elif isinstance(pulses_raw, dict):
            pulses = [pulses_raw]
        else:
            # np. 0 lub int -> pusta lista
            pulses = []

        reports_count = len(pulses)

        # Wyciągnij daty z pulsów (safe)
        last_dates = []
        for p in pulses:
            # różne pola: 'modified', 'created', 'timestamp'
            dt_candidate = None
            if isinstance(p, dict):
                for fld in ("modified", "created", "timestamp"):
                    if fld in p and p[fld]:
                        dt_candidate = p[fld]
                        break
            parsed = _parse_iso_or_timestamp(dt_candidate)
            if parsed:
                last_dates.append(parsed)

        # fallback na reputation.updated
        if last_dates:
            last_rep = max(last_dates).strftime("%Y-%m-%d %H:%M:%S")
        else:
            rep = (d.get("reputation") or {}).get("updated")
            parsed_rep = _parse_iso_or_timestamp(rep)
            last_rep = parsed_rep.strftime("%Y-%m-%d %H:%M:%S") if parsed_rep else "N/A"

        pulse_ids = [p.get("id") for p in pulses if isinstance(p, dict) and "id" in p]

        return {
            "source": "AlienVault OTX",
            "confidence_score": "N/A",
            "last_reported": last_rep,
            "reports": reports_count,
            "malicious": reports_count > 0,
            "additional_info": f"Pulses: {pulse_ids}"
        }

    except requests.HTTPError as e:
        # logujemy szczegóły na stderr, do pliku logów itp.
        print(f"[WARN] OTX HTTP error for {ip}: {e}", file=sys.stderr)
        return {
            "source": "AlienVault OTX",
            "confidence_score": "N/A",
            "last_reported": "N/A",
            "reports": 0,
            "malicious": False,
            "additional_info": "OTX HTTP error"
        }
    except Exception as e:
        # nie wrzucamy surowego e do raportu – tylko log i czytelny komunikat
        print(f"[WARN] OTX parse error for {ip}: {e}", file=sys.stderr)
        return {
            "source": "AlienVault OTX",
            "confidence_score": "N/A",
            "last_reported": "N/A",
            "reports": 0,
            "malicious": False,
            "additional_info": "OTX parse error"
        }



def check_virustotal(ip):
    if not VT_KEY:
        return None
    try:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        r = requests.get(url, headers={"x-apikey": VT_KEY})
        r.raise_for_status()
        d = r.json().get("data", {}).get("attributes", {})
        last_analysis = d.get("last_analysis_stats", {})
        malicious = last_analysis.get("malicious", 0)
        # Konwersja utime do czytelnej daty
        last_rep_ts = d.get("last_analysis_date")
        if last_rep_ts:
            last_rep = datetime.utcfromtimestamp(last_rep_ts).strftime("%Y-%m-%d %H:%M:%S")
        else:
            last_rep = "N/A"

        return {
            "source": "VirusTotal",
            "confidence_score": "N/A",
            "last_reported": last_rep,
            "reports": malicious,
            "malicious": malicious > 0
        }
    except Exception as e:
        return {"source": "VirusTotal", "confidence_score": "N/A",
                "last_reported": "N/A", "reports": "N/A",
                "malicious": False, "error": str(e)}

def check_ipinfo(ip):
    if not IPINFO_KEY:
        return None
    try:
        url = f"https://ipinfo.io/{ip}?token={IPINFO_KEY}"
        r = requests.get(url)
        r.raise_for_status()
        d = r.json()
        return {
            "source": "ipinfo",
            "confidence_score": "N/A",
            "last_reported": "N/A",
            "reports": "N/A",
            "malicious": False,
            "additional_info": f"Org: {d.get('org')}, City: {d.get('city')}, Country: {d.get('country')}"
        }
    except Exception as e:
        return {"source": "ipinfo", "confidence_score": "N/A",
                "last_reported": "N/A", "reports": "N/A",
                "malicious": False, "error": str(e)}


# ----------------------------
# Raporty
# ----------------------------

def generate_html_report(results):
    with open(OUTPUT_HTML, "w", encoding="utf-8") as f:
        f.write("<!DOCTYPE html><html><head><title>CTI Report</title></head><body>")
        f.write("<h1>CTI Report for Source IPs</h1>")
        f.write("<table border='1'><tr><th>IP</th><th>Source</th><th>Confidence</th>"
                "<th>Last Reported</th><th>Reports</th><th>Malicious</th><th>Additional Info</th></tr>")
        for ip, entries in results.items():
            for entry in entries:
                f.write("<tr>")
                f.write(f"<td>{ip}</td>")
                f.write(f"<td>{entry.get('source')}</td>")
                f.write(f"<td>{entry.get('confidence_score')}</td>")
                f.write(f"<td>{entry.get('last_reported')}</td>")
                f.write(f"<td>{entry.get('reports')}</td>")
                f.write(f"<td>{entry.get('malicious')}</td>")
                f.write(f"<td>{entry.get('additional_info','')}</td>")
                f.write("</tr>")
        f.write("</table></body></html>")


def generate_csv_report(results):
    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["IP", "Source", "Confidence", "Last Reported", "Reports", "Malicious", "Additional Info"])
        for ip, entries in results.items():
            for entry in entries:
                writer.writerow([
                    ip,
                    entry.get("source"),
                    entry.get("confidence_score"),
                    entry.get("last_reported"),
                    entry.get("reports"),
                    entry.get("malicious"),
                    entry.get("additional_info", "")
                ])


# ----------------------------
# Main
# ----------------------------

if __name__ == "__main__":
    print("Fetching source IPs from Wazuh Indexer...")
    ips = fetch_source_ips()
    print (ips)
    print(f"Found {len(ips)} IPs in logs.")

    if SKIP_LOCAL:
        ips = [ip for ip in ips if not is_local_ip(ip)]
        print(f"After filtering local IPs: {len(ips)} remain.")

    results = {}
    for ip in ips:
        results[ip] = []
        for checker in (check_abuseipdb, check_misp, check_alienvault, check_virustotal, check_ipinfo):
            res = checker(ip)
##            print(f"[DEBUG] {checker.__name__} -> {res}")
            if res:
                results[ip].append(res)

    generate_html_report(results)
    generate_csv_report(results)

    print(f"Reports generated: {OUTPUT_HTML}, {OUTPUT_CSV}")
