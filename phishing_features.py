import pandas as pd
import numpy as np
import re
import whois
import datetime
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse




def extract_features(url):
    features = {}

    # 1. Having IP Address
    has_ip = bool(re.search(r'\d+\.\d+\.\d+\.\d+', url))
    features["having_IP_Address"] = -1 if has_ip else 1

    # 2. Having @ Symbol
    features["having_At_Symbol"] = -1 if "@" in url else 1

    # 🚨 Combined Rule: IP + @ → always phishy
    if has_ip and "@" in url:
        features["Abnormal_URL"] = -1
    else:
        features["Abnormal_URL"] = 1

    # 3. URL Length
    features["URL_Length"] = 1 if len(url) < 54 else -1

    # 4. Shortening Service
    features["Shortining_Service"] = -1 if re.search(r'bit\.ly|tinyurl|goo\.gl|ow\.ly', url) else 1

    # 5. Double Slash Redirection
    path = urlparse(url).path
    features["double_slash_redirecting"] = -1 if "//" in path else 1

    # 6. Prefix-Suffix
    features["Prefix_Suffix"] = -1 if "-" in urlparse(url).netloc else 1

    # 7. Subdomain Count
    subdomain_count = urlparse(url).netloc.count('.')
    features["having_Sub_Domain"] = -1 if subdomain_count > 2 else 1

    # 8. SSL Final State (only check scheme, not cert validation here)
    features["SSLfinal_State"] = 1 if url.startswith("https") else -1

    # 9. Right click, mouseover, iframe, popup (default safe=1, suspicious=-1)
    try:
        r = requests.get(url, timeout=5)
        soup = BeautifulSoup(r.text, "html.parser")
    except:
        soup = None

    try:
        features["on_mouseover"] = -1 if soup and soup.find_all(onmouseover=True) else 1
    except:
        features["on_mouseover"] = -1

    try:
        features["RightClick"] = -1 if soup and "contextmenu" in str(soup) else 1
    except:
        features["RightClick"] = -1

    try:
        features["popUpWidnow"] = -1 if soup and ("alert(" in str(soup) or "confirm(" in str(soup)) else 1
    except:
        features["popUpWidnow"] = -1

    try:
        features["Iframe"] = -1 if soup and soup.find_all("iframe") else 1
    except:
        features["Iframe"] = -1

    # 10. Age of Domain (whois)
    try:
        domain_info = whois.whois(urlparse(url).netloc)
        if hasattr(domain_info, 'creation_date') and domain_info.creation_date:
            if isinstance(domain_info.creation_date, list):
                age_days = (datetime.datetime.now() - domain_info.creation_date[0]).days
            else:
                age_days = (datetime.datetime.now() - domain_info.creation_date).days
            features["age_of_domain"] = 1 if age_days > 180 else -1
        else:
            features["age_of_domain"] = -1
    except:
        features["age_of_domain"] = -1

    # 11. DNS Record
    try:
        features["DNSRecord"] = 1 if domain_info else -1
    except:
        features["DNSRecord"] = -1

    # Force unresolved features to phishy by default
    features["web_traffic"] = -1
    features["Page_Rank"] = -1
    features["Google_Index"] = -1
    features["Links_pointing_to_page"] = -1
    features["Statistical_report"] = -1

    return pd.DataFrame([features])
