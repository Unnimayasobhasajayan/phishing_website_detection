# import streamlit as st
# import pandas as pd
# import re
# import datetime
# import requests
# import whois
# from bs4 import BeautifulSoup
# from urllib.parse import urlparse
# import joblib
# model = joblib.load("phishing_model.pkl") 
# def extract_features(url):
#     features = {}
#     features["having_IP_Address"] = 1 if not re.search(r'\d+\.\d+\.\d+\.\d+', url) else -1
#     features["URL_Length"] = 1 if len(url) < 54 else (0 if len(url) <= 75 else -1)
#     features["Shortining_Service"] = 1 if not re.search(r'bit\.ly|tinyurl|goo\.gl|ow\.ly', url) else -1
#     features["having_At_Symbol"] = 1 if "@" not in url else -1
#     features["double_slash_redirecting"] = 1 if "//" not in urlparse(url).path else -1
#     features["Prefix_Suffix"] = 1 if "-" not in urlparse(url).netloc else -1
#     subdomain_count = urlparse(url).netloc.count('.')
#     features["having_Sub_Domain"] = 1 if subdomain_count <= 1 else (0 if subdomain_count == 2 else -1)
#     features["SSLfinal_State"] = 1 if url.startswith("https") else (0 if url.startswith("http://") else -1)
    
#     try:
#         domain_info = whois.whois(urlparse(url).netloc)
#         if hasattr(domain_info, 'expiration_date') and domain_info.expiration_date:
#             if isinstance(domain_info.expiration_date, list):
#                 exp_date = domain_info.expiration_date[0]
#             else:
#                 exp_date = domain_info.expiration_date
#             reg_length = (exp_date - datetime.datetime.now()).days
#             features["Domain_registeration_length"] = 1 if reg_length > 365 else -1
#         else:
#             features["Domain_registeration_length"] = -1
#     except:
#         features["Domain_registeration_length"] = -1
    
#     try:
#         r = requests.get(url, timeout=5)
#         soup = BeautifulSoup(r.text, "html.parser")
#     except:
#         soup = None
    
#     try:
#         favicon = soup.find("link", rel="shortcut icon") if soup else None
#         if favicon and urlparse(favicon.get("href")).netloc == urlparse(url).netloc:
#             features["Favicon"] = 1
#         else:
#             features["Favicon"] = -1
#     except:
#         features["Favicon"] = -1

#     port = urlparse(url).port
#     features["port"] = 1 if port is None or port in [80, 443] else -1  
#     domain = urlparse(url).netloc
#     features["HTTPS_token"] = 1 if "https" not in domain.lower() else -1
    
#     try:
#         external_count = 0
#         total_count = 0
#         if soup:
#             for tag in soup.find_all(["img", "script"]):
#                 src = tag.get("src")
#                 if src:
#                     total_count += 1
#                     if urlparse(src).netloc != urlparse(url).netloc:
#                         external_count += 1
#         if total_count == 0 or (external_count / total_count) < 0.5:
#             features["Request_URL"] = 1
#         else:
#             features["Request_URL"] = -1
#     except:
#         features["Request_URL"] = -1
    
#     # Set placeholders for features not implemented here
#     features["URL_of_Anchor"] = -1
#     features["Links_in_tags"] = -1
#     features["SFH"] = -1
#     features["Submitting_to_email"] = -1
#     features["Abnormal_URL"] = -1
#     features["Redirect"] = -1
#     features["on_mouseover"] = -1
#     features["RightClick"] = -1
#     features["popUpWidnow"] = -1
#     features["Iframe"] = -1
#     features["age_of_domain"] = -1
#     features["DNSRecord"] = -1
#     features["web_traffic"] = -1
#     features["Page_Rank"] = -1
#     features["Google_Index"] = -1
#     features["Links_pointing_to_page"] = -1
#     features["Statistical_report"] = -1
#     return pd.DataFrame([features])
# st.title("🔒 Phishing Website Detector")
# st.write("Enter a URL below to check whether it's **Legitimate** or **Phishy**.")

# url = st.text_input("Enter URL:", "http://192.168.1.100/login@secure-bank.com")

# if st.button("Check URL"):
#     if url:
#         df_features = extract_features(url)
        
#         # Align columns with training features
#         expected_features = model.feature_names_in_
#         df_features = df_features.reindex(columns=expected_features, fill_value=-1)
        
#         # Prediction
#         prediction = model.predict(df_features)
#         probability = model.predict_proba(df_features)
        
#         # Force override for suspicious patterns
#         if re.search(r'\d+\.\d+\.\d+\.\d+', url) and "@" in url:
#             pred_label = "Phishy"
#         else:
#             pred_label = "Legitimate" if prediction[0] == 1 else "Phishy"
        
#         st.subheader(f"Prediction: {pred_label}")
#         st.write("Prediction Probability:", probability)
#     else:
#         st.warning("Please enter a valid URL.")
import streamlit as st
import joblib
import pandas as pd
from urllib.parse import urlparse
import re
import datetime
import whois
import requests
from bs4 import BeautifulSoup

# Load trained model
model = joblib.load("phishing_model.pkl")
def extract_features(url):
    features = {}
    features["having_IP_Address"] = 1 if not re.search(r'\d+\.\d+\.\d+\.\d+', url) else -1
    features["URL_Length"] = 1 if len(url) < 54 else (0 if len(url) <= 75 else -1)
    features["Shortining_Service"] = 1 if not re.search(r'bit\.ly|tinyurl|goo\.gl|ow\.ly', url) else -1
    features["having_At_Symbol"] = 1 if "@" not in url else -1
    features["double_slash_redirecting"] = 1 if "//" not in urlparse(url).path else -1
    features["Prefix_Suffix"] = 1 if "-" not in urlparse(url).netloc else -1
    subdomain_count = urlparse(url).netloc.count('.')
    features["having_Sub_Domain"] = 1 if subdomain_count <= 1 else (0 if subdomain_count == 2 else -1)
    features["SSLfinal_State"] = 1 if url.startswith("https") else (0 if url.startswith("http://") else -1)
    
    try:
        domain_info = whois.whois(urlparse(url).netloc)
        if hasattr(domain_info, 'expiration_date') and domain_info.expiration_date:
            if isinstance(domain_info.expiration_date, list):
                exp_date = domain_info.expiration_date[0]
            else:
                exp_date = domain_info.expiration_date
            reg_length = (exp_date - datetime.datetime.now()).days
            features["Domain_registeration_length"] = 1 if reg_length > 365 else -1
        else:
            features["Domain_registeration_length"] = -1
    except:
        features["Domain_registeration_length"] = -1
    
    try:
        r = requests.get(url, timeout=5)
        soup = BeautifulSoup(r.text, "html.parser")
    except:
        soup = None
    
    try:
        favicon = soup.find("link", rel="shortcut icon") if soup else None
        if favicon and urlparse(favicon.get("href")).netloc == urlparse(url).netloc:
            features["Favicon"] = 1
        else:
            features["Favicon"] = -1
    except:
        features["Favicon"] = -1

    port = urlparse(url).port
    features["port"] = 1 if port is None or port in [80, 443] else -1  
    domain = urlparse(url).netloc
    features["HTTPS_token"] = 1 if "https" not in domain.lower() else -1
    
    try:
        external_count = 0
        total_count = 0
        if soup:
            for tag in soup.find_all(["img", "script"]):
                src = tag.get("src")
                if src:
                    total_count += 1
                    if urlparse(src).netloc != urlparse(url).netloc:
                        external_count += 1
        if total_count == 0 or (external_count / total_count) < 0.5:
            features["Request_URL"] = 1
        else:
            features["Request_URL"] = -1
    except:
        features["Request_URL"] = -1
    
    # Set placeholders for features not implemented here
    features["URL_of_Anchor"] = -1
    features["Links_in_tags"] = -1
    features["SFH"] = -1
    features["Submitting_to_email"] = -1
    features["Abnormal_URL"] = -1
    features["Redirect"] = -1
    features["on_mouseover"] = -1
    features["RightClick"] = -1
    features["popUpWidnow"] = -1
    features["Iframe"] = -1
    features["age_of_domain"] = -1
    features["DNSRecord"] = -1
    features["web_traffic"] = -1
    features["Page_Rank"] = -1
    features["Google_Index"] = -1
    features["Links_pointing_to_page"] = -1
    features["Statistical_report"] = -1
    return pd.DataFrame([features])


# Page Config
st.set_page_config(
    page_title="Phishing URL Detector",
    page_icon="🛡️",
    layout="centered",
    initial_sidebar_state="collapsed"
)

# Custom CSS for styling
st.markdown("""
    <style>
    .main { background-color: #f8f9fa; }
    .stTextInput > div > div > input {
        border: 2px solid #4CAF50;
        border-radius: 10px;
    }
    .stButton>button {
        background-color: #4CAF50;
        color: white;
        border-radius: 10px;
        padding: 0.6em 1em;
        font-weight: bold;
    }
    .stButton>button:hover {
        background-color: #45a049;
    }
    </style>
""", unsafe_allow_html=True)

# App Title
st.title("🛡️ Phishing Website Detection")
st.write("Enter a URL below to check if it is **Legitimate** or **Phishy**.")

# Input box
url = st.text_input("🔗 Enter URL:", placeholder="e.g. http://secure-bank-login.com")

# Predict button
if st.button("Check URL"):
    if url:
        with st.spinner("Analyzing the URL..."):
            try:
                df_features = extract_features(url)
                prediction = model.predict(df_features)
                probability = model.predict_proba(df_features)[0]

                # Result Display
                if prediction[0] == 1:
                    st.success(f"✅ Legitimate Website")
                    # st.progress(int(probability[1] * 100))
                    # st.write(f"Probability : {probability[1]*100:.2f}%")  # show probability bar
                else:
                    st.error(f"⚠️ Phishy Website")
                    # st.progress(int(probability[0] * 100))
                    # st.write(f"Probability : {probability[1]*100:.2f}%")
                # Expandable: Show features extracted
                with st.expander("🔍 View Extracted Features"):
                    st.dataframe(df_features.T)

            except Exception as e:
                st.error(f"Error while analyzing URL: {e}")
    else:
        st.warning("Please enter a URL first!")

# Footer
st.markdown("---")
st.caption("🔒 Built with Streamlit & Scikit-learn | Detect Phishing Websites in Real-time")
