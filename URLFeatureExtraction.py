# phishing_detector.py

import streamlit as st
from urllib.parse import urlparse, urlencode
import ipaddress
import re
from bs4 import BeautifulSoup
import urllib.request
import requests
from datetime import datetime

# Define the feature extraction functions

def havingIP(url):
    try:
        ipaddress.ip_address(url)
        return 1
    except:
        return 0

def haveAtSign(url):
    return 1 if "@" in url else 0

def getLength(url):
    return 1 if len(url) >= 54 else 0

def getDepth(url):
    s = urlparse(url).path.split('/')
    return sum(1 for i in s if len(i) != 0)

def redirection(url):
    return 1 if url.rfind('//') > 6 else 0

def httpDomain(url):
    return 1 if 'https' in urlparse(url).netloc else 0

shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl"

def tinyURL(url):
    return 1 if re.search(shortening_services, url) else 0

def prefixSuffix(url):
    return 1 if '-' in urlparse(url).netloc else 0

def web_traffic(url):
    try:
        url = urllib.parse.quote(url)
        rank = BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + url).read(), "xml").find("REACH")['RANK']
        return 0 if int(rank) < 100000 else 1
    except:
        return 1

def iframe(response):
    if response == "":
        return 1
    return 0 if re.findall(r"[<iframe>|<frameBorder>]", response.text) else 1

def mouseOver(response):
    if response == "":
        return 1
    return 1 if re.findall("<script>.+onmouseover.+</script>", response.text) else 0

def rightClick(response):
    if response == "":
        return 1
    return 1 if re.findall(r"event.button ?== ?2", response.text) else 0

def forwarding(response):
    if response == "":
        return 1
    return 0 if len(response.history) <= 2 else 1

# Function to extract features from a URL
def featureExtraction(url):
    features = []
    features.append(havingIP(url))
    features.append(haveAtSign(url))
    features.append(getLength(url))
    features.append(getDepth(url))
    features.append(redirection(url))
    features.append(httpDomain(url))
    features.append(tinyURL(url))
    features.append(prefixSuffix(url))

    # HTML & Javascript based features
    try:
        response = requests.get(url)
    except:
        response = ""

    features.append(iframe(response))
    features.append(mouseOver(response))
    features.append(rightClick(response))
    features.append(forwarding(response))

    return features

# Simple rule-based decision to classify phishing or legitimate
def classify_url(features):
    if sum(features) > 4:  # Arbitrary threshold: If more than 4 features indicate phishing, classify as phishing
        return "Phishing"
    else:
        return "Legitimate"

# Streamlit interface
st.title("Phishing URL Detector")
url = st.text_input("Enter a URL to analyze")

if st.button("Check URL"):
    if url:
        features = featureExtraction(url)
        result = classify_url(features)
        st.write("Extracted Features:", features)
        st.write("This URL is classified as:", result)
    else:
        st.write("Please enter a URL.")
