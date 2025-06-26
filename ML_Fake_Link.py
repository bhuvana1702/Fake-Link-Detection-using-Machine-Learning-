import pandas as pd
import numpy as np
import re
import joblib
import pickle
import os
from urllib.parse import urlparse
from tld import get_tld

# Function to check if a URL contains an IP address
def having_ip_address(url):
    match = re.search(r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\/)', url)
    return 1 if match else 0

# Function to check for abnormal URLs
def abnormal_url(url):
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        return 1 if not hostname or "@" in url else 0
    except:
        return 1

# Function to count occurrences of a character in a URL
def count_occurrences(url, char):
    return url.count(char)

# Function to count directory levels in a URL
def no_of_dir(url):
    return urlparse(url).path.count('/')

# Function to check for URL shortening services
def shortening_service(url):
    shorteners = r"bit\.ly|goo\.gl|tinyurl|t\.co|ow\.ly|is\.gd|tr\.im|su\.pr"
    return 1 if re.search(shorteners, url) else 0

# Function to compute URL length
def url_length(url):
    return len(url)

# Function to compute hostname length
def hostname_length(url):
    return len(urlparse(url).netloc)

# Function to check for suspicious words
def suspicious_words(url):
    return 1 if re.search(r'paypal|login|signin|bank|account|update|free|lucky', url, re.IGNORECASE) else 0

# Function to count digits in URL
def digit_count(url):
    return sum(c.isdigit() for c in url)

# Function to count letters in URL
def letter_count(url):
    return sum(c.isalpha() for c in url)

# Function to compute first directory length
def fd_length(url):
    try:
        return len(urlparse(url).path.split('/')[1])
    except:
        return 0

# Function to compute TLD length
def tld_length(url):
    try:
        return len(get_tld(url, fail_silently=True) or '')
    except:
        return -1 

# Feature extraction function
def main(url):
    return [
        having_ip_address(url), abnormal_url(url), count_occurrences(url, '.'), count_occurrences(url, 'www'),
        count_occurrences(url, '@'), no_of_dir(url), count_occurrences(url, '//'), shortening_service(url),
        count_occurrences(url, 'https'), count_occurrences(url, 'http'), count_occurrences(url, '%'),
        count_occurrences(url, '?'), count_occurrences(url, '-'), count_occurrences(url, '='),
        url_length(url), hostname_length(url), suspicious_words(url), digit_count(url),
        letter_count(url), fd_length(url), tld_length(url)
    ]

# Run dataset processing & model training only when executed directly
if __name__ == "__main__":
    csv_path = r"C:\Users\Eswar\Desktop\malicious_phish.csv"
    if os.path.exists(csv_path):
        df = pd.read_csv(csv_path)
    
        df['type_code'] = df['type'].astype('category').cat.codes
        
        # Apply feature extraction
        df = df.assign(**{col: df['url'].apply(func) for col, func in {
            'use_of_ip': having_ip_address, 'abnormal_url': abnormal_url, 'count.': lambda x: count_occurrences(x, '.'),
            'count-www': lambda x: count_occurrences(x, 'www'), 'count@': lambda x: count_occurrences(x, '@'),
            'count_dir': no_of_dir, 'count_embed_domian': lambda x: count_occurrences(x, '//'),
            'short_url': shortening_service, 'count-https': lambda x: count_occurrences(x, 'https'),
            'count-http': lambda x: count_occurrences(x, 'http'), 'count%': lambda x: count_occurrences(x, '%'),
            'count?': lambda x: count_occurrences(x, '?'), 'count-': lambda x: count_occurrences(x, '-'),
            'count=': lambda x: count_occurrences(x, '='), 'url_length': url_length,
            'hostname_length': hostname_length, 'sus_url': suspicious_words, 'count-digits': digit_count,
            'count-letters': letter_count, 'fd_length': fd_length, 'tld_length': tld_length
        }.items()})
        
        # Define features and target
        feature_columns = ['use_of_ip', 'abnormal_url', 'count.', 'count-www', 'count@', 'count_dir', 'count_embed_domian', 'short_url', 'count-https',
                            'count-http', 'count%', 'count?', 'count-', 'count=', 'url_length', 'hostname_length', 'sus_url',
                            'count-digits', 'count-letters', 'fd_length', 'tld_length']
        X = df[feature_columns]
        y = df['type_code']
        
        # Check dataset integrity before splitting
        if X.empty or y.empty:
            print("Error: Feature extraction failed. Check input dataset.")
            exit()
        
        # Split data
        from sklearn.model_selection import train_test_split
        X_train, X_test, y_train, y_test = train_test_split(X, y, stratify=y, test_size=0.2, shuffle=True, random_state=5)
        
        # Train model
        # Train model
        from sklearn import metrics
        from sklearn.ensemble import RandomForestClassifier
        rf = RandomForestClassifier(n_estimators=100, max_features='sqrt')
        rf.fit(X_train, y_train)
        y_pred_rf = rf.predict(X_test)
        score = metrics.accuracy_score(y_test, y_pred_rf)
        print("accuracy:   %0.3f" % score)
        
        # Save model
        with open("rf_model.pkl", "wb") as f:
            pickle.dump(rf, f)
        
        print("Model saved successfully.")