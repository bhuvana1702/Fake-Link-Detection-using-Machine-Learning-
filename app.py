from flask import Flask, request, render_template
import pickle
import pandas as pd
from ML_Fake_Link import main  

app = Flask(__name__)

# Load the trained Random Forest model
try:
    with open("rf_model.pkl", "rb") as model_file:
        model = pickle.load(model_file)
except FileNotFoundError:
    print("Error: Model file not found.")
    model = None

# Routes
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    url = request.form.get('url')
    if not url:
        return render_template('index.html', prediction_text="Please enter a URL")
    
    input_features = main(url)
    column_names = [
        'use_of_ip', 'abnormal_url', 'count.', 'count-www', 'count@',
        'count_dir', 'count_embed_domian', 'short_url', 'count-https',
        'count-http', 'count%', 'count?', 'count-', 'count=', 'url_length',
        'hostname_length', 'sus_url', 'count-digits', 'count-letters',
        'fd_length', 'tld_length'
    ]
    
    if len(input_features) != len(column_names):
        return render_template('index.html', prediction_text="Feature extraction mismatch. Please check ML_Fake_Link.py.")
    
    input_features_df = pd.DataFrame([input_features], columns=column_names)
    
    if model:
        prediction = model.predict(input_features_df)[0]
        prediction_text = {
            0: "SAFE",
            1: "DEFACEMENT",
            2: "PHISHING",
            3: "MALWARE"
        }.get(prediction, "UNKNOWN")
    else:
        prediction_text = "Model not available."
    
    return render_template('index.html', prediction_text=f'This URL is {prediction_text}')

if __name__ == '__main__':
    app.run(debug=True)