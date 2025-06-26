🔍 Fake Link Detection using Machine Learning
📄 Overview
This project aims to detect malicious or fake URLs using a machine learning model trained 
on a rich dataset of legitimate and malicious links. It leverages URL-based features such as 
character patterns, keyword usage, and structural cues to classify whether a given link is SAFE or Malicious.

📦 Dataset
We used the publicly available Malicious URLs Dataset from Kaggle: 👉 Malicious URLs Dataset – Kaggle

Due to file size limitations on GitHub, we have not uploaded the .csv and .pkl files here.

⚠️ Note:
You can download the dataset from the above link.
When you run the machine learning script provided in this repo, it will automatically train the model and generate the .pkl file (rf_model.pkl) in your local directory.

🧠 Model Details
The model uses features extracted from the structure of the URL:

Count of special characters (., -, /, @, =, _, etc.)
Presence of keywords like login, secure, bank, etc.
Length of the domain and path
Use of IP addresses or abnormal patterns
Use of HTTPS or not
Suspicious symbols (%, #, ?, &, etc.)
Subdomain depth
Many other derived features...
Algorithm Used: Random Forest Classifier

Training Output: Generates rf_model.pkl as a trained model file.

🖥️ Web Interface
A simple web page was built using HTML & CSS to interact with the model.

🧩 Features:
A clean and minimal search bar interface
Users can enter a URL and check whether it's classified as:
✅ SAFE (Green)
🚫 FAKE (Red)
Output is shown immediately with color-coded text
⚙️ How to Run
📥 Download the dataset from Kaggle: https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset

🧪 Run the ML training script:

It will preprocess the data, train the model, and create rf_model.pkl.
🌐 Open the web interface:

Launch index.html in your browser.
Enter a URL in the search bar and check the result.
📊 Results
The model shows high accuracy in identifying malicious URLs.
Feature importance revealed that:
High counts of symbols (@, %, etc.)
Long domain paths
Use of obfuscated IPs
Lack of HTTPS
are strong indicators of fake links.
👨‍💻 Built With
Python (Pandas, scikit-learn)
HTML & CSS
JavaScript (if added for form submission)
Kaggle dataset (Malicious URLs)
📬 Author
Bhuvana
Final Year CSE Student | Machine Learning & Web Enthusiast
📫 GitHub Profile

📜 License
This project is for educational and research purposes only. Use the dataset in accordance with Kaggle’s dataset license.
