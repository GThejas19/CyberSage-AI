# 🛡️ CyberSage AI — Phishing Detection System

An AI-powered phishing detection web application built with Python, Flask, and Machine Learning to help identify potentially suspicious URLs and messages.

## 📌 About the Project

CyberSage AI analyzes URLs and messages using machine learning predictions and rule-based checks. It provides a risk level to help users recognize potentially dangerous content.

This project was developed as a hands-on learning project in Python, web development, and cybersecurity.

## ✨ Features

* 🔍 **URL Analysis** — Checks URLs for potentially suspicious characteristics.
* 💬 **Message Analysis** — Identifies suspicious language and requests for sensitive information.
* 🤖 **Machine Learning** — Uses a trained model to classify phishing-related inputs.
* 🚦 **Risk Classification** — Displays High, Medium, or Low risk levels.
* 🔐 **User Authentication** — Supports registration and login.
* 📊 **Dashboard** — Displays scan statistics and visual summaries.
* 📝 **Scan History** — Allows users to review their own scan results.
* 📥 **CSV Reports** — Supports exporting scan data.

## 🧰 Technologies Used

* Python
* Flask
* Machine Learning
* scikit-learn
* pandas
* NumPy
* HTML
* CSS
* JavaScript
* SQLite / project database
* Joblib

*Check `requirements.txt` for the actual dependencies used by your project.*

## 📂 Project Structure

```text
CyberSage-AI/
├── app.py
├── analyzer.py
├── database.py
├── auth_db.py
├── train_model.py
├── test_analyzer.py
├── check_model.py
├── requirements.txt
├── dataset.csv
├── phishing_model.joblib
├── templates/
├── static/
└── README.md
```

*This is the expected structure based on the project files. Adjust it to match the files actually uploaded to your repository.*

## ⚙️ Installation and Setup

### 1. Clone the repository

```bash
git clone https://github.com/GThejas19/CyberSage-AI.git
cd CyberSage-AI
```

### 2. Create a virtual environment

```bash
python -m venv venv
```

On Windows, activate it with:

```bash
venv\Scripts\activate
```

### 3. Install dependencies

```bash
python -m pip install -r requirements.txt
```

### 4. Run the application

```bash
python app.py
```

Open your browser and visit:

```text
http://127.0.0.1:5000
```

Follow any additional setup instructions required by the project.

## 🧪 Testing

Run the analyzer tests with:

```bash
python -m pytest test_analyzer.py
```

If pytest is not installed, install it with:

```bash
python -m pip install pytest
```

## 🔎 How It Works

1. The user submits a URL or message for analysis.
2. The application checks the input for suspicious characteristics.
3. The trained machine learning model contributes to the classification.
4. The analyzer calculates a risk score and assigns a risk category.
5. The application displays the result and records scan history.

## ⚠️ Important Note

CyberSage AI is an educational project. Its results are not a guarantee that a URL or message is safe or malicious. A low-risk result does not guarantee safety, and a high-risk result does not prove malicious intent.

## 🔒 Security and Responsible Use

* Never upload passwords, API keys, secret keys, or private databases.
* Use environment variables for sensitive configuration.
* Do not use real personal or confidential information in test datasets.
* Keep dependencies updated and test security changes before deployment.

## 🚀 Future Improvements

* Improve model evaluation and phishing detection accuracy.
* Add more diverse training data.
* Improve the dashboard and reporting features.
* Add more automated tests.
* Deploy the application securely for online demonstrations.

## 👨‍💻 Developer

**GitHub:** [GThejas19](https://github.com/GThejas19)

---

⭐ If you find this project useful, consider starring the repository!
