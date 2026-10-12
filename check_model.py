import joblib
from pathlib import Path

model_path = Path(__file__).resolve().parent / "phishing_model.joblib"
model = joblib.load(model_path)

print("Model type:", type(model).__name__)
print("Classes:", getattr(model, "classes_", "Not available"))
print("Supports probabilities:", hasattr(model, "predict_proba"))