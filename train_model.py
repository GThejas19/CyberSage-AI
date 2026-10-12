
from pathlib import Path
import os

import joblib
import pandas as pd

from sklearn.model_selection import (
    train_test_split,
    StratifiedKFold,
    cross_validate,
)
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score,
)


# --------------------------------------------------
# CONFIGURATION
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
DATASET_PATH = BASE_DIR / "dataset.csv"
MODEL_PATH = BASE_DIR / "phishing_model.joblib"

LABELS = ["legitimate", "phishing"]


# --------------------------------------------------
# BUILD MACHINE LEARNING MODEL
# --------------------------------------------------

def build_model():
    """Create the CyberSage text-classification pipeline."""

    return Pipeline([
        (
            "tfidf",
            TfidfVectorizer(
                lowercase=True,
                ngram_range=(1, 2),
                strip_accents="unicode",
                sublinear_tf=True,
            ),
        ),
        (
            "classifier",
            LogisticRegression(
                max_iter=2000,
                class_weight="balanced",
                random_state=42,
            ),
        ),
    ])


# --------------------------------------------------
# TRAIN AND EVALUATE MODEL
# --------------------------------------------------

def main():
    print("=" * 60)
    print("          CyberSage AI - Model Training")
    print("=" * 60)

    # 1. Check dataset
    if not DATASET_PATH.exists():
        raise FileNotFoundError(
            f"Dataset not found: {DATASET_PATH}\n"
            "Place dataset.csv beside train_model.py."
        )

    print("\n[1/7] Loading dataset...")

    data = pd.read_csv(DATASET_PATH)

    required_columns = {"text", "label"}

    if not required_columns.issubset(data.columns):
        raise ValueError(
            "dataset.csv must contain these columns: "
            "'text' and 'label'."
        )

    data = data[["text", "label"]].copy()

    # Clean missing values, text, and labels.
    data = data.dropna(subset=["text", "label"])

    data["text"] = data["text"].astype(str).str.strip()
    data["label"] = (
        data["label"].astype(str).str.strip().str.lower()
    )

    data = data[data["text"] != ""]

    invalid_labels = set(data["label"].unique()) - set(LABELS)

    if invalid_labels:
        raise ValueError(
            f"Invalid labels: {sorted(invalid_labels)}\n"
            "Use only 'legitimate' and 'phishing'."
        )

    # Normalize text for duplicate detection.
    data["_duplicate_key"] = (
        data["text"]
        .str.lower()
        .str.replace(r"\s+", " ", regex=True)
        .str.strip()
    )

    # Remove examples with conflicting labels.
    label_counts_by_text = (
        data.groupby("_duplicate_key")["label"].nunique()
    )

    conflicting_keys = label_counts_by_text[
        label_counts_by_text > 1
    ].index

    if len(conflicting_keys):
        print(
            "Warning: removing "
            f"{len(conflicting_keys)} text entries "
            "with conflicting labels."
        )

        data = data[
            ~data["_duplicate_key"].isin(conflicting_keys)
        ].copy()

    # Remove duplicate examples.
    before = len(data)

    data = data.drop_duplicates(
        subset=["_duplicate_key"]
    )

    duplicates_removed = before - len(data)

    data = (
        data.drop(columns=["_duplicate_key"])
        .reset_index(drop=True)
    )

    print(f"Duplicate examples removed: {duplicates_removed}")
    print(f"Usable examples: {len(data)}")

    print("\nExamples per label:")
    print(data["label"].value_counts().to_string())

    counts = data["label"].value_counts()

    for label in LABELS:
        if counts.get(label, 0) < 4:
            raise ValueError(
                f"At least 4 distinct examples per label "
                f"are required. Insufficient examples for: {label}"
            )

    X = data["text"]
    y = data["label"]

    # 2. Split dataset
    print("\n[2/7] Creating training and test sets...")

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.25,
        random_state=42,
        stratify=y,
    )

    print(f"Training examples: {len(X_train)}")
    print(f"Test examples: {len(X_test)}")

    # 3. Train model
    print("\n[3/7] Training model...")

    model = build_model()
    model.fit(X_train, y_train)

    print("Model training completed.")

    # 4. Evaluate on held-out test set
    print("\n[4/7] Evaluating model...")

    predictions = model.predict(X_test)

    accuracy = accuracy_score(y_test, predictions)

    precision = precision_score(
        y_test,
        predictions,
        pos_label="phishing",
        zero_division=0,
    )

    recall = recall_score(
        y_test,
        predictions,
        pos_label="phishing",
        zero_division=0,
    )

    f1 = f1_score(
        y_test,
        predictions,
        pos_label="phishing",
        zero_division=0,
    )

    print("\n" + "=" * 40)
    print("          TEST METRICS")
    print("=" * 40)

    print(f"Accuracy:  {accuracy * 100:.2f}%")
    print(f"Precision: {precision * 100:.2f}%")
    print(f"Recall:    {recall * 100:.2f}%")
    print(f"F1-score:  {f1 * 100:.2f}%")

    print("\nClassification Report:")

    print(
        classification_report(
            y_test,
            predictions,
            labels=LABELS,
            zero_division=0,
        )
    )

    matrix = confusion_matrix(
        y_test,
        predictions,
        labels=LABELS,
    )

    print("Confusion Matrix:")
    print("Rows = actual; columns = predicted")
    print("Class order:", LABELS)
    print(matrix)

    # 5. Cross-validation using training data only
    print("\n[5/7] Running cross-validation...")

    train_counts = y_train.value_counts()
    folds = min(5, int(train_counts.min()))

    if folds >= 2:
        cv = StratifiedKFold(
            n_splits=folds,
            shuffle=True,
            random_state=42,
        )

        cv_results = cross_validate(
            build_model(),
            X_train,
            y_train,
            cv=cv,
            scoring={
                "accuracy": "accuracy",
                "f1_macro": "f1_macro",
            },
            error_score="raise",
        )

        cv_accuracy = cv_results["test_accuracy"]
        cv_f1 = cv_results["test_f1_macro"]

        print(
            "Cross-validation accuracy: "
            f"{cv_accuracy.mean() * 100:.2f}%"
        )

        print(
            "Accuracy standard deviation: "
            f"{cv_accuracy.std() * 100:.2f}%"
        )

        print(
            "Cross-validation macro F1: "
            f"{cv_f1.mean() * 100:.2f}%"
        )
    else:
        print(
            "Cross-validation skipped: insufficient "
            "examples in the training set."
        )

    # 6. Check prediction probabilities
    print("\n[6/7] Checking probability predictions...")

    if hasattr(model, "predict_proba"):
        probabilities = model.predict_proba(X_test.iloc[:1])[0]

        print("Probability predictions are supported.")
        print("Model classes:", list(model.classes_))

        print("Example test probabilities:")

        for label, probability in zip(
            model.classes_,
            probabilities,
        ):
            print(f"  {label}: {probability * 100:.2f}%")
    else:
        print("Probability predictions are unavailable.")

    # 7. Save model safely
    print("\n[7/7] Saving trained model...")

    temporary_path = MODEL_PATH.with_name(
        MODEL_PATH.name + ".tmp"
    )

    try:
        joblib.dump(model, temporary_path)
        os.replace(temporary_path, MODEL_PATH)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()

    print(f"\nModel saved successfully:\n{MODEL_PATH}")

    print("\n" + "=" * 60)
    print("       TRAINING COMPLETED SUCCESSFULLY")
    print("=" * 60)

    print(
        "\nIMPORTANT: Metrics depend on dataset quality and size. "
        "Good test results do not guarantee real-world phishing "
        "detection accuracy."
    )


# --------------------------------------------------
# ENTRY POINT
# --------------------------------------------------

if __name__ == "__main__":
    main()
