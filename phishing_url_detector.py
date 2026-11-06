
import csv
import json
import math
import re
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from datetime import datetime, timezone

# ==================================================
# INFOZATECH - CYBER SECURITY INTERNSHIP
# TASK 5: PHISHING URL DETECTOR
# ==================================================

DATASET_FILE = "phishing_dataset.csv"

# 1. LABELED STARTER DATASET
# 1 = Phishing
# 0 = Legitimate
#
# These are demonstration examples.
# Use a larger verified dataset for real-world evaluation.

SAMPLE_DATA = [
    ("http://secure-login.example.invalid/account", 1),
    ("http://verify-bank.example.invalid/login", 1),
    ("http://update-password.example.invalid/verify", 1),
    ("http://free-prize.example.invalid/winner", 1),
    ("http://account-alert.example.invalid/signin", 1),
    ("http://confirm-payment.example.invalid/update", 1),
    ("http://urgent-security.example.invalid/login", 1),
    ("http://claim-reward.example.invalid/bonus", 1),
    ("http://secure-wallet.example.invalid/confirm", 1),
    ("http://verify-user.example.invalid/account", 1),
    ("http://login-support.example.invalid/password", 1),
    ("http://bank-alert.example.invalid/secure", 1),

    ("https://www.wikipedia.org", 0),
    ("https://www.wikipedia.org/wiki/Python", 0),
    ("https://www.python.org", 0),
    ("https://www.python.org/about", 0),
    ("https://github.com", 0),
    ("https://github.com/features", 0),
    ("https://www.microsoft.com", 0),
    ("https://www.microsoft.com/en-in", 0),
    ("https://www.google.com", 0),
    ("https://www.google.com/search", 0),
    ("https://www.mozilla.org", 0),
    ("https://www.mozilla.org/en-US/about", 0)
]

# 2. CREATE DATASET IF IT DOES NOT EXIST

def create_dataset():

    try:
        with open(DATASET_FILE, "x", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)
            writer.writerow(["URL", "Label"])

            for url, label in SAMPLE_DATA:
                writer.writerow([
                    url,
                    "Phishing" if label == 1 else "Legitimate"
                ])

        print("Starter dataset created successfully.")

    except FileExistsError:
        print("Existing dataset found.")

# 3. LOAD LABELED DATASET

def load_dataset():

    records = []

    with open(DATASET_FILE, "r", newline="", encoding="utf-8-sig") as file:

        reader = csv.DictReader(file)

        if not reader.fieldnames:
            raise ValueError("Dataset has no column headers.")

        columns = {
            name.strip().lower(): name
            for name in reader.fieldnames
        }

        if "url" not in columns or "label" not in columns:
            raise ValueError(
                "CSV must contain URL and Label columns."
            )

        for row in reader:

            url = (row.get(columns["url"]) or "").strip()
            label = (row.get(columns["label"]) or "").strip().lower()

            if not url:
                continue

            if label in ("1", "phishing", "malicious"):
                records.append((url, 1))

            elif label in ("0", "legitimate", "safe", "benign"):
                records.append((url, 0))

    if not records:
        raise ValueError("No valid labeled URLs found.")

    if len(set(label for _, label in records)) != 2:
        raise ValueError(
            "Dataset must contain both phishing and legitimate URLs."
        )

    return records

# 4. EXTRACT URL FEATURES

def normalize_url(url):

    url = url.strip()

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url

    parsed = urllib.parse.urlparse(url)

    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS URLs are supported.")

    if not parsed.hostname:
        raise ValueError("Invalid URL. Please enter a valid domain.")

    return url, parsed

def extract_features(url):

    normalized, parsed = normalize_url(url)

    length = len(normalized)

    if length < 54:
        length_category = "short"
    elif length <= 75:
        length_category = "medium"
    else:
        length_category = "long"

    features = {
        "url_length": length_category,
        "at_symbol": "yes" if "@" in normalized else "no",
        "https": "yes" if parsed.scheme.lower() == "https" else "no"
    }

    return normalized, parsed.hostname, features

# 5. DOMAIN AGE USING RDAP

def get_domain_age(domain):
    try:
        # Remove www because RDAP needs the registered domain
        domain = domain.lower().strip()

        if domain.startswith("www."):
            domain = domain[4:]

        request = urllib.request.Request(
            "https://rdap.org/domain/" + domain,
            headers={
                "User-Agent": "Mozilla/5.0",
                "Accept": "application/rdap+json"
            }
        )

        with urllib.request.urlopen(request, timeout=15) as response:
            data = json.loads(response.read().decode("utf-8"))

        for event in data.get("events", []):
            action = event.get("eventAction", "").lower()

            if action in ("registration", "registered"):
                date_text = event.get("eventDate", "")

                registration_date = datetime.fromisoformat(
                    date_text.replace("Z", "+00:00")
                )

                age = (
                    datetime.now(timezone.utc) - registration_date
                ).days

                return max(0, age)

        return None

    except Exception as error:
        print("Domain age lookup error:", error)
        return None

def get_age_category(age):

    if age is None:
        return "unknown"

    if age < 180:
        return "new"

    if age < 365:
        return "young"

    return "established"

# 6. NAIVE BAYES CLASSIFICATION MODEL

class NaiveBayesClassifier:

    def __init__(self):

        self.class_counts = Counter()
        self.feature_counts = defaultdict(Counter)
        self.feature_totals = defaultdict(Counter)
        self.feature_values = defaultdict(set)
        self.total = 0

    def train(self, training_data):

        for features, label in training_data:

            self.class_counts[label] += 1
            self.total += 1

            for feature, value in features.items():

                self.feature_counts[label][
                    (feature, value)
                ] += 1

                self.feature_totals[label][feature] += 1

                self.feature_values[feature].add(value)

    def predict_proba(self, features):

        scores = {}

        for label in (0, 1):

            class_count = self.class_counts[label]

            score = math.log(
                (class_count + 1) / (self.total + 2)
            )

            for feature, value in features.items():

                count = self.feature_counts[label][
                    (feature, value)
                ]

                total = self.feature_totals[label][feature]

                possible_values = max(
                    1, len(self.feature_values[feature])
                )

                probability = (
                    count + 1
                ) / (
                    total + possible_values
                )

                score += math.log(probability)

            scores[label] = score

        maximum = max(scores.values())

        probabilities = {
            label: math.exp(score - maximum)
            for label, score in scores.items()
        }

        total_probability = sum(probabilities.values())

        return {
            label: value / total_probability
            for label, value in probabilities.items()
        }

    def predict(self, features):

        probabilities = self.predict_proba(features)

        return max(probabilities, key=probabilities.get)

# 7. STRATIFIED TRAINING AND TESTING SPLIT

def split_dataset(records):

    training_data = []
    testing_data = []

    for label in (0, 1):

        group = [
            record for record in records
            if record[1] == label
        ]

        if len(group) < 2:
            raise ValueError(
                "Each class needs at least two examples."
            )

        # Keep every fourth record for testing.
        for index, record in enumerate(group):

            features = extract_features(record[0])[2]
            item = (features, record[1])

            if index % 4 == 0:
                testing_data.append(item)
            else:
                training_data.append(item)

    return training_data, testing_data

# 8. MODEL EVALUATION

def evaluate_model(model, testing_data):

    correct = 0

    tp = 0
    tn = 0
    fp = 0
    fn = 0

    for features, actual in testing_data:

        predicted = model.predict(features)

        if predicted == actual:
            correct += 1

        if actual == 1 and predicted == 1:
            tp += 1

        elif actual == 0 and predicted == 0:
            tn += 1

        elif actual == 0 and predicted == 1:
            fp += 1

        elif actual == 1 and predicted == 0:
            fn += 1

    accuracy = correct / len(testing_data) * 100

    print("\n========== MODEL EVALUATION ==========")
    print("Training samples:", model.total)
    print("Testing samples:", len(testing_data))
    print("Correct predictions:", correct)
    print("Accuracy: {:.2f}%".format(accuracy))

    print("\nConfusion Matrix:")
    print("True Positive :", tp)
    print("True Negative :", tn)
    print("False Positive:", fp)
    print("False Negative:", fn)

    print("\nLimitations:")
    print("- Small datasets may produce unreliable results.")
    print("- New phishing patterns may not be detected.")
    print("- Model predictions are not security guarantees.")

# 9. INTERACTIVE URL DETECTOR

def check_url(model):

    print("\n========== PHISHING URL DETECTOR ==========")

    url = input("Paste a URL to check: ").strip()

    if not url:
        print("Please enter a URL.")
        return

    try:

        normalized, domain, features = extract_features(url)

        age = get_domain_age(domain)

        probabilities = model.predict_proba(features)

        prediction = model.predict(features)

        phishing_probability = probabilities[1] * 100

        print("\n========== ANALYSIS RESULT ==========")

        print("URL:", normalized)
        print("Domain:", domain)
        print("URL Length:", len(normalized))
        print("@ Symbol:", features["at_symbol"])
        print("HTTPS:", features["https"])

        if age is None:
            print("Domain Age: Could not retrieve")
        else:
            print("Domain Age:", age, "days")

        print("Domain Age Category:", get_age_category(age))

        print(
            "\nPhishing Probability: {:.2f}%".format(
                phishing_probability
            )
        )

        if prediction == 1:
            print("Risk Assessment: HIGH RISK")
            print("Warning: This URL may be a phishing website.")

        else:
            print("Risk Assessment: LOWER MODEL-ESTIMATED RISK")
            print("No phishing pattern detected by this model.")

        print(
            "\nNote: This result is not a security guarantee."
        )

    except ValueError as error:
        print("Input Error:", error)

# 10. MAIN PROGRAM

def main():

    print("========================================")
    print("       PHISHING URL DETECTOR")
    print("       INFOZATECH - TASK 5")
    print("========================================")

    try:

        create_dataset()

        records = load_dataset()

        print("\nTotal labeled URLs:", len(records))

        training_data, testing_data = split_dataset(records)

        model = NaiveBayesClassifier()
        model.train(training_data)

        evaluate_model(model, testing_data)

        while True:

            print("\n1. Check a URL")
            print("2. Exit")

            choice = input("\nEnter your choice: ").strip()

            if choice == "1":
                check_url(model)

            elif choice == "2":
                print(
                    "Thank you for using Phishing URL Detector."
                )
                break

            else:
                print("Invalid choice. Please enter 1 or 2.")

    except (ValueError, OSError, csv.Error) as error:

        print("\nProgram Error:", error)

if __name__ == "__main__":
    main()