import os
import pickle
import numpy as np
import pandas as pd
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
def train_and_save_models():
    # Setup directories (relative to this file's location so training runs on any machine/OS)
    base_dir = os.path.dirname(os.path.abspath(__file__))
    models_dir = os.path.join(base_dir, "models")
    # Datasets can live anywhere; default to a "datasets" folder next to this script, but allow
    # overriding via environment variables for people who keep their CSVs elsewhere.
    datasets_dir = os.getenv("DATASETS_DIR", os.path.join(base_dir, "datasets"))
    os.makedirs(models_dir, exist_ok=True)
    print("--- Starting Model Training ---")
    # 1. PHISHING MODEL
    phishing_path = os.getenv("PHISHING_DATASET_PATH", os.path.join(datasets_dir, "Phishing Dataset.csv"))
    if os.path.exists(phishing_path):
        print(f"Loading Phishing Dataset from: {phishing_path}")
        df_phish = pd.read_csv(phishing_path)
        # Target: suspicious_activity
        # We can drop year/month/day if we want, or keep them. Let's keep features that can be parsed
        X_phish = df_phish.drop(columns=['suspicious_activity'])
        y_phish = df_phish['suspicious_activity']
        
        X_train, X_test, y_train, y_test = train_test_split(X_phish, y_phish, test_size=0.2, random_state=42)
        model_phish = XGBClassifier(n_estimators=50, max_depth=4, random_state=42, eval_metric='logloss')
        model_phish.fit(X_train, y_train)
        
        # Save model and columns
        with open(os.path.join(models_dir, "phishing_model.pkl"), "wb") as f:
            pickle.dump((model_phish, list(X_phish.columns)), f)
        print(f"Phishing Model trained. Accuracy: {model_phish.score(X_test, y_test):.4f}")
    else:
        print("Phishing Dataset not found!")
    # 2. FRAUD MODEL
    fraud_path = os.getenv("FRAUD_DATASET_PATH", os.path.join(datasets_dir, "Fraud Dataset.csv"))
    if os.path.exists(fraud_path):
        print(f"Loading Fraud Dataset from: {fraud_path}")
        df_fraud = pd.read_csv(fraud_path)
        # Target: fraudulent
        X_fraud = df_fraud.drop(columns=['fraudulent'])
        y_fraud = df_fraud['fraudulent']
        
        X_train, X_test, y_train, y_test = train_test_split(X_fraud, y_fraud, test_size=0.2, random_state=42)
        model_fraud = XGBClassifier(n_estimators=50, max_depth=4, random_state=42, eval_metric='logloss')
        model_fraud.fit(X_train, y_train)
        
        # Save model and columns
        with open(os.path.join(models_dir, "fraud_model.pkl"), "wb") as f:
            pickle.dump((model_fraud, list(X_fraud.columns)), f)
        print(f"Fraud Model trained. Accuracy: {model_fraud.score(X_test, y_test):.4f}")
    else:
        print("Fraud Dataset not found!")
    # 3. AML MODEL
    aml_path = os.getenv("AML_DATASET_PATH", os.path.join(datasets_dir, "ML Dataset.csv"))
    if os.path.exists(aml_path):
        print(f"Loading AML Dataset from: {aml_path}")
        df_aml = pd.read_csv(aml_path)
        # Columns: typeofaction, sourceid, destinationid, amountofmoney, date, isfraud, typeoffraud, guiltyid, levelofcrime, typeofcrime
        # Target: isfraud
        # Let's clean typeofaction
        le_action = LabelEncoder()
        df_aml['typeofaction'] = le_action.fit_transform(df_aml['typeofaction'].astype(str))
        
        # Drop columns that are text or represent identifiers that are less general
        features = ['typeofaction', 'sourceid', 'destinationid', 'amountofmoney']
        X_aml = df_aml[features]
        y_aml = df_aml['isfraud'].fillna(0).astype(int)
        
        X_train, X_test, y_train, y_test = train_test_split(X_aml, y_aml, test_size=0.2, random_state=42)
        model_aml = XGBClassifier(n_estimators=50, max_depth=4, random_state=42, eval_metric='logloss')
        model_aml.fit(X_train, y_train)
        
        # Save model, encoder and columns
        with open(os.path.join(models_dir, "aml_model.pkl"), "wb") as f:
            pickle.dump((model_aml, features, le_action), f)
        print(f"AML Model trained. Accuracy: {model_aml.score(X_test, y_test):.4f}")
    else:
        print("AML Dataset not found!")
    # 4. LOAN ELIGIBILITY MODEL (Synthetic Supervised Dataset based on logical loan rules)
    print("Generating Synthetic Loan Eligibility Dataset...")
    np.random.seed(42)
    n_samples = 5000
    
    # Feature ranges
    income = np.random.uniform(15000, 150000, n_samples) # Monthly income
    existing_emi = np.random.uniform(0, 50000, n_samples)
    existing_loans = np.random.randint(0, 6, n_samples)
    employment_status = np.random.randint(0, 3, n_samples) # 0: Unemployed, 1: Self-employed, 2: Salaried
    savings = np.random.uniform(1000, 200000, n_samples)
    
    # Risks from previous checks
    fraud_result = np.random.choice([0, 1], size=n_samples, p=[0.9, 0.1])
    aml_result = np.random.choice([0, 1, 2], size=n_samples, p=[0.85, 0.1, 0.05]) # 0: Low, 1: Medium, 2: High Risk
    identity_verified_result = np.random.choice([0, 1], size=n_samples, p=[0.05, 0.95])
    
    # Calculate eligibility label dynamically based on logical financial standards
    # dti = debt to income ratio
    dti = existing_emi / (income + 1.0)
    
    eligible = []
    for i in range(n_samples):
        # Base criteria
        is_clean = (fraud_result[i] == 0) and (aml_result[i] < 2) and (identity_verified_result[i] == 1)
        is_financially_sound = (dti[i] < 0.45) and (income[i] > 25000) and (existing_loans[i] < 4)
        
        # Determine score
        score = 0.0
        if is_clean:
            score += 0.5
        if is_financially_sound:
            score += 0.4
        if employment_status[i] >= 1: # Employed
            score += 0.1
        if savings[i] > 10000:
            score += 0.1
            
        # Target assignment with noise
        label = 1 if (score >= 0.7 and np.random.random() < 0.95) or (score < 0.7 and np.random.random() < 0.05) else 0
        eligible.append(label)
        
    df_elig = pd.DataFrame({
        'income': income,
        'existing_emi': existing_emi,
        'existing_loans': existing_loans,
        'employment_status': employment_status,
        'savings': savings,
        'fraud_result': fraud_result,
        'aml_result': aml_result,
        'identity_verified_result': identity_verified_result,
        'eligible': eligible
    })
    
    X_elig = df_elig.drop(columns=['eligible'])
    y_elig = df_elig['eligible']
    
    X_train, X_test, y_train, y_test = train_test_split(X_elig, y_elig, test_size=0.2, random_state=42)
    model_elig = XGBClassifier(n_estimators=50, max_depth=4, random_state=42, eval_metric='logloss')
    model_elig.fit(X_train, y_train)
    
    # Save model and columns
    with open(os.path.join(models_dir, "eligibility_model.pkl"), "wb") as f:
        pickle.dump((model_elig, list(X_elig.columns)), f)
    print(f"Eligibility Model trained. Accuracy: {model_elig.score(X_test, y_test):.4f}")
    
    print("--- Model Training Complete. All models saved! ---")
if __name__ == "__main__":
    train_and_save_models()