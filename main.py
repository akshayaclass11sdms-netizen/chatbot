import os
import re
import json
import uuid
import shutil
import datetime
from typing import List
from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Form, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
import pydantic
from database import init_db, get_db, DBUser, DBLoginHistory, DBApplication, DBOCRExtracted, DBAnalysisResult
from ml_models import MLModelSuite
app = FastAPI(title="AI Loan Approval Chatbot Backend")
# Enable CORS for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# Setup directories (relative to this file's location so the app runs on any machine/OS)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)
# Initialize database and models
init_db()
ml_suite = MLModelSuite()
# Pydantic Schemas
class RegisterSchema(pydantic.BaseModel):
    email: str
    password: str
class LoginSchema(pydantic.BaseModel):
    email: str
    password: str
class OTPVerifySchema(pydantic.BaseModel):
    email: str
    otp: str
    ip_address: str = "127.0.0.1"
    browser: str = "Unknown"
    device: str = "Unknown"
    os: str = "Unknown"
    location: str = "Unknown"
    failed_attempts: int = 0
class ApplicationSchema(pydantic.BaseModel):
    email: str
    full_name: str
    dob: str
    aadhaar_no: str
    pan_no: str
    income: float
    existing_emi: float
    existing_loans: int
    employment_status: str
    savings: float
    loan_amount: float
    loan_term: int
class DecisionSchema(pydantic.BaseModel):
    application_id: int
    decision: str  # APPROVED, REJECTED, MANUAL REVIEW
    notes: str = ""
@app.on_event("startup")
def startup_event():
    # Insert a dummy user if table is empty, for testing ease
    db = next(get_db())
    try:
        if not db.query(DBUser).first():
            test_user = DBUser(email="customer@example.com", password_hash="password123")
            db.add(test_user)
            db.commit()
            print("Inserted default test user: customer@example.com / password123")
    except Exception as e:
        print(f"Error seeding database: {e}")
    finally:
        db.close()
# --- AUTH ENDPOINTS ---
@app.post("/api/auth/register")
def register(user: RegisterSchema, db: Session = Depends(get_db)):
    db_user = db.query(DBUser).filter(DBUser.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    new_user = DBUser(email=user.email, password_hash=user.password)
    db.add(new_user)
    db.commit()
    return {"message": "Registration successful"}
@app.post("/api/auth/login")
def login(user: LoginSchema, db: Session = Depends(get_db)):
    db_user = db.query(DBUser).filter(DBUser.email == user.email).first()
    if not db_user or db_user.password_hash != user.password:
        # Increment failed login attempt simulation
        return {"status": "error", "message": "Invalid email or password"}
    
    # Generate 6-digit OTP
    import random
    otp = str(random.randint(100000, 999999))
    db_user.otp_secret = otp
    db.commit()
    
    # In a real environment, we would email the OTP. Here we log it to console and return it for the UI mock client
    print(f"\n[EMAIL MOCK] Sending OTP {otp} to {user.email}\n")
    return {"status": "success", "message": "OTP generated and sent to email", "mock_otp": otp}
@app.post("/api/auth/verify-otp")
def verify_otp(payload: OTPVerifySchema, db: Session = Depends(get_db)):
    db_user = db.query(DBUser).filter(DBUser.email == payload.email).first()
    if not db_user or db_user.otp_secret != payload.otp:
        # Log a failed attempt
        login_log = DBLoginHistory(
            email=payload.email,
            ip_address=payload.ip_address,
            browser=payload.browser,
            device=payload.device,
            os=payload.os,
            location=payload.location,
            failed_attempts=payload.failed_attempts + 1,
            phishing_prob=0.9,
            phishing_risk="High Risk"
        )
        db.add(login_log)
        db.commit()
        raise HTTPException(status_code=400, detail="Invalid OTP code")
    
    # OTP is valid, clear secret
    db_user.otp_secret = None
    db.commit()
    # Pre-process details for Phishing Detection Model
    # Phishing model features: device_type, os_type, browser, location, failed_attempts, threat_level, etc.
    # Map text browser/os to code numbers used by dataset:
    os_mapping = {"windows": 1, "macos": 2, "linux": 3, "android": 4, "ios": 5, "unknown": 0}
    browser_mapping = {"chrome": 1, "firefox": 2, "safari": 3, "edge": 4, "opera": 5, "unknown": 0}
    device_mapping = {"desktop": 1, "mobile": 2, "tablet": 3, "unknown": 0}
    os_code = os_mapping.get(payload.os.lower(), 0)
    browser_code = browser_mapping.get(payload.browser.lower(), 0)
    device_code = device_mapping.get(payload.device.lower(), 0)
    
    # Randomly assign realistic numerical codes matching the dataset structure for the models
    location_code = abs(hash(payload.location)) % 50000
    
    # Phishing check feature inputs matching columns
    phish_data = {
        "device_type": device_code,
        "os_type": os_code,
        "browser": browser_code,
        "location": location_code,
        "login_method": 1,
        "success": 1,
        "failure_reason": 3, # None
        "auth_type": 1, # OTP
        "account_status": 1, # Active
        "failed_attempts": payload.failed_attempts,
        "mfa_enabled": 1,
        "token_expired": 0,
        "session_duration": 120,
        "password_age_days": 45,
        "role": 1,
        "privilege_level": 1,
        "blocked": 0,
        "error_code": 4,
        "system_component": 0,
        "year": 2026,
        "month": 7,
        "day": 12,
        "hour": 21,
        "day_of_week": 6
    }
    
    phishing_prob, phishing_risk = ml_suite.predict_phishing_risk(phish_data)
    # Save details to login history
    login_log = DBLoginHistory(
        email=payload.email,
        ip_address=payload.ip_address,
        browser=payload.browser,
        device=payload.device,
        os=payload.os,
        location=payload.location,
        failed_attempts=payload.failed_attempts,
        phishing_prob=phishing_prob,
        phishing_risk=phishing_risk
    )
    db.add(login_log)
    db.commit()
    return {
        "status": "success", 
        "message": "Authentication successful",
        "phishing_risk": phishing_risk,
        "phishing_probability": phishing_prob,
        "login_id": login_log.id
    }
# --- LOAN APPLICATION ENDPOINTS ---
@app.post("/api/loan/apply")
def submit_loan_application(app_data: ApplicationSchema, db: Session = Depends(get_db)):
    # Verify user exists
    db_user = db.query(DBUser).filter(DBUser.email == app_data.email).first()
    if not db_user:
        raise HTTPException(status_code=400, detail="User session not registered")
        
    db_app = DBApplication(
        email=app_data.email,
        full_name=app_data.full_name,
        dob=app_data.dob,
        aadhaar_no=app_data.aadhaar_no,
        pan_no=app_data.pan_no,
        income=app_data.income,
        existing_emi=app_data.existing_emi,
        existing_loans=app_data.existing_loans,
        employment_status=app_data.employment_status,
        savings=app_data.savings,
        loan_amount=app_data.loan_amount,
        loan_term=app_data.loan_term
    )
    db.add(db_app)
    db.commit()
    db.refresh(db_app)
    
    return {"status": "success", "message": "Application stored successfully", "application_id": db_app.id}
@app.post("/api/loan/upload-documents")
async def upload_documents(
    application_id: int = Form(...),
    aadhaar_file: UploadFile = File(None),
    pan_file: UploadFile = File(None),
    salary_file: UploadFile = File(None),
    bank_file: UploadFile = File(None),
    db: Session = Depends(get_db)
):
    app_record = db.query(DBApplication).filter(DBApplication.id == application_id).first()
    if not app_record:
        raise HTTPException(status_code=404, detail="Application not found")
    files = {
        "aadhaar": aadhaar_file,
        "pan": pan_file,
        "salary": salary_file,
        "bank": bank_file
    }
    uploaded_ocr_details = []
    
    for doc_type, file_obj in files.items():
        if not file_obj:
            continue
            
        # Create safe unique filename
        filename = f"{application_id}_{doc_type}_{uuid.uuid4().hex[:6]}_{file_obj.filename}"
        file_path = os.path.join(UPLOAD_DIR, filename)
        
        # Save file to disk
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file_obj.file, buffer)
            
        # Process EasyOCR
        raw_text = ml_suite.run_ocr(file_path, doc_type)
        
        # Parse fields from OCR text to check against application form details
        extracted_name = ""
        extracted_dob = ""
        extracted_id_no = ""
        extracted_salary = None
        
        # Identity match heuristic:
        comparison_status = "Identity Mismatch"
        
        # Simple rule-based extraction from text for verification
        if doc_type == "aadhaar":
            # Search Aadhaar Card values
            match_name = re.search(r"Name:\s*([A-Za-z\s]+)", raw_text, re.IGNORECASE)
            match_dob = re.search(r"DOB:\s*(\d{2}/\d{2}/\d{4})", raw_text, re.IGNORECASE)
            match_id = re.search(r"Aadhaar(?: Card)? Number:\s*(\d{4}\s\d{4}\s\d{4}|\d{12})", raw_text, re.IGNORECASE)
            
            extracted_name = match_name.group(1).strip() if match_name else ""
            extracted_dob = match_dob.group(1).strip() if match_dob else ""
            extracted_id_no = match_id.group(1).replace(" ", "").strip() if match_id else ""
            
            # Match
            name_match = app_record.full_name.lower() in extracted_name.lower() or extracted_name.lower() in app_record.full_name.lower()
            dob_match = app_record.dob == extracted_dob
            id_match = app_record.aadhaar_no.replace(" ", "") == extracted_id_no
            
            if name_match and dob_match and id_match:
                comparison_status = "Verified"
                
        elif doc_type == "pan":
            match_name = re.search(r"Name:\s*([A-Za-z\s]+)", raw_text, re.IGNORECASE)
            match_dob = re.search(r"DOB:\s*(\d{2}/\d{2}/\d{4})", raw_text, re.IGNORECASE)
            match_id = re.search(r"PAN:\s*([A-Z0-9]+)", raw_text, re.IGNORECASE)
            
            extracted_name = match_name.group(1).strip() if match_name else ""
            extracted_dob = match_dob.group(1).strip() if match_dob else ""
            extracted_id_no = match_id.group(1).strip() if match_id else ""
            
            name_match = app_record.full_name.lower() in extracted_name.lower() or extracted_name.lower() in app_record.full_name.lower()
            dob_match = app_record.dob == extracted_dob
            id_match = app_record.pan_no.upper() == extracted_id_no.upper()
            
            if name_match and dob_match and id_match:
                comparison_status = "Verified"
                
        elif doc_type == "salary":
            match_name = re.search(r"Name:\s*([A-Za-z\s]+)", raw_text, re.IGNORECASE)
            match_sal = re.search(r"Gross Salary:\s*INR\s*([\d,]+)", raw_text, re.IGNORECASE)
            
            extracted_name = match_name.group(1).strip() if match_name else ""
            extracted_salary = float(match_sal.group(1).replace(",", "")) if match_sal else 0.0
            
            name_match = app_record.full_name.lower() in extracted_name.lower() or extracted_name.lower() in app_record.full_name.lower()
            sal_match = abs(app_record.income - extracted_salary) < 5000 # minor difference allowed
            
            if name_match and sal_match:
                comparison_status = "Verified"
            else:
                comparison_status = "Identity Mismatch"
                
        elif doc_type == "bank":
            match_name = re.search(r"Account for\s*([A-Za-z\s]+)", raw_text, re.IGNORECASE)
            extracted_name = match_name.group(1).strip() if match_name else ""
            
            name_match = app_record.full_name.lower() in extracted_name.lower() or extracted_name.lower() in app_record.full_name.lower()
            if name_match:
                comparison_status = "Verified"
        # Save to OCR table
        ocr_record = DBOCRExtracted(
            application_id=application_id,
            document_type=doc_type,
            raw_text=raw_text,
            extracted_name=extracted_name,
            extracted_dob=extracted_dob,
            extracted_id_no=extracted_id_no,
            extracted_salary=extracted_salary,
            comparison_status=comparison_status
        )
        db.add(ocr_record)
        uploaded_ocr_details.append({
            "document_type": doc_type,
            "status": comparison_status,
            "extracted_name": extracted_name
        })
        
    db.commit()
    # Once files are uploaded and OCR is processed, trigger downstream pipeline models
    analysis_res = run_downstream_evaluations(application_id, db)
    
    return {
        "status": "success",
        "ocr_verifications": uploaded_ocr_details,
        "evaluation_summary": {
            "decision": analysis_res.decision,
            "risk_score": analysis_res.overall_risk_score,
            "fraud_risk": analysis_res.fraud_risk,
            "aml_risk": analysis_res.aml_risk,
            "eligibility": analysis_res.eligibility_decision
        }
    }
def run_downstream_evaluations(application_id: int, db: Session):
    app_record = db.query(DBApplication).filter(DBApplication.id == application_id).first()
    ocr_records = db.query(DBOCRExtracted).filter(DBOCRExtracted.application_id == application_id).all()
    
    # 1. Gather ID verification status
    identity_verified = 1
    for ocr in ocr_records:
        if ocr.comparison_status == "Identity Mismatch":
            identity_verified = 0
    # 2. Named Entity Recognition (NER) & PII Masking
    # Gather raw text from documents to anonymize
    combined_raw_text = f"Customer details Name: {app_record.full_name}, DOB: {app_record.dob}, Aadhaar: {app_record.aadhaar_no}, PAN: {app_record.pan_no}. "
    for ocr in ocr_records:
        combined_raw_text += f"\nDocument {ocr.document_type} Raw Text: {ocr.raw_text}"
        
    masked_text, pii_entities = ml_suite.mask_pii(combined_raw_text)
    # 3. Fraud Detection Model
    # Features: ip_region_mismatch, device_change_rate, application_frequency, loan_amount, session_duration, previous_defaults, browser_fingerprint_change, etc.
    # Get phishing history
    last_login = db.query(DBLoginHistory).filter(DBLoginHistory.email == app_record.email).order_by(DBLoginHistory.id.desc()).first()
    ip_mismatch = 1 if (last_login and last_login.phishing_risk == "High Risk") else 0
    failed_attempts = last_login.failed_attempts if last_login else 0
    
    fraud_data = {
        "ip_region_mismatch": ip_mismatch,
        "device_change_rate": 0.2, # standard mock
        "application_frequency": 1.0,
        "loan_amount": app_record.loan_amount,
        "institution": 1,
        "loan_type": 1,
        "session_duration": 180,
        "geo_location_consistency": 1 if ip_mismatch == 0 else 0,
        "previous_defaults": 0,
        "time_between_apps": 50000.0,
        "browser_fingerprint_change": 0.05
    }
    fraud_prob = ml_suite.predict_fraud_risk(fraud_data)
    # If identity verification is rejected, force fraud probability to 1.0
    if identity_verified == 0:
        fraud_prob = max(fraud_prob, 0.95)
    fraud_risk = "Fraud" if fraud_prob > 0.5 else "No Fraud"
    # 4. AML Detection Model
    # Features: typeofaction, sourceid, destinationid, amountofmoney
    # Parse transaction info from bank statement OCR if present, otherwise default to mock
    bank_ocr = next((o for o in ocr_records if o.document_type == "bank"), None)
    amt_laundering = 0.0
    action_type = "transfer"
    
    if bank_ocr:
        # Check for high cash deposit inside transaction strings
        high_txn = re.findall(r"(?:deposit|transfer|credit)\s*(?:INR)?\s*([\d,]+)", bank_ocr.raw_text, re.IGNORECASE)
        tx_vals = [float(v.replace(",", "")) for v in high_txn]
        if tx_vals:
            amt_laundering = max(tx_vals)
            # Check keywords
            if "deposit" in bank_ocr.raw_text.lower():
                action_type = "cash-in"
    aml_data = {
        "typeofaction": action_type,
        "sourceid": 1234.0,
        "destinationid": 5678.0,
        "amountofmoney": amt_laundering if amt_laundering > 0 else 25000.0
    }
    aml_prob = ml_suite.predict_aml_risk(aml_data)
    
    # Map AML probability to Risk Level
    if aml_prob > 0.7:
        aml_risk = "High Risk"
        aml_code = 2
    elif aml_prob > 0.3:
        aml_risk = "Medium Risk"
        aml_code = 1
    else:
        aml_risk = "Low Risk"
        aml_code = 0
    # 5. Loan Eligibility Prediction Model
    # Features: income, existing_emi, existing_loans, employment_status, savings, fraud_result, aml_result, identity_verified_result
    emp_map = {"unemployed": 0, "self-employed": 1, "salaried": 2}
    emp_code = emp_map.get(app_record.employment_status.lower(), 2)
    
    elig_data = {
        "income": app_record.income,
        "existing_emi": app_record.existing_emi,
        "existing_loans": app_record.existing_loans,
        "employment_status": emp_code,
        "savings": app_record.savings,
        "fraud_result": 1 if fraud_risk == "Fraud" else 0,
        "aml_result": aml_code,
        "identity_verified_result": identity_verified
    }
    
    elig_prob, shap_img = ml_suite.predict_eligibility_and_shap(elig_data)
    eligibility_decision = "Eligible" if elig_prob > 0.5 else "Not Eligible"
    # 6. Overall Risk Score Generation
    # Weight values: Phishing Prob: 15%, Fraud Prob: 35%, AML Prob: 35%, ID Mismatch: 15%
    phish_val = last_login.phishing_prob if last_login else 0.1
    id_val = 0.0 if identity_verified == 1 else 1.0
    
    overall_score = (phish_val * 0.15) + (fraud_prob * 0.35) + (aml_prob * 0.35) + (id_val * 0.15)
    overall_risk_pct = float(round(overall_score * 100, 1))
    # 7. Final Loan Decision Logic
    # APPROVED, MANUAL REVIEW, REJECTED
    if fraud_risk == "Fraud" or id_val == 1.0 or elig_prob < 0.25:
        final_decision = "REJECTED"
    elif aml_risk == "High Risk" or overall_risk_pct > 40.0 or elig_prob < 0.5:
        final_decision = "MANUAL REVIEW"
    else:
        final_decision = "APPROVED"
    # Save to Analysis DB
    # Check if analysis record already exists, otherwise create
    analysis_record = db.query(DBAnalysisResult).filter(DBAnalysisResult.application_id == application_id).first()
    if not analysis_record:
        analysis_record = DBAnalysisResult(application_id=application_id)
        db.add(analysis_record)
    analysis_record.masked_data = masked_text
    analysis_record.pii_detected = json.dumps(pii_entities)
    analysis_record.fraud_prob = fraud_prob
    analysis_record.fraud_risk = fraud_risk
    analysis_record.aml_prob = aml_prob
    analysis_record.aml_risk = aml_risk
    analysis_record.eligibility_prob = elig_prob
    analysis_record.eligibility_decision = eligibility_decision
    analysis_record.overall_risk_score = overall_risk_pct
    analysis_record.shap_img_base64 = shap_img
    analysis_record.decision = final_decision
    
    db.commit()
    db.refresh(analysis_record)
    
    return analysis_record
# --- DASHBOARD ENDPOINTS ---
@app.get("/api/dashboard/applications")
def get_dashboard_applications(db: Session = Depends(get_db)):
    apps = db.query(DBApplication).order_by(DBApplication.id.desc()).all()
    result = []
    for a in apps:
        ocr_list = []
        for ocr in a.ocr_records:
            ocr_list.append({
                "document_type": ocr.document_type,
                "extracted_name": ocr.extracted_name,
                "comparison_status": ocr.comparison_status
            })
            
        analysis_details = {}
        if a.analysis:
            analysis_details = {
                "masked_data": a.analysis.masked_data,
                "pii_detected": json.loads(a.analysis.pii_detected) if a.analysis.pii_detected else [],
                "fraud_prob": a.analysis.fraud_prob,
                "fraud_risk": a.analysis.fraud_risk,
                "aml_prob": a.analysis.aml_prob,
                "aml_risk": a.analysis.aml_risk,
                "eligibility_prob": a.analysis.eligibility_prob,
                "eligibility_decision": a.analysis.eligibility_decision,
                "overall_risk_score": a.analysis.overall_risk_score,
                "shap_img_base64": a.analysis.shap_img_base64,
                "decision": a.analysis.decision
            }
            
        last_login = db.query(DBLoginHistory).filter(DBLoginHistory.email == a.email).order_by(DBLoginHistory.id.desc()).first()
        login_details = {}
        if last_login:
            login_details = {
                "ip_address": last_login.ip_address,
                "browser": last_login.browser,
                "os": last_login.os,
                "location": last_login.location,
                "login_time": last_login.login_time.strftime("%Y-%m-%d %H:%M:%S"),
                "failed_attempts": last_login.failed_attempts,
                "phishing_prob": last_login.phishing_prob,
                "phishing_risk": last_login.phishing_risk
            }
        result.append({
            "id": a.id,
            "email": a.email,
            "full_name": a.full_name,
            "dob": a.dob,
            "aadhaar_no": a.aadhaar_no,
            "pan_no": a.pan_no,
            "income": a.income,
            "existing_emi": a.existing_emi,
            "existing_loans": a.existing_loans,
            "employment_status": a.employment_status,
            "savings": a.savings,
            "loan_amount": a.loan_amount,
            "loan_term": a.loan_term,
            "created_at": a.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            "ocr_records": ocr_list,
            "login_details": login_details,
            "analysis": analysis_details
        })
        
    return result
@app.post("/api/dashboard/decide")
def update_decision(payload: DecisionSchema, db: Session = Depends(get_db)):
    analysis = db.query(DBAnalysisResult).filter(DBAnalysisResult.application_id == payload.application_id).first()
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis results not found")
        
    analysis.decision = payload.decision
    db.commit()
    return {"status": "success", "message": f"Application decision updated to {payload.decision}"}
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)