import os
from sqlalchemy import create_engine, Column, Integer, String, Float, Text, ForeignKey, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
import datetime
# Determine DB connection string (default to PostgreSQL if configured, otherwise SQLite fallback)
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    # Use SQLite inside a data directory next to this file for out-of-the-box local operation.
    # Using the script's own directory (instead of a hardcoded machine-specific path) means this
    # works on any OS/machine without editing the source.
    base_dir = os.path.dirname(os.path.abspath(__file__))
    data_dir = os.path.join(base_dir, "data")
    os.makedirs(data_dir, exist_ok=True)
    db_path = os.path.join(data_dir, "loan_approval.db")
    DATABASE_URL = f"sqlite:///{db_path}"
    print(f"DATABASE_URL not set. Falling back to SQLite database at: {db_path}")
else:
    print(f"Connecting to database: {DATABASE_URL.split('@')[-1] if '@' in DATABASE_URL else DATABASE_URL}")
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()
class DBUser(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    otp_secret = Column(String(10), nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
class DBLoginHistory(Base):
    __tablename__ = "login_history"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), index=True, nullable=False)
    ip_address = Column(String(50))
    browser = Column(String(50))
    device = Column(String(50))
    os = Column(String(50))
    location = Column(String(100))
    login_time = Column(DateTime, default=datetime.datetime.utcnow)
    failed_attempts = Column(Integer, default=0)
    phishing_prob = Column(Float, default=0.0)
    phishing_risk = Column(String(50), default="Low/Medium Risk")
class DBApplication(Base):
    __tablename__ = "applications"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), index=True, nullable=False)
    full_name = Column(String(255))
    dob = Column(String(50))
    aadhaar_no = Column(String(50))
    pan_no = Column(String(50))
    income = Column(Float)
    existing_emi = Column(Float)
    existing_loans = Column(Integer)
    employment_status = Column(String(50)) # Unemployed, Self-employed, Salaried
    savings = Column(Float)
    loan_amount = Column(Float)
    loan_term = Column(Integer) # In months
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    # Relationships
    ocr_records = relationship("DBOCRExtracted", back_populates="application", cascade="all, delete-orphan")
    analysis = relationship("DBAnalysisResult", uselist=False, back_populates="application", cascade="all, delete-orphan")
class DBOCRExtracted(Base):
    __tablename__ = "ocr_extracted"
    id = Column(Integer, primary_key=True, index=True)
    application_id = Column(Integer, ForeignKey("applications.id"), nullable=False)
    document_type = Column(String(50), nullable=False) # aadhaar, pan, salary, bank
    raw_text = Column(Text)
    extracted_name = Column(String(255))
    extracted_dob = Column(String(50))
    extracted_id_no = Column(String(100))
    extracted_salary = Column(Float)
    comparison_status = Column(String(50)) # Verified, Identity Mismatch
    application = relationship("DBApplication", back_populates="ocr_records")
class DBAnalysisResult(Base):
    __tablename__ = "analysis_results"
    id = Column(Integer, primary_key=True, index=True)
    application_id = Column(Integer, ForeignKey("applications.id"), nullable=False)
    masked_data = Column(Text) # Masked application details (JSON or text)
    pii_detected = Column(Text) # Identified entities list (JSON string)
    fraud_prob = Column(Float, default=0.0)
    fraud_risk = Column(String(50), default="No Fraud")
    aml_prob = Column(Float, default=0.0)
    aml_risk = Column(String(50), default="Low Risk")
    eligibility_prob = Column(Float, default=0.0)
    eligibility_decision = Column(String(50), default="Not Eligible")
    overall_risk_score = Column(Float, default=0.0) # Overall Risk Score (0-100)
    shap_img_base64 = Column(Text) # SHAP waterfall chart encoded as string
    decision = Column(String(50), default="MANUAL REVIEW") # APPROVED, REJECTED, MANUAL REVIEW
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    application = relationship("DBApplication", back_populates="analysis")
def init_db():
    Base.metadata.create_all(bind=engine)
    print("Database tables initialized.")
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()