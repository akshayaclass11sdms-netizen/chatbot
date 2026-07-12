const API_BASE = "http://127.0.0.1:8000/api";
// Chat State variables
let currentEmail = "customer@example.com";
let applicationId = null;
let failedLoginAttempts = 0;
let mockOtp = null;
// --- TAB NAVIGATION ---
function switchTab(tabId) {
    document.querySelectorAll('.tab-content').forEach(tab => tab.classList.remove('active'));
    document.querySelectorAll('.nav-tab').forEach(btn => btn.classList.remove('active'));
    
    document.getElementById(tabId).classList.add('active');
    
    // Set matching active class in navbar
    const tabBtnMap = {
        'chatbot-tab': 'Loan Chatbot',
        'dashboard-tab': 'Officer Dashboard'
    };
    
    document.querySelectorAll('.nav-tab').forEach(btn => {
        if (btn.innerText.trim().includes(tabBtnMap[tabId])) {
            btn.classList.add('active');
        }
    });
}
// --- MOCK INBOX HELPERS ---
function addMockEmail(sender, subject, body) {
    const mailList = document.getElementById('mail-list');
    const mailId = 'mail-' + Date.now();
    
    const mailCard = document.createElement('div');
    mailCard.className = 'mail-card unread';
    mailCard.id = mailId;
    mailCard.onclick = () => {
        mailCard.classList.remove('unread');
        alert(`From: ${sender}\nSubject: ${subject}\n\n${body}`);
    };
    
    const now = new Date();
    const timeStr = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    
    mailCard.innerHTML = `
        <div class="mail-sender">sender: ${sender}</div>
        <div class="mail-subject">${subject}</div>
        <div class="mail-body">${body}</div>
        <div class="mail-time">${timeStr}</div>
    `;
    
    mailList.prepend(mailCard);
    
    // Play a minor sound notification if possible
    try {
        const audioCtx = new (window.AudioContext || window.webkitAudioContext)();
        const osc = audioCtx.createOscillator();
        const gain = audioCtx.createGain();
        osc.connect(gain);
        gain.connect(audioCtx.destination);
        osc.frequency.value = 880; // A5 note
        gain.gain.setValueAtTime(0.05, audioCtx.currentTime);
        osc.start();
        osc.stop(audioCtx.currentTime + 0.1);
    } catch(e) {}
}
// --- CHAT DIALOG LOGIC ---
function appendBotMessage(content, widgetHtml = "") {
    const chatContainer = document.getElementById('chat-messages');
    
    const bubble = document.createElement('div');
    bubble.className = 'chat-bubble bot';
    bubble.innerHTML = `
        <div class="bubble-avatar"><i class="fa-solid fa-robot"></i></div>
        <div class="bubble-content">
            ${content}
            ${widgetHtml}
        </div>
    `;
    
    chatContainer.appendChild(bubble);
    chatContainer.scrollTop = chatContainer.scrollHeight;
}
function appendUserMessage(content) {
    const chatContainer = document.getElementById('chat-messages');
    
    const bubble = document.createElement('div');
    bubble.className = 'chat-bubble user';
    bubble.innerHTML = `
        <div class="bubble-avatar"><i class="fa-solid fa-user"></i></div>
        <div class="bubble-content">${content}</div>
    `;
    
    chatContainer.appendChild(bubble);
    chatContainer.scrollTop = chatContainer.scrollHeight;
}
// --- FLOW STAGE 1: LOGIN ---
async function submitLogin() {
    const email = document.getElementById('login-email').value;
    const password = document.getElementById('login-password').value;
    
    if (!email || !password) {
        alert("Please enter both email and password.");
        return;
    }
    
    currentEmail = email;
    
    try {
        const response = await fetch(`${API_BASE}/auth/login`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email, password })
        });
        
        const data = await response.json();
        
        if (data.status === "success") {
            mockOtp = data.mock_otp;
            appendUserMessage(`Logged in with email: ${email}. Requesting OTP.`);
            
            // Deliver OTP to simulated mailbox
            addMockEmail(
                "auth@creditshield.com", 
                "Secure Verification OTP Code", 
                `Your 6-digit verification code is: ${mockOtp}. Please enter this inside the chatbot console to authenticate.`
            );
            
            // Render OTP verification widget
            const otpWidget = `
                <div class="chat-widget" id="otp-widget">
                    <div class="widget-title">Verify OTP Code</div>
                    <p style="font-size:12px; color:var(--text-secondary); margin-bottom:10px;">A 6-digit verification code has been dispatched to your registered email address.</p>
                    <div class="form-group">
                        <label class="form-label">Enter 6-Digit OTP</label>
                        <input type="text" id="otp-code" class="form-input" placeholder="XXXXXX" maxlength="6" style="letter-spacing: 5px; text-align: center; font-size:16px;">
                    </div>
                    <div class="form-group" style="margin-top: 15px;">
                        <button class="btn" onclick="submitOTP()"><i class="fa-solid fa-key"></i> Confirm Authentication</button>
                    </div>
                </div>
            `;
            
            setTimeout(() => {
                appendBotMessage("An authentication code has been generated. Please verify the code to capture security features.", otpWidget);
                // Remove login widget
                const oldWidget = document.getElementById('login-widget');
                if (oldWidget) oldWidget.style.display = 'none';
            }, 500);
            
        } else {
            failedLoginAttempts++;
            alert(data.message || "Invalid credentials. Please try again.");
        }
    } catch (e) {
        console.error(e);
        alert("Failed to connect to the backend server.");
    }
}
// --- FLOW STAGE 2: OTP & DEVICE RISK ---
async function submitOTP() {
    const otp = document.getElementById('otp-code').value;
    if (!otp || otp.length !== 6) {
        alert("Please enter the 6-digit OTP code.");
        return;
    }
    
    appendUserMessage(`Submitting OTP code: ${otp}`);
    
    // Automatically capture client-side device info for the Phishing XGBoost model
    const userAgent = navigator.userAgent;
    let browser = "Unknown";
    let os = "Unknown";
    let device = "Desktop";
    
    // Browser Match
    if (userAgent.indexOf("Chrome") > -1) browser = "Chrome";
    else if (userAgent.indexOf("Safari") > -1) browser = "Safari";
    else if (userAgent.indexOf("Firefox") > -1) browser = "Firefox";
    else if (userAgent.indexOf("Edge") > -1) browser = "Edge";
    
    // OS Match
    if (userAgent.indexOf("Windows") > -1) os = "Windows";
    else if (userAgent.indexOf("Macintosh") > -1) os = "MacOS";
    else if (userAgent.indexOf("Android") > -1) { os = "Android"; device = "Mobile"; }
    else if (userAgent.indexOf("iPhone") > -1 || userAgent.indexOf("iPad") > -1) { os = "iOS"; device = "Mobile"; }
    else if (userAgent.indexOf("Linux") > -1) os = "Linux";
    
    // Setup Mock Client metadata
    const ip_address = "192.168.1.45";
    const location = "Bangalore, KA, India";
    
    try {
        const response = await fetch(`${API_BASE}/auth/verify-otp`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                email: currentEmail,
                otp: otp,
                ip_address,
                browser,
                device,
                os,
                location,
                failed_attempts: failedLoginAttempts
            })
        });
        
        if (!response.ok) {
            const err = await response.json();
            failedLoginAttempts++;
            alert(err.detail || "Authentication Failed.");
            return;
        }
        
        const data = await response.json();
        
        // Output security findings to the user
        let phishRiskHTML = `
            <div class="chat-widget" style="border-color:${data.phishing_risk === 'High Risk' ? 'var(--accent-red)' : 'var(--accent-green)'}">
                <div class="widget-title" style="color:${data.phishing_risk === 'High Risk' ? 'var(--accent-red)' : 'var(--accent-green)'}">Phishing Evaluation Result</div>
                <div style="font-size:12px; margin-bottom:10px;">
                    <strong>Login Probability Score:</strong> ${(data.phishing_probability * 100).toFixed(2)}% Phishing Risk<br>
                    <strong>Risk Category:</strong> ${data.phishing_risk}
                </div>
                <div style="font-size:11px; color:var(--text-secondary);">
                    Captured Login Info: ${device} / ${os} / ${browser} <br>
                    IP: ${ip_address} (${location})
                </div>
            </div>
        `;
        
        appendBotMessage("Security verification completed.", phishRiskHTML);
        
        // Hide OTP input
        const oldWidget = document.getElementById('otp-widget');
        if (oldWidget) oldWidget.style.display = 'none';
        
        // Act according to Risk Profile
        if (data.phishing_risk === "High Risk") {
            setTimeout(() => {
                appendBotMessage("⚠️ <strong>Caution:</strong> Our security logs indicate high-risk factors regarding your login footprint. Step-up multi-factor validation required or your account might be held for manual security check.");
            }, 1000);
        } else {
            // Low/Medium Risk -> Proceed to Form
            setTimeout(() => {
                renderLoanForm();
            }, 1000);
        }
        
    } catch(e) {
        console.error(e);
        alert("Failed to confirm OTP verification.");
    }
}
// --- FLOW STAGE 3: APPLICATION FORM ---
function renderLoanForm() {
    const formWidget = `
        <div class="chat-widget" id="loan-form-widget" style="max-width:100%;">
            <div class="widget-title">Secure Loan Application</div>
            
            <div class="form-row">
                <div class="form-group">
                    <label class="form-label">Full Name (Matches ID)</label>
                    <input type="text" id="loan-name" class="form-input" value="Akshaya S">
                </div>
                <div class="form-group">
                    <label class="form-label">DOB (DD/MM/YYYY)</label>
                    <input type="text" id="loan-dob" class="form-input" placeholder="12/08/1996" value="12/08/1996">
                </div>
            </div>
            <div class="form-row">
                <div class="form-group">
                    <label class="form-label">Aadhaar Card No</label>
                    <input type="text" id="loan-aadhaar" class="form-input" value="3456 7890 1234">
                </div>
                <div class="form-group">
                    <label class="form-label">PAN Card No</label>
                    <input type="text" id="loan-pan" class="form-input" value="ABCDE1234F">
                </div>
            </div>
            <div class="form-row">
                <div class="form-group">
                    <label class="form-label">Employment Status</label>
                    <select id="loan-employment" class="form-input" style="background:#0f172a; height:34px;">
                        <option value="Salaried">Salaried</option>
                        <option value="Self-employed">Self-employed</option>
                        <option value="Unemployed">Unemployed</option>
                    </select>
                </div>
                <div class="form-group">
                    <label class="form-label">Monthly Gross Income (INR)</label>
                    <input type="number" id="loan-income" class="form-input" value="75000">
                </div>
            </div>
            <div class="form-row">
                <div class="form-group">
                    <label class="form-label">Existing EMI Commitments (INR)</label>
                    <input type="number" id="loan-emi" class="form-input" value="12000">
                </div>
                <div class="form-group">
                    <label class="form-label">Existing Active Loans (Count)</label>
                    <input type="number" id="loan-loans" class="form-input" value="1">
                </div>
            </div>
            <div class="form-row">
                <div class="form-group">
                    <label class="form-label">Total Liquid Savings (INR)</label>
                    <input type="number" id="loan-savings" class="form-input" value="120000">
                </div>
                <div class="form-group">
                    <label class="form-label">Desired Loan Amount (INR)</label>
                    <input type="number" id="loan-amount" class="form-input" value="500000">
                </div>
            </div>
            <div class="form-group">
                <label class="form-label">Desired Loan Term (Months)</label>
                <input type="number" id="loan-term" class="form-input" value="36">
            </div>
            <div class="form-group" style="margin-top: 15px;">
                <button class="btn" onclick="submitLoanDetails()"><i class="fa-solid fa-cloud-arrow-up"></i> Submit Loan Profiles</button>
            </div>
        </div>
    `;
    
    appendBotMessage("Please provide your profile and request details inside the application card below:", formWidget);
}
async function submitLoanDetails() {
    const full_name = document.getElementById('loan-name').value;
    const dob = document.getElementById('loan-dob').value;
    const aadhaar_no = document.getElementById('loan-aadhaar').value;
    const pan_no = document.getElementById('loan-pan').value;
    const employment_status = document.getElementById('loan-employment').value;
    const income = parseFloat(document.getElementById('loan-income').value);
    const existing_emi = parseFloat(document.getElementById('loan-emi').value);
    const existing_loans = parseInt(document.getElementById('loan-loans').value);
    const savings = parseFloat(document.getElementById('loan-savings').value);
    const loan_amount = parseFloat(document.getElementById('loan-amount').value);
    const loan_term = parseInt(document.getElementById('loan-term').value);
    
    if (!full_name || !dob || !aadhaar_no || !pan_no || isNaN(income) || isNaN(loan_amount)) {
        alert("Please ensure all fields are correctly filled.");
        return;
    }
    
    appendUserMessage(`Submitting loan details for ${full_name}. Requested amount: INR ${loan_amount}`);
    
    try {
        const response = await fetch(`${API_BASE}/loan/apply`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                email: currentEmail, full_name, dob, aadhaar_no, pan_no,
                income, existing_emi, existing_loans, employment_status,
                savings, loan_amount, loan_term
            })
        });
        
        const data = await response.json();
        
        if (data.status === "success") {
            applicationId = data.application_id;
            
            // Hide previous form widget
            const oldWidget = document.getElementById('loan-form-widget');
            if (oldWidget) oldWidget.style.display = 'none';
            
            // Render Document upload widget
            renderUploadWidget();
        } else {
            alert("Error storing application profile details.");
        }
    } catch(e) {
        console.error(e);
        alert("Server communication error.");
    }
}
// --- FLOW STAGE 4: DOCUMENT UPLOADS ---
function renderUploadWidget() {
    const uploadWidget = `
        <div class="chat-widget" id="upload-widget">
            <div class="widget-title">Secure Document Upload</div>
            <p style="font-size:12px; color:var(--text-secondary); margin-bottom:12px;">Please upload image/PDF records of verification documents. Names and IDs will be verified using EasyOCR extraction.</p>
            
            <div class="upload-grid">
                <div class="upload-card" id="card-aadhaar">
                    <div class="upload-icon"><i class="fa-solid fa-id-card"></i></div>
                    <div class="upload-title">Aadhaar Card</div>
                    <div class="upload-sub" id="lbl-aadhaar">Select file</div>
                    <input type="file" class="file-input" id="file-aadhaar" onchange="fileSelected('aadhaar')">
                </div>
                <div class="upload-card" id="card-pan">
                    <div class="upload-icon"><i class="fa-solid fa-address-card"></i></div>
                    <div class="upload-title">PAN Card</div>
                    <div class="upload-sub" id="lbl-pan">Select file</div>
                    <input type="file" class="file-input" id="file-pan" onchange="fileSelected('pan')">
                </div>
            </div>
            
            <div class="upload-grid" style="margin-top:10px;">
                <div class="upload-card" id="card-salary">
                    <div class="upload-icon"><i class="fa-solid fa-file-invoice-dollar"></i></div>
                    <div class="upload-title">Salary Slip</div>
                    <div class="upload-sub" id="lbl-salary">Select file</div>
                    <input type="file" class="file-input" id="file-salary" onchange="fileSelected('salary')">
                </div>
                <div class="upload-card" id="card-bank">
                    <div class="upload-icon"><i class="fa-solid fa-receipt"></i></div>
                    <div class="upload-title">Bank Statement</div>
                    <div class="upload-sub" id="lbl-bank">Select file</div>
                    <input type="file" class="file-input" id="file-bank" onchange="fileSelected('bank')">
                </div>
            </div>
            <div class="form-group" style="margin-top: 15px;">
                <button class="btn" onclick="submitDocuments()"><i class="fa-solid fa-gears"></i> Process & Analyze Documents</button>
            </div>
        </div>
    `;
    
    appendBotMessage("Your basic profile is updated. Please upload your support documents for identity check, fraud, and AML validation:", uploadWidget);
}
function fileSelected(type) {
    const input = document.getElementById(`file-${type}`);
    const card = document.getElementById(`card-${type}`);
    const label = document.getElementById(`lbl-${type}`);
    
    if (input.files.length > 0) {
        card.classList.add('filled');
        label.innerText = input.files[0].name;
    } else {
        card.classList.remove('filled');
        label.innerText = "Select file";
    }
}
async function submitDocuments() {
    const aadhaar = document.getElementById('file-aadhaar').files[0];
    const pan = document.getElementById('file-pan').files[0];
    const salary = document.getElementById('file-salary').files[0];
    const bank = document.getElementById('file-bank').files[0];
    
    // We require at least Aadhaar and PAN for basic testing, others can be mock verified
    if (!aadhaar || !pan) {
        alert("Please upload at least your Aadhaar Card and PAN Card for identity verification.");
        return;
    }
    
    appendUserMessage("Uploading and starting ML analysis on documents...");
    
    // Render an interactive processing checklist
    const processingWidget = `
        <div class="chat-widget" id="processing-checklist">
            <div class="widget-title">Processing ML Models Pipeline</div>
            <div class="processing-list">
                <div class="processing-step active" id="step-ocr">
                    <div class="processing-icon"></div> Extracting text via EasyOCR...
                </div>
                <div class="processing-step" id="step-id">
                    <div class="processing-icon"></div> Comparing form data with extracted IDs...
                </div>
                <div class="processing-step" id="step-ner">
                    <div class="processing-icon"></div> Identifying sensitive entities (spaCy NER)...
                </div>
                <div class="processing-step" id="step-mask">
                    <div class="processing-icon"></div> Masking PII details (Microsoft Presidio)...
                </div>
                <div class="processing-step" id="step-ml">
                    <div class="processing-icon"></div> Evaluating Fraud, AML & Loan XGBoost classifiers...
                </div>
            </div>
        </div>
    `;
    
    appendBotMessage("Executing automated security and pipeline verification checks. Please stand by...", processingWidget);
    
    // Hide upload widget
    const oldWidget = document.getElementById('upload-widget');
    if (oldWidget) oldWidget.style.display = 'none';
    
    // Build Form
    const fd = new FormData();
    fd.append("application_id", applicationId);
    fd.append("aadhaar_file", aadhaar);
    fd.append("pan_file", pan);
    if (salary) fd.append("salary_file", salary);
    if (bank) fd.append("bank_file", bank);
    
    // Progress Checklist Animation simulation
    setTimeout(() => advanceChecklist("step-ocr", "step-id"), 1500);
    setTimeout(() => advanceChecklist("step-id", "step-ner"), 3000);
    setTimeout(() => advanceChecklist("step-ner", "step-mask"), 4200);
    setTimeout(() => advanceChecklist("step-mask", "step-ml"), 5500);
    try {
        const response = await fetch(`${API_BASE}/loan/upload-documents`, {
            method: "POST",
            body: fd
        });
        
        const data = await response.json();
        
        // Wait till checklist finishes to render final dialog
        setTimeout(() => {
            // Complete last step
            const lastStep = document.getElementById('step-ml');
            if (lastStep) {
                lastStep.classList.remove('active');
                lastStep.classList.add('done');
            }
            
            displayFinalDecision(data.evaluation_summary);
        }, 6500);
        
    } catch(e) {
        console.error(e);
        alert("Pipeline processing failed due to API errors.");
    }
}
function advanceChecklist(currentId, nextId) {
    const cur = document.getElementById(currentId);
    const nxt = document.getElementById(nextId);
    if (cur) {
        cur.classList.remove('active');
        cur.classList.add('done');
    }
    if (nxt) {
        nxt.classList.add('active');
    }
}
// --- FLOW STAGE 5: RESULT VIEW ---
function displayFinalDecision(summary) {
    let resultColor = "var(--accent-yellow)";
    let desc = "Your application requires a loan officer to manually review the security assessments.";
    let icon = "fa-clock-rotate-left";
    
    if (summary.decision === "APPROVED") {
        resultColor = "var(--accent-green)";
        desc = "Congratulations! Your loan request has passed all automated fraud/AML checks and has been Approved.";
        icon = "fa-circle-check";
    } else if (summary.decision === "REJECTED") {
        resultColor = "var(--accent-red)";
        desc = "Attention: Your request has been Rejected based on security parameters (fraud risk, document mismatch, or low eligibility scores).";
        icon = "fa-circle-xmark";
    }
    
    const decisionCard = `
        <div class="chat-widget" style="border-color:${resultColor}; border-width: 2px;">
            <div class="widget-title" style="color:${resultColor}; display:flex; justify-content:space-between; align-items:center;">
                <span>Loan Decision: ${summary.decision}</span>
                <i class="fa-solid ${icon}" style="font-size:18px;"></i>
            </div>
            <p style="font-size:13px; margin-bottom:12px; line-height:1.4;">${desc}</p>
            <div style="background:rgba(255,255,255,0.03); border-radius:6px; padding:10px; font-size:12px;">
                <strong>Overall Risk Rating:</strong> ${summary.risk_score}%<br>
                <strong>Security Fraud Flag:</strong> ${summary.fraud_risk}<br>
                <strong>AML Transactions Check:</strong> ${summary.aml_risk}<br>
                <strong>Eligibility Evaluation:</strong> ${summary.eligibility}
            </div>
        </div>
    `;
    
    appendBotMessage("Decision evaluation completed.", decisionCard);
    
    // Add Email notification
    addMockEmail(
        "processing@creditshield.com",
        `Update on Loan Application #${applicationId}`,
        `Hello,\nYour loan application has been evaluated. Decision Status: ${summary.decision}.\nOverall calculated security risk rating: ${summary.risk_score}%. Thank you.`
    );
}
// --- DASHBOARD LOADER ---
async function loadDashboardData() {
    try {
        const response = await fetch(`${API_BASE}/dashboard/applications`);
        const apps = await response.json();
        
        // Load Counters
        document.getElementById('stat-total').innerText = apps.length;
        document.getElementById('stat-approved').innerText = apps.filter(a => a.analysis.decision === 'APPROVED').length;
        document.getElementById('stat-review').innerText = apps.filter(a => a.analysis.decision === 'MANUAL REVIEW').length;
        document.getElementById('stat-rejected').innerText = apps.filter(a => a.analysis.decision === 'REJECTED').length;
        
        // Render Table Rows
        const tbody = document.getElementById('app-table-body');
        if (apps.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="8" style="text-align: center; color: var(--text-secondary); padding: 30px;">
                        No applications processed yet. Fill out the chatbot form to seed records.
                    </td>
                </tr>
            `;
            return;
        }
        
        tbody.innerHTML = "";
        apps.forEach(app => {
            const tr = document.createElement('tr');
            tr.onclick = () => viewAppDetails(app);
            
            // Decision Badge HTML
            let decClass = "review";
            if (app.analysis.decision === "APPROVED") decClass = "approved";
            if (app.analysis.decision === "REJECTED") decClass = "rejected";
            
            // Risk Badge
            let riskClass = "risk-low";
            if (app.analysis.overall_risk_score > 35) riskClass = "risk-high";
            else if (app.analysis.overall_risk_score > 15) riskClass = "risk-med";
            
            tr.innerHTML = `
                <td>#${app.id}</td>
                <td><strong>${app.full_name}</strong></td>
                <td>INR ${app.loan_amount.toLocaleString()}</td>
                <td><span class="badge ${app.login_details.phishing_risk === 'High Risk' ? 'risk-high' : 'risk-low'}">${app.login_details.phishing_risk || '-'}</span></td>
                <td><span class="badge ${app.analysis.fraud_risk === 'Fraud' ? 'risk-high' : 'risk-low'}">${app.analysis.fraud_risk || '-'}</span></td>
                <td><span class="badge ${app.analysis.aml_risk === 'High Risk' ? 'risk-high' : app.analysis.aml_risk === 'Medium Risk' ? 'risk-med' : 'risk-low'}">${app.analysis.aml_risk || '-'}</span></td>
                <td><span class="badge ${riskClass}">${app.analysis.overall_risk_score}%</span></td>
                <td><span class="badge ${decClass}">${app.analysis.decision}</span></td>
            `;
            
            tbody.appendChild(tr);
        });
        
    } catch(e) {
        console.error(e);
    }
}
// --- DASHBOARD DETAIL VIEWER ---
function viewAppDetails(app) {
    selectedAppId = app.id;
    
    // Hide table queue, show detail
    document.getElementById('dashboard-list-view').style.display = 'none';
    document.getElementById('dashboard-detail-view').style.display = 'grid';
    
    // Set Profile
    document.getElementById('detail-app-id').innerText = `#${app.id}`;
    document.getElementById('detail-app-date').innerText = app.created_at;
    document.getElementById('detail-full-name').innerText = app.full_name;
    document.getElementById('detail-email').innerText = app.email;
    document.getElementById('detail-aadhaar').innerText = app.aadhaar_no;
    document.getElementById('detail-pan').innerText = app.pan_no;
    document.getElementById('detail-employment').innerText = app.employment_status;
    document.getElementById('detail-loan-details').innerText = `INR ${app.loan_amount.toLocaleString()} for ${app.loan_term} months (Income: INR ${app.income.toLocaleString()})`;
    
    // Decision Badge
    const dBadge = document.getElementById('detail-decision-badge');
    dBadge.innerText = app.analysis.decision;
    dBadge.className = `badge ${app.analysis.decision.toLowerCase().replace(' ', '')}`;
    // OCR Side by Side Comparison
    const cmpName = app.ocr_records.find(o => o.document_type === 'aadhaar') || app.ocr_records.find(o => o.document_type === 'pan');
    const cmpDob = app.ocr_records.find(o => o.document_type === 'aadhaar') || app.ocr_records.find(o => o.document_type === 'pan');
    const cmpAadh = app.ocr_records.find(o => o.document_type === 'aadhaar');
    const cmpPan = app.ocr_records.find(o => o.document_type === 'pan');
    
    // Fill text
    document.getElementById('cmp-form-name').innerText = app.full_name;
    document.getElementById('cmp-ocr-name').innerText = cmpName ? cmpName.extracted_name : "Not Found";
    document.getElementById('cmp-form-dob').innerText = app.dob;
    document.getElementById('cmp-ocr-dob').innerText = cmpDob && cmpDob.extracted_dob ? cmpDob.extracted_dob : "Not Found";
    
    document.getElementById('cmp-form-aadhaar').innerText = app.aadhaar_no;
    document.getElementById('cmp-ocr-aadhaar').innerText = cmpAadh ? cmpAadh.extracted_id_no : "Not Found";
    document.getElementById('cmp-form-pan').innerText = app.pan_no;
    document.getElementById('cmp-ocr-pan').innerText = cmpPan ? cmpPan.extracted_id_no : "Not Found";
    
    // Update comparison colors
    const setBlockStatus = (elId, match) => {
        const block = document.getElementById(elId);
        if (match) {
            block.className = "compare-block match";
        } else {
            block.className = "compare-block mismatch";
        }
    };
    
    const nameMatch = cmpName && (app.full_name.toLowerCase().includes(cmpName.extracted_name.toLowerCase()) || cmpName.extracted_name.toLowerCase().includes(app.full_name.toLowerCase()));
    setBlockStatus('compare-name-card', nameMatch);
    setBlockStatus('compare-dob-card', cmpDob && app.dob === cmpDob.extracted_dob);
    setBlockStatus('compare-aadhaar-card', cmpAadh && app.aadhaar_no.replace(/\s/g, '') === cmpAadh.extracted_id_no);
    setBlockStatus('compare-pan-card', cmpPan && app.pan_no.toUpperCase() === cmpPan.extracted_id_no.toUpperCase());
    
    // OCR Overall verify label
    const ocrOverall = app.ocr_records.every(o => o.comparison_status === 'Verified');
    const ocrLabel = document.getElementById('detail-ocr-overall-status');
    if (ocrOverall && app.ocr_records.length > 0) {
        ocrLabel.innerText = "VERIFIED";
        ocrLabel.className = "badge approved";
    } else {
        ocrLabel.innerText = "IDENTITY MISMATCH";
        ocrLabel.className = "badge rejected";
    }
    // Masked Text
    document.getElementById('detail-masked-text').innerText = app.analysis.masked_data || "No text analyzed.";
    
    // NER Tag List
    const piiContainer = document.getElementById('detail-pii-list');
    piiContainer.innerHTML = "";
    if (app.analysis.pii_detected && app.analysis.pii_detected.length > 0) {
        app.analysis.pii_detected.forEach(item => {
            const span = document.createElement('span');
            span.className = "pii-item";
            span.innerText = `${item.entity}: ${item.value}`;
            piiContainer.appendChild(span);
        });
    } else {
        piiContainer.innerHTML = "<span style='font-size:11px; color:var(--text-secondary);'>No PII elements identified.</span>";
    }
    // Risk Dial
    const dial = document.getElementById('detail-risk-dial');
    const pct = app.analysis.overall_risk_score;
    dial.style.setProperty('--risk-pct', `${pct}%`);
    document.getElementById('detail-risk-pct').innerText = `${pct}%`;
    
    // Dial color adjustment
    let riskDesc = "Low Risk";
    let riskColor = "var(--accent-green)";
    if (pct > 35) {
        riskDesc = "High Risk";
        riskColor = "var(--accent-red)";
    } else if (pct > 15) {
        riskDesc = "Medium Risk";
        riskColor = "var(--accent-yellow)";
    }
    document.getElementById('detail-risk-desc').innerText = riskDesc;
    document.getElementById('detail-risk-desc').style.color = riskColor;
    dial.style.backgroundImage = `conic-gradient(${riskColor} 0%, ${riskColor} ${pct}%, rgba(255, 255, 255, 0.05) ${pct}%, rgba(255, 255, 255, 0.05) 100%)`;
    // Breakdown tags
    const phishVal = document.getElementById('risk-breakdown-phishing');
    phishVal.innerText = app.login_details.phishing_risk || '-';
    phishVal.className = `badge ${app.login_details.phishing_risk === 'High Risk' ? 'rejected' : 'approved'}`;
    
    const fraudVal = document.getElementById('risk-breakdown-fraud');
    fraudVal.innerText = app.analysis.fraud_risk || '-';
    fraudVal.className = `badge ${app.analysis.fraud_risk === 'Fraud' ? 'rejected' : 'approved'}`;
    
    const amlVal = document.getElementById('risk-breakdown-aml');
    amlVal.innerText = app.analysis.aml_risk || '-';
    amlVal.className = `badge ${app.analysis.aml_risk === 'High Risk' ? 'rejected' : app.analysis.aml_risk === 'Medium Risk' ? 'review' : 'approved'}`;
    
    const eligVal = document.getElementById('risk-breakdown-eligibility');
    eligVal.innerText = app.analysis.eligibility_decision || '-';
    eligVal.className = `badge ${app.analysis.eligibility_decision === 'Eligible' ? 'approved' : 'rejected'}`;
    // SHAP Chart
    const shapContainer = document.getElementById('detail-shap-chart');
    if (app.analysis.shap_img_base64) {
        shapContainer.innerHTML = `<img src="data:image/png;base64,${app.analysis.shap_img_base64}" class="shap-chart-img" alt="SHAP explanation plot">`;
    } else {
        shapContainer.innerHTML = `<span style="font-size:11px; color:var(--text-secondary);">No SHAP explanation plot generated.</span>`;
    }
}
function closeAppDetails() {
    document.getElementById('dashboard-detail-view').style.display = 'none';
    document.getElementById('dashboard-list-view').style.display = 'flex';
    loadDashboardData();
}
// --- FLOW STAGE 6: DECISION MAKER ---
async function updateAppDecision(newDecision) {
    if (!selectedAppId) return;
    
    try {
        const response = await fetch(`${API_BASE}/dashboard/decide`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                application_id: selectedAppId,
                decision: newDecision,
                notes: `Decision updated manually by Officer.`
            })
        });
        
        const data = await response.json();
        
        if (data.status === "success") {
            // Update UI badge
            const badge = document.getElementById('detail-decision-badge');
            badge.innerText = newDecision;
            badge.className = `badge ${newDecision.toLowerCase().replace(' ', '')}`;
            
            alert(data.message);
            
            // Close details and refresh queue
            closeAppDetails();
        } else {
            alert("Error updating application status.");
        }
    } catch(e) {
        console.error(e);
        alert("Failed to submit status update.");
    }
}