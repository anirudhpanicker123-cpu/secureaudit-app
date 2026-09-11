from flask import Flask, request, render_template, redirect, url_for, flash, jsonify, session, send_file
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import os
import json
import zipfile
from datetime import datetime
import groq
from pdf_export import AuditPDF
from flask import send_file
from io import BytesIO

from config import Config
from parser import ConfigParser
from compliance_engine import ComplianceEngine
from database import (init_db, create_user, get_user_by_email, get_user_by_id,
                     save_audit, get_all_audits, get_audit_by_id, delete_audit,
                     save_chat_message, get_chat_history)
from knowledge_graph import ComplianceKnowledgeGraph

app = Flask(__name__)
app.config.from_object(Config)

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
init_db()

# ============================================================
# Authentication Setup
# ============================================================

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'


class User(UserMixin):
    def __init__(self, user_dict):
        self.id = str(user_dict['id'])
        self.email = user_dict['email']
        self.username = user_dict.get('username', '')
        self.profile_pic = user_dict.get('profile_pic', '')


@login_manager.user_loader
def load_user(user_id):
    user_dict = get_user_by_id(int(user_id))
    if user_dict:
        return User(user_dict)
    return None


# ============================================================
# Groq AI Setup
# ============================================================

try:
    client = groq.Groq(
        api_key=app.config['GROQ_API_KEY'],
        max_retries=0,
        timeout=25.0
    )
    ai_enabled = True
    print("AI Assistant is ENABLED!")
except Exception as e:
    client = None
    ai_enabled = False
    print("Groq API not configured. AI features disabled. Error: " + str(e))


AI_MODELS = ["openai/gpt-oss-120b", "openai/gpt-oss-20b"]


# ============================================================
# Helper Functions
# ============================================================

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


def call_ai(messages, temperature=0.4, max_tokens=500):
    """Try each model in order. Returns None if all fail."""
    if not ai_enabled:
        return None
    for model_name in AI_MODELS:
        try:
            response = client.chat.completions.create(
                model=model_name,
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens
            )
            return response.choices[0].message.content
        except Exception as e:
            print("Model " + model_name + " failed: " + str(e)[:120])
            continue
    return None


def get_ai_explanation(violation):
    """Full-quality AI explanation for every violation."""
    if not ai_enabled:
        return "AI explanation unavailable."

    prompt = f"""You are a senior network security engineer explaining a compliance violation to a colleague.

CONTEXT:
Violation: {violation['description']}
Severity: {violation['severity']}
Rule ID: {violation['rule']}
Base Fix Command: {violation.get('remediation', 'N/A')}

Respond EXACTLY in this markdown format (no extra text before or after):

### Why it matters
- First specific security risk, one sentence
- Second risk, one sentence
- Third risk if applicable

### Potential impact
- **Business impact:** One sentence about what could happen
- **Technical impact:** One sentence about the device or network
- **Compliance:** Which standards this violates (PCI-DSS, NIST, ISO 27001)

### Step-by-step fix
1. Enter privileged mode: `enable`
2. Enter configuration mode: `configure terminal`
3. Apply the fix: `{violation.get('remediation', 'N/A')}`
4. Save configuration: `write memory`
5. Verify with: `show running-config`

### Verification
Run `show running-config` and confirm the change is present.

RULES:
- Use ONLY the markdown format above
- Keep each bullet to ONE clear sentence
- Total length: under 180 words"""

    result = call_ai(
        messages=[
            {"role": "system", "content": "You are a network security expert. Output markdown only."},
            {"role": "user", "content": prompt}
        ],
        temperature=0.4,
        max_tokens=500
    )

    if not result:
        return "AI explanation temporarily unavailable. All models are rate-limited or unreachable."
    return result


# ============================================================
# Authentication Routes
# ============================================================

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        if not email or not password:
            flash('Email and password are required.', 'error')
            return redirect(url_for('register'))

        if len(password) < 6:
            flash('Password must be at least 6 characters.', 'error')
            return redirect(url_for('register'))

        if get_user_by_email(email):
            flash('An account with this email already exists.', 'error')
            return redirect(url_for('register'))

        password_hash = generate_password_hash(password)
        user_id = create_user(email=email, username=username or email.split('@')[0], password_hash=password_hash)
        user_dict = get_user_by_id(user_id)
        login_user(User(user_dict))
        flash('Account created successfully! Welcome.', 'success')
        return redirect(url_for('index'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        user_dict = get_user_by_email(email)
        if user_dict and user_dict.get('password_hash') and check_password_hash(user_dict['password_hash'], password):
            login_user(User(user_dict))
            flash('Welcome back!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))

        flash('Invalid email or password.', 'error')
        return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))


# ============================================================
# Main App Routes (all protected with @login_required)
# ============================================================

@app.route('/')
@login_required
def index():
    return render_template('index.html')


@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        flash('No file selected')
        return redirect(url_for('index'))

    file = request.files['file']
    if file.filename == '':
        flash('No file selected')
        return redirect(url_for('index'))

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        with open(filepath, 'r', errors='ignore') as f:
            config_text = f.read()

        parser = ConfigParser(config_text)
        vendor = parser.detect_vendor()
        parser.vendor = vendor
        parse_success = parser.parse_config()

        engine = ComplianceEngine(config_text, vendor)
        violations, passed = engine.run_checks()
        score = engine.get_compliance_score()

        # Generate AI explanations for every violation
        for violation in violations:
            violation['ai_explanation'] = get_ai_explanation(violation)

        results = {
            'filename': filename,
            'vendor': vendor.upper(),
            'parse_success': parse_success,
            'compliance_score': round(score, 2),
            'total_rules': len(Config.COMPLIANCE_RULES),
            'passed_count': len(passed),
            'violation_count': len(violations),
            'violations': violations,
            'passed_checks': passed,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }

        audit_id = save_audit(results, current_user.id)
        results['id'] = audit_id

        return render_template('result.html', results=results)

    flash('File type not allowed. Please upload .txt, .conf, .cfg, or .config files')
    return redirect(url_for('index'))


@app.route('/upload-batch', methods=['POST'])
@login_required
def upload_batch():
    """Handle ZIP file with multiple config files"""
    if 'file' not in request.files:
        flash('No file selected')
        return redirect(url_for('index'))

    file = request.files['file']
    if file.filename == '':
        flash('No file selected')
        return redirect(url_for('index'))

    if not file.filename.lower().endswith('.zip'):
        flash('Please upload a ZIP file for batch mode')
        return redirect(url_for('index'))

    filename = secure_filename(file.filename)
    zip_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(zip_path)

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    extract_folder = os.path.join(app.config['UPLOAD_FOLDER'], 'batch_' + timestamp)

    try:
        os.makedirs(extract_folder, exist_ok=True)
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(extract_folder)
    except zipfile.BadZipFile:
        flash('Invalid ZIP file')
        return redirect(url_for('index'))
    except Exception as e:
        flash('Could not extract ZIP: ' + str(e))
        return redirect(url_for('index'))

    valid_extensions = app.config['ALLOWED_EXTENSIONS']
    config_files = []

    for root, dirs, files in os.walk(extract_folder):
        for f in files:
            if f.startswith('.') or f.startswith('__'):
                continue
            if '.' in f:
                ext = f.rsplit('.', 1)[-1].lower()
                if ext in valid_extensions:
                    config_files.append(os.path.join(root, f))

    if not config_files:
        flash('No valid config files found in ZIP')
        return redirect(url_for('index'))

    batch_results = []

    for config_path in config_files:
        try:
            with open(config_path, 'r', errors='ignore') as f:
                config_text = f.read()

            if not config_text.strip():
                continue

            file_name = os.path.basename(config_path)

            parser = ConfigParser(config_text)
            vendor = parser.detect_vendor()
            parser.vendor = vendor
            parser.parse_config()

            engine = ComplianceEngine(config_text, vendor)
            violations, passed = engine.run_checks()
            score = engine.get_compliance_score()

            # Generate AI explanations for ALL violations
            for v in violations:
                v['ai_explanation'] = get_ai_explanation(v)

            results = {
                'filename': file_name,
                'vendor': vendor.upper(),
                'parse_success': True,
                'compliance_score': round(score, 2),
                'total_rules': len(Config.COMPLIANCE_RULES),
                'passed_count': len(passed),
                'violation_count': len(violations),
                'violations': violations,
                'passed_checks': passed,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }

            audit_id = save_audit(results, current_user.id)
            results['id'] = audit_id
            batch_results.append(results)

        except Exception as e:
            print('Error processing ' + config_path + ': ' + str(e))
            continue

    if not batch_results:
        flash('No configs could be processed')
        return redirect(url_for('index'))

    batch_results.sort(key=lambda x: x['compliance_score'])

    total_files = len(batch_results)
    avg_score = sum(r['compliance_score'] for r in batch_results) / total_files
    total_violations = sum(r['violation_count'] for r in batch_results)
    total_passed = sum(r['passed_count'] for r in batch_results)
    total_high = sum(sum(1 for v in r['violations'] if v['severity'] == 'HIGH') for r in batch_results)
    total_medium = sum(sum(1 for v in r['violations'] if v['severity'] == 'MEDIUM') for r in batch_results)
    total_low = sum(sum(1 for v in r['violations'] if v['severity'] == 'LOW') for r in batch_results)

    vendors = {}
    for r in batch_results:
        v = r['vendor']
        vendors[v] = vendors.get(v, 0) + 1

    batch_summary = {
        'total_files': total_files,
        'avg_score': round(avg_score, 1),
        'total_violations': total_violations,
        'total_passed': total_passed,
        'total_high': total_high,
        'total_medium': total_medium,
        'total_low': total_low,
        'vendors': vendors,
        'results': batch_results,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }

    return render_template('batch_result.html', batch=batch_summary)


@app.route('/api/audit', methods=['POST'])
@login_required
def api_audit():
    """REST API endpoint for programmatic access"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    config_text = file.read().decode('utf-8')

    parser = ConfigParser(config_text)
    vendor = parser.detect_vendor()
    parser.vendor = vendor
    parser.parse_config()

    engine = ComplianceEngine(config_text, vendor)
    violations, passed = engine.run_checks()
    score = engine.get_compliance_score()

    return jsonify({
        'vendor': vendor,
        'compliance_score': score,
        'violations': violations,
        'passed_checks': passed,
        'total_rules': len(Config.COMPLIANCE_RULES)
    })


@app.route('/history')
@login_required
def history():
    """Show all past audits for the current user"""
    audits = get_all_audits(current_user.id)
    return render_template('history.html', audits=audits)


@app.route('/audit/<int:audit_id>')
@login_required
def view_audit(audit_id):
    """View a specific audit — only if it belongs to the current user"""
    audit = get_audit_by_id(audit_id, current_user.id)
    if not audit:
        flash('Audit not found or access denied.')
        return redirect(url_for('history'))

    chat_history = get_chat_history(audit_id)
    return render_template('result.html', results=audit, chat_history=chat_history)


@app.route('/audit/<int:audit_id>/delete', methods=['POST'])
@login_required
def delete_audit_route(audit_id):
    """Delete an audit — only if it belongs to the current user"""
    delete_audit(audit_id, current_user.id)
    flash('Audit deleted successfully')
    return redirect(url_for('history'))


@app.route('/audit/<int:audit_id>/chat', methods=['POST'])
@login_required
def chat_with_ai(audit_id):
    """AI Chat Assistant"""
    data = request.get_json()
    user_message = data.get('message', '').strip()

    if not user_message:
        return jsonify({'error': 'Message cannot be empty'}), 400

    audit = get_audit_by_id(audit_id, current_user.id)
    if not audit:
        return jsonify({'error': 'Audit not found'}), 404

    violations_summary = "\n".join([
        "- " + v['description'] + " (Severity: " + v['severity'] + ")"
        for v in audit['violations']
    ]) or "No violations"

    passed_summary = "\n".join([
        "- " + p['description']
        for p in audit['passed_checks']
    ]) or "No passed checks"

    context = f"""You are a network security AI assistant helping a user understand a compliance audit.

AUDIT CONTEXT:
- File: {audit['filename']}
- Vendor: {audit['vendor']}
- Compliance Score: {audit['compliance_score']}%
- Total Rules: {audit['total_rules']}
- Passed: {audit['passed_count']}
- Violations: {audit['violation_count']}

VIOLATIONS FOUND:
{violations_summary}

PASSED CHECKS:
{passed_summary}

Answer the user's question clearly and concisely. If they ask for commands, provide exact vendor-specific ({audit['vendor']}) commands. Keep answers under 200 words."""

    past_chats = get_chat_history(audit_id)
    messages = [{"role": "system", "content": context}]

    for chat in past_chats[-5:]:
        messages.append({"role": "user", "content": chat['user']})
        messages.append({"role": "assistant", "content": chat['ai']})

    messages.append({"role": "user", "content": user_message})

    ai_response = call_ai(messages=messages, temperature=0.7, max_tokens=400)

    if not ai_response:
        ai_response = "Sorry, AI is temporarily unavailable. Please try again in a moment."

    save_chat_message(audit_id, user_message, ai_response)
    return jsonify({'response': ai_response, 'timestamp': datetime.now().strftime('%H:%M:%S')})


@app.route('/audit/<int:audit_id>/fix-script')
@login_required
def generate_fix_script(audit_id):
    """Generate a single remediation script for all violations"""
    audit = get_audit_by_id(audit_id, current_user.id)
    if not audit:
        flash('Audit not found')
        return redirect(url_for('history'))

    lines = []
    lines.append("! " + "=" * 52)
    lines.append("! REMEDIATION SCRIPT")
    lines.append("! Device: " + str(audit['filename']))
    lines.append("! Vendor: " + str(audit['vendor']))
    lines.append("! Generated: " + str(audit['timestamp']))
    lines.append("! Total Violations: " + str(audit['violation_count']))
    lines.append("! Compliance Score: " + str(audit['compliance_score']) + "%")
    lines.append("! " + "=" * 52)
    lines.append("")

    if not audit['violations']:
        lines.append("! No violations found - nothing to fix!")
        lines.append("")
    else:
        severity_order = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}
        sorted_violations = sorted(
            audit['violations'],
            key=lambda v: severity_order.get(v.get('severity', 'LOW'), 3)
        )

        for violation in sorted_violations:
            severity = violation.get('severity', 'UNKNOWN')
            description = violation.get('description', 'No description')
            rule = violation.get('rule', 'unknown')
            remediation = violation.get('remediation', '')

            lines.append("! [" + severity + "] " + description)
            lines.append("! Rule: " + rule)
            lines.append("! --------------------------------------------")

            if remediation:
                for cmd_line in remediation.split('\n'):
                    lines.append(cmd_line)

            lines.append("")
            lines.append("")

    lines.append("! " + "=" * 52)
    lines.append("! END OF SCRIPT")
    lines.append("! Apply by copying and pasting into device CLI")
    lines.append("! " + "=" * 52)

    script_text = '\n'.join(lines)

    return jsonify({
        'script': script_text,
        'filename': 'fix_script_' + str(audit['filename']) + '.txt',
        'violations_count': audit['violation_count'],
        'vendor': audit['vendor']
    })


@app.route('/audit/<int:audit_id>/graph')
@login_required
def knowledge_graph_route(audit_id):
    """Return the knowledge graph for an audit as JSON"""
    audit = get_audit_by_id(audit_id, current_user.id)
    if not audit:
        return jsonify({'error': 'Audit not found'}), 404

    try:
        kg = ComplianceKnowledgeGraph(audit)
        kg.build()
        return jsonify({
            'graph': kg.to_cytoscape_json(),
            'stats': kg.get_stats()
        })
    except Exception as e:
        print('Graph error: ' + str(e))
        return jsonify({'error': str(e)}), 500


@app.route('/audit/<int:audit_id>/pdf')
@login_required
def download_pdf(audit_id):
    """Generate and download a PDF report for this audit"""
    audit = get_audit_by_id(audit_id, current_user.id)
    if not audit:
        flash('Audit not found or access denied.')
        return redirect(url_for('history'))

    try:
        pdf_gen = AuditPDF(audit)
        pdf_bytes = pdf_gen.build()

        # Friendly filename
        safe_name = (audit.get('filename', 'audit') or 'audit').replace(' ', '_')
        pdf_filename = 'SecureAudit_Report_' + safe_name + '.pdf'

        return send_file(
            BytesIO(pdf_bytes),
            mimetype='application/pdf',
            as_attachment=True,
            download_name=pdf_filename
        )
    except Exception as e:
        print('PDF generation error: ' + str(e))
        flash('Could not generate PDF: ' + str(e))
        return redirect(url_for('view_audit', audit_id=audit_id))
if __name__ == '__main__':
    print("Starting Network Compliance Auditor...")
    app.run(debug=True, host='0.0.0.0', port=5000)