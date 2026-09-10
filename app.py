from groq import Groq
import os
from dotenv import load_dotenv

# Load your API key from the .env file
load_dotenv()
client = Groq(api_key=os.getenv('GROQ_API_KEY'))

def get_ai_analysis(config_text):
    """Sends the config file content to Groq for analysis."""
    try:
        chat_completion = client.chat.completions.create(
            messages=[
                {
                    "role": "system", 
                    "content": "You are an expert Network Security Auditor. Analyze the provided configuration file. Output the results in three sections: 1) Security Vulnerabilities found, 2) Compliance issues, 3) Remediation commands to fix them. Keep it concise."
                },
                {
                    "role": "user", 
                    "content": f"Analyze this network configuration file:\n\n{config_text}"
                }
            ],
            model="openai/gpt-oss-120b",
        )
        return chat_completion.choices[0].message.content
    except Exception as e:
        return f"Error calling AI: {str(e)}"
    # app.py
from flask import Flask, request, render_template, redirect, url_for, flash, jsonify
from werkzeug.utils import secure_filename
import os
import json
import zipfile
import shutil
from datetime import datetime
import groq


from config import Config
from parser import ConfigParser
from compliance_engine import ComplianceEngine
from database import init_db, save_audit, get_all_audits, get_audit_by_id, delete_audit, save_chat_message, get_chat_history

app = Flask(__name__)
app.config.from_object(Config)

# Ensure required directories exist (needed for cloud deployment)
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize database
init_db()

# Initialize Groq client for AI
try:
    client = groq.Groq(api_key=app.config['GROQ_API_KEY'])
    ai_enabled = True
except:
    ai_enabled = False
    print("Groq API not configured. AI features disabled.")

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def get_ai_explanation(violation):
    """Use AI to generate a structured, markdown-formatted explanation"""
    if not ai_enabled:
        return "AI explanation unavailable. Please add your Groq API key."

    try:
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
- **Compliance:** Which standards this violates, like PCI-DSS, NIST, ISO 27001

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
- Make commands realistic and executable
- Do NOT add intro or outro phrases
- Total length: under 200 words"""

        response = client.chat.completions.create(
            model="openai/gpt-oss-120b",
            messages=[
                {"role": "system", "content": "You are a network security expert. Output markdown only."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.4,
            max_tokens=500
        )

        return response.choices[0].message.content

    except Exception as e:
        return f"AI explanation failed: {str(e)}"

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        flash('No file selected')
        return redirect(request.url)
    
    file = request.files['file']
    
    if file.filename == '':
        flash('No file selected')
        return redirect(request.url)
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        # Read the configuration
        with open(filepath, 'r') as f:
            config_text = f.read()
        
        # Parse the configuration
        parser = ConfigParser(config_text)
        vendor = parser.detect_vendor()
        parser.vendor = vendor
        parse_success = parser.parse_config()
        
        # Run compliance checks
        engine = ComplianceEngine(config_text, vendor)
        violations, passed = engine.run_checks()
        score = engine.get_compliance_score()
        
        # Get AI explanations for violations
        for violation in violations:
            violation['ai_explanation'] = get_ai_explanation(violation)
        
        # Prepare results
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

        # Save to database                                   ADD THESE 2 LINES
        audit_id = save_audit(results)                       
        results['id'] = audit_id 

        # Save results to file (for demo purposes)
        result_file = f"results_{filename}.json"
        result_path = os.path.join('uploads', result_file)
        with open(result_path, 'w') as f:
            json.dump(results, f, indent=2)
        
        return render_template('result.html', results=results)
    
    flash('File type not allowed. Please upload .txt, .conf, .cfg, or .config files')
    return redirect(url_for('index'))

@app.route('/api/audit', methods=['POST'])
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
# ... (all your existing routes: /upload, /api/audit, etc.) ...


@app.route('/history')                              #  NEW
def history():                                       #  NEW
    """Show all past audits"""                       #  NEW
    audits = get_all_audits()                        #  NEW
    return render_template('history.html', audits=audits)  #  NEW

@app.route('/audit/<int:audit_id>')                  #  NEW
def view_audit(audit_id):                            #  NEW
    """View a specific audit from history"""         #  NEW
    audit = get_audit_by_id(audit_id)                #  NEW
    if not audit:                                    #  NEW
        flash('Audit not found')                     #  NEW
        return redirect(url_for('history'))          #  NEW
    chat_history = get_chat_history(audit_id)        #  NEW
    return render_template('result.html', results=audit, chat_history=chat_history)  #  NEW

@app.route('/audit/<int:audit_id>/delete', methods=['POST'])  #  NEW
def delete_audit_route(audit_id):                    #  NEW
    """Delete an audit"""                            #  NEW
    delete_audit(audit_id)                           #  NEW
    flash('Audit deleted successfully')              #  NEW
    return redirect(url_for('history'))              #  NEW

@app.route('/audit/<int:audit_id>/chat', methods=['POST'])  #  NEW
def chat_with_ai(audit_id):                          #  NEW
    """AI Chat Assistant - answer follow-up questions"""  #  NEW
    data = request.get_json()                        #  NEW
    user_message = data.get('message', '').strip()   #  NEW
    
    if not user_message:                             #  NEW
        return jsonify({'error': 'Message cannot be empty'}), 400  #  NEW
    
    audit = get_audit_by_id(audit_id)                #  NEW
    if not audit:                                    #  NEW
        return jsonify({'error': 'Audit not found'}), 404  #  NEW
    
    # Build context from the audit                   
    violations_summary = "\n".join([                 
        f"- {v['description']} (Severity: {v['severity']})"    
        for v in audit['violations']                 
    ]) or "No violations"                            
    
    passed_summary = "\n".join([                     
        f"- {p['description']}"                      
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

Answer the user's question clearly and concisely. If they ask for commands, provide exact vendor-specific ({audit['vendor']}) commands. Keep answers under 150 words."""

    past_chats = get_chat_history(audit_id)          
    messages = [{"role": "system", "content": context}]  
    
    for chat in past_chats[-5:]:                     
        messages.append({"role": "user", "content": chat['user']})     
        messages.append({"role": "assistant", "content": chat['ai']})   
    
    messages.append({"role": "user", "content": user_message})  
    
    models_to_try = ["openai/gpt-oss-120b", "openai/gpt-oss-20b", "llama-3.1-8b-instant"]  
    ai_response = None                               
    
    for model_name in models_to_try:                 
        try:                                         
            response = client.chat.completions.create(
                model=model_name,                    
                messages=messages,                   
                temperature=0.7,                     
                max_tokens=300                       
            )                                        
            ai_response = response.choices[0].message.content  
            break                                    
        except Exception as e:                       
            print(f"Model {model_name} failed: {e}, trying next...")  
            continue                                 
    
    if not ai_response:                              
        ai_response = "Sorry, I couldn't process your question right now."  
    
    save_chat_message(audit_id, user_message, ai_response)  
    
    return jsonify({                                 
        'response': ai_response,                     
        'timestamp': datetime.now().strftime('%H:%M:%S')  
    })


@app.route('/audit/<int:audit_id>/fix-script')
def generate_fix_script(audit_id):
    """Generate a single remediation script for all violations"""
    audit = get_audit_by_id(audit_id)
    if not audit:
        flash('Audit not found')
        return redirect(url_for('history'))

    # Build the script
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


@app.route('/upload-batch', methods=['POST'])

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

    # Extract to a timestamped folder
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

    # Find all valid config files
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

    # Process each config file
    batch_results = []

    for config_path in config_files:
        try:
            with open(config_path, 'r', errors='ignore') as f:
                config_text = f.read()

            if not config_text.strip():
                continue

            file_name = os.path.basename(config_path)

            # Parse
            parser = ConfigParser(config_text)
            vendor = parser.detect_vendor()
            parser.vendor = vendor
            parser.parse_config()

            # Run checks
            engine = ComplianceEngine(config_text, vendor)
            violations, passed = engine.run_checks()
            score = engine.get_compliance_score()

            # Get AI explanations for top 3 HIGH severity violations only (for speed)
            high_violations = [v for v in violations if v['severity'] == 'HIGH'][:3]
            for v in high_violations:
                v['ai_explanation'] = get_ai_explanation(v)
            for v in violations:
                if 'ai_explanation' not in v:
                    v['ai_explanation'] = ''

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

            audit_id = save_audit(results)
            results['id'] = audit_id
            batch_results.append(results)

        except Exception as e:
            print('Error processing ' + config_path + ': ' + str(e))
            continue

    if not batch_results:
        flash('No configs could be processed')
        return redirect(url_for('index'))

    # Sort by score (worst first)
    batch_results.sort(key=lambda x: x['compliance_score'])

    # Aggregate stats
    total_files = len(batch_results)
    avg_score = sum(r['compliance_score'] for r in batch_results) / total_files
    total_violations = sum(r['violation_count'] for r in batch_results)
    total_passed = sum(r['passed_count'] for r in batch_results)
    total_high = sum(
        sum(1 for v in r['violations'] if v['severity'] == 'HIGH')
        for r in batch_results
    )
    total_medium = sum(
        sum(1 for v in r['violations'] if v['severity'] == 'MEDIUM')
        for r in batch_results
    )
    total_low = sum(
        sum(1 for v in r['violations'] if v['severity'] == 'LOW')
        for r in batch_results
    )

    # Vendor breakdown
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

if __name__ == '__main__':
    # Create uploads folder if it doesn't exist
    if not os.path.exists('uploads'):
        os.makedirs('uploads')
    
    # Check if AI is enabled
    if ai_enabled:
        print("🤖 AI Assistant is ENABLED!")
    else:
        print("⚠️  AI Assistant is DISABLED. Add GROQ_API_KEY to .env file")
    
    print("🚀 Starting Network Compliance Auditor...")
    app.run(debug=True, host='0.0.0.0', port=5000)