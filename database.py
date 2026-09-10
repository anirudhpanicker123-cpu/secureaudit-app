# database.py
import sqlite3
import json
from datetime import datetime
import os

DB_PATH = 'audit_history.db'

def init_db():
    """Create the database and tables if they don't exist"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            vendor TEXT,
            compliance_score REAL,
            total_rules INTEGER,
            passed_count INTEGER,
            violation_count INTEGER,
            violations_json TEXT,
            passed_json TEXT,
            timestamp TEXT
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS chat_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            audit_id INTEGER,
            user_message TEXT,
            ai_response TEXT,
            timestamp TEXT,
            FOREIGN KEY (audit_id) REFERENCES audits(id)
        )
    ''')
    
    conn.commit()
    conn.close()

def save_audit(results):
    """Save an audit result to the database"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT INTO audits 
        (filename, vendor, compliance_score, total_rules, passed_count, violation_count, violations_json, passed_json, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        results['filename'],
        results['vendor'],
        results['compliance_score'],
        results['total_rules'],
        results['passed_count'],
        results['violation_count'],
        json.dumps(results['violations']),
        json.dumps(results['passed_checks']),
        results['timestamp']
    ))
    
    audit_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return audit_id

def get_all_audits():
    """Get all past audits (summary only)"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT id, filename, vendor, compliance_score, total_rules, 
               passed_count, violation_count, timestamp
        FROM audits
        ORDER BY id DESC
    ''')
    
    rows = cursor.fetchall()
    conn.close()
    
    audits = []
    for row in rows:
        audits.append({
            'id': row[0],
            'filename': row[1],
            'vendor': row[2],
            'compliance_score': row[3],
            'total_rules': row[4],
            'passed_count': row[5],
            'violation_count': row[6],
            'timestamp': row[7]
        })
    return audits

def get_audit_by_id(audit_id):
    """Get full audit details by ID"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM audits WHERE id = ?', (audit_id,))
    row = cursor.fetchone()
    conn.close()
    
    if not row:
        return None
    
    return {
        'id': row[0],
        'filename': row[1],
        'vendor': row[2],
        'compliance_score': row[3],
        'total_rules': row[4],
        'passed_count': row[5],
        'violation_count': row[6],
        'violations': json.loads(row[7]),
        'passed_checks': json.loads(row[8]),
        'timestamp': row[9]
    }

def delete_audit(audit_id):
    """Delete an audit by ID"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('DELETE FROM audits WHERE id = ?', (audit_id,))
    conn.commit()
    conn.close()

# ===== CHAT HISTORY FUNCTIONS =====

def save_chat_message(audit_id, user_message, ai_response):
    """Save a chat message pair"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT INTO chat_history (audit_id, user_message, ai_response, timestamp)
        VALUES (?, ?, ?, ?)
    ''', (audit_id, user_message, ai_response, datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
    
    conn.commit()
    conn.close()

def get_chat_history(audit_id):
    """Get chat history for an audit"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT user_message, ai_response, timestamp
        FROM chat_history
        WHERE audit_id = ?
        ORDER BY id ASC
    ''', (audit_id,))
    
    rows = cursor.fetchall()
    conn.close()
    
    return [{'user': r[0], 'ai': r[1], 'timestamp': r[2]} for r in rows]    