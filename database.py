# database.py
import sqlite3
import json
from datetime import datetime
import os

DB_PATH = 'audit_history.db'


# ============================================================
# Database Schema Setup
# ============================================================

def init_db():
    """Create the database and tables if they don't exist."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Users table — for authentication
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            username TEXT,
            password_hash TEXT,
            profile_pic TEXT,
            created_at TEXT
        )
    ''')

    # Audits table — now scoped to user_id
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
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

    # Chat history table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS chat_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            audit_id INTEGER,
            user_message TEXT,
            ai_response TEXT,
            timestamp TEXT
        )
    ''')

    conn.commit()
    conn.close()


# ============================================================
# User Functions
# ============================================================

def create_user(email, username=None, password_hash=None, profile_pic=None):
    """Create a new user and return their ID."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO users (email, username, password_hash, profile_pic, created_at)
        VALUES (?, ?, ?, ?, ?)
    ''', (
        email,
        username,
        password_hash,
        profile_pic,
        datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    ))
    user_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return user_id


def get_user_by_email(email):
    """Return user dict by email, or None if not found."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return None

    return {
        'id': row[0],
        'email': row[1],
        'username': row[2],
        'password_hash': row[3],
        'profile_pic': row[4],
        'created_at': row[5]
    }


def get_user_by_id(user_id):
    """Return user dict by ID, or None if not found."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return None

    return {
        'id': row[0],
        'email': row[1],
        'username': row[2],
        'password_hash': row[3],
        'profile_pic': row[4],
        'created_at': row[5]
    }


# ============================================================
# Audit Functions (scoped per user)
# ============================================================

def save_audit(results, user_id):
    """Save an audit result for a specific user. Returns the new audit ID."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO audits
        (user_id, filename, vendor, compliance_score, total_rules,
         passed_count, violation_count, violations_json, passed_json, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        user_id,
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


def get_all_audits(user_id):
    """Return all audits for a specific user (most recent first)."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, filename, vendor, compliance_score, total_rules,
               passed_count, violation_count, timestamp
        FROM audits
        WHERE user_id = ?
        ORDER BY id DESC
    ''', (user_id,))
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


def get_audit_by_id(audit_id, user_id):
    """Return full audit dict — only if it belongs to this user."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        'SELECT * FROM audits WHERE id = ? AND user_id = ?',
        (audit_id, user_id)
    )
    row = cursor.fetchone()
    conn.close()

    if not row:
        return None

    return {
        'id': row[0],
        'user_id': row[1],
        'filename': row[2],
        'vendor': row[3],
        'compliance_score': row[4],
        'total_rules': row[5],
        'passed_count': row[6],
        'violation_count': row[7],
        'violations': json.loads(row[8]) if row[8] else [],
        'passed_checks': json.loads(row[9]) if row[9] else [],
        'timestamp': row[10]
    }


def delete_audit(audit_id, user_id):
    """Delete an audit — only if it belongs to this user."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        'DELETE FROM audits WHERE id = ? AND user_id = ?',
        (audit_id, user_id)
    )
    # Also clean up any chat history for this audit
    cursor.execute('DELETE FROM chat_history WHERE audit_id = ?', (audit_id,))
    conn.commit()
    conn.close()


# ============================================================
# Chat History Functions
# ============================================================

def save_chat_message(audit_id, user_message, ai_response):
    """Save a single chat message pair."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO chat_history (audit_id, user_message, ai_response, timestamp)
        VALUES (?, ?, ?, ?)
    ''', (
        audit_id,
        user_message,
        ai_response,
        datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    ))
    conn.commit()
    conn.close()


def get_chat_history(audit_id):
    """Return all chat messages for an audit in chronological order."""
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

    return [
        {'user': r[0], 'ai': r[1], 'timestamp': r[2]}
        for r in rows
    ]