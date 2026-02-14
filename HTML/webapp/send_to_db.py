from flask import Flask, request, jsonify
import sqlite3
import os
import sys


app = Flask(__name__)

# Enable CORS for all routes
from flask_cors import CORS
CORS(app)   

# Database setup
DB_PATH = os.path.join(os.path.dirname(__file__), 'contact_submissions.db')
def init_db():
    try:
        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            # Add new columns if not exist
            c.execute('''CREATE TABLE IF NOT EXISTS submissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL,
                phone TEXT,
                message TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                read INTEGER DEFAULT 0,
                follow_up INTEGER DEFAULT 0
            )''')
            # Try to add columns if they don't exist (for upgrades)
            try:
                c.execute('ALTER TABLE submissions ADD COLUMN phone TEXT')
            except Exception:
                pass
            try:
                c.execute('ALTER TABLE submissions ADD COLUMN read INTEGER DEFAULT 0')
            except Exception:
                pass
            try:
                c.execute('ALTER TABLE submissions ADD COLUMN follow_up INTEGER DEFAULT 0')
            except Exception:
                pass
            conn.commit()
        print(f"Database initialized at {DB_PATH}")
    except Exception as e:
        print(f"Error initializing database: {e}")
        raise
init_db()



# Save contact form submission to SQLite
@app.route('/send-email', methods=['POST'])
def save_submission():
    data = request.json
    name = data.get('name')
    email = data.get('email')
    phone = data.get('phone', '')
    message = data.get('message')
    if not (name and email and message):
        return jsonify({'success': False, 'message': 'Missing required fields.'}), 400
    # Validate phone: allow only digits or empty
    if phone and (not phone.isdigit()):
        return jsonify({'success': False, 'message': 'Phone number must contain only digits.'}), 400
    try:
        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            c.execute('INSERT INTO submissions (name, email, phone, message) VALUES (?, ?, ?, ?)', (name, email, phone, message))
            conn.commit()
        return jsonify({'success': True, 'message': 'Submission saved successfully.'}), 200
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


# View all submissions in a table
from flask import render_template_string
def get_submissions():
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute('SELECT id, name, email, phone, message, created_at, read, follow_up FROM submissions ORDER BY created_at DESC')
        return c.fetchall()



@app.route('/view-submissions')
def view_submissions():
    submissions = get_submissions()
    html = '''
    <!doctype html>
    <html lang="en">
    <head>
        <meta charset="utf-8"/>
        <title>Contact Submissions</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; }
            table { border-collapse: collapse; width: 100%; }
            th, td { border: 1px solid #ccc; padding: 8px; }
            th { background: #f0f0f0; }
            .btn { padding: 4px 10px; border: none; border-radius: 3px; cursor: pointer; }
            .btn-read { background: #e0e0e0; }
            .btn-unread { background: #ffd6d6; }
            .btn-follow { background: #d6eaff; }
            .btn-unfollow { background: #e0e0e0; }
        </style>
    </head>
    <body>
        <h1>Contact Submissions</h1>
        <table>
            <tr><th>ID</th><th>Name</th><th>Email</th><th>Phone</th><th>Message</th><th>Created At</th><th>Read</th><th>Follow Up</th></tr>
            {% for row in submissions %}
            <tr>
                <td>{{ row[0] }}</td>
                <td>{{ row[1] }}</td>
                <td>{{ row[2] }}</td>
                <td>{{ row[3] }}</td>
                <td>{{ row[4] }}</td>
                <td>{{ row[5] }}</td>
                <td>
                    <form method="post" action="/toggle-read" style="display:inline">
                        <input type="hidden" name="id" value="{{ row[0] }}"/>
                        {% if row[6] %}
                        <button class="btn btn-read" type="submit">Read</button>
                        {% else %}
                        <button class="btn btn-unread" type="submit">Unread</button>
                        {% endif %}
                    </form>
                </td>
                <td>
                    <form method="post" action="/toggle-follow" style="display:inline">
                        <input type="hidden" name="id" value="{{ row[0] }}"/>
                        {% if row[7] %}
                        <button class="btn btn-follow" type="submit">Follow Up</button>
                        {% else %}
                        <button class="btn btn-unfollow" type="submit">No Follow Up</button>
                        {% endif %}
                    </form>
                </td>
            </tr>
            {% endfor %}
        </table>
    </body>
    </html>
    '''
    return render_template_string(html, submissions=submissions)

# Toggle read status
from flask import redirect, url_for
@app.route('/toggle-read', methods=['POST'])
def toggle_read():
    sub_id = request.form.get('id')
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute('UPDATE submissions SET read = 1-read WHERE id = ?', (sub_id,))
        conn.commit()
    return redirect(url_for('view_submissions'))

# Toggle follow up status
@app.route('/toggle-follow', methods=['POST'])
def toggle_follow():
    sub_id = request.form.get('id')
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute('UPDATE submissions SET follow_up = 1-follow_up WHERE id = ?', (sub_id,))
        conn.commit()
    return redirect(url_for('view_submissions'))

# if __name__ == '__main__':
#     app.run(debug=True)


if __name__ == '__main__':
    print("=" * 60)
    print("🚀 Starting Contact Submission Server")
    print("📄 Contact Form: http://localhost:8000/contact.html")
    print("📋 View Submissions: http://localhost:5000/view-submissions")
    print("=" * 60)
    sys.stdout.flush()
    sys.stderr.flush()

    try:
        app.run(host='0.0.0.0', port=8000, debug=False, use_reloader=False, threaded=True)
    except KeyboardInterrupt:
        print("\n✅ Contact Submission Server stopped")
        sys.exit(0)