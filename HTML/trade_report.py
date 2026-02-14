
import os
import sqlite3
from flask import Flask, render_template_string, request, redirect, url_for, jsonify
import traceback
import pandas as pd
import plotly.express as px
import sys
from flask_cors import CORS
import requests



app = Flask(__name__)
CORS(app)

# ===== Flask Configuration =====
app.secret_key = 'tradejenie_secure_secret_key_2024_update_in_production'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True if using HTTPS
app.config['PERMANENT_SESSION_LIFETIME'] = __import__('datetime').timedelta(hours=24)

# --- Telegram Bot Config ---
# Replace with your actual bot tokens and chat IDs
TELEGRAM_BOT_TOKEN_1 = '8503112654:AAFqR6ir0hO1lp0vFUX-cANfZdBW98x41TY'
TELEGRAM_CHAT_ID_1 = '8016061002'
TELEGRAM_BOT_TOKEN_2 = '8358403068:AAHFkIxITvoWkEJKyWBx6v9e-pjP6bkGneA'
TELEGRAM_CHAT_ID_2 = '5827825724'

def send_telegram_message(text):
    for bot_token, chat_id in [
        (TELEGRAM_BOT_TOKEN_1, TELEGRAM_CHAT_ID_1),
        (TELEGRAM_BOT_TOKEN_2, TELEGRAM_CHAT_ID_2)
    ]:
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        payload = {"chat_id": chat_id, "text": text}
        try:
            resp = requests.post(url, json=payload, timeout=5)
            resp.raise_for_status()
        except Exception as e:
            print(f"Error sending Telegram message to {chat_id}: {e}")

# Constants for investments
# Constants for investments
HEDGE_INVESTMENT = 80000
TRADING_INVESTMENT = 180000
from login import login_bp
app.register_blueprint(login_bp)
from manualtrading import hk_bp
app.register_blueprint(hk_bp)

# ===== Session Management =====
from flask import session
@app.before_request
def session_handler():
    """
    Validate session on every request
    """
    from flask import request, redirect, url_for
    # Make session changes persistent
    session.permanent = True
    # Clear session if it's invalid or expired
    if 'user_id' in session:
        # Validate that session has all required fields
        if 'username' not in session or 'login_time' not in session:
            session.clear()

@app.route('/_routes')
def list_routes():
    output = []
    for rule in app.url_map.iter_rules():
        methods = ','.join(sorted(rule.methods - {'HEAD', 'OPTIONS'}))
        output.append(f"{rule.rule} [{methods}]")
    return '<br>'.join(sorted(output))


# Global 404 handler: redirect logged-in users to dashboard, others to login
@app.errorhandler(404)
def handle_404(error):
    try:
        # If session has user_id, consider user logged in
        if session.get('user_id'):
            return redirect('/dashboard')
        else:
            return redirect('/login')
    except Exception:
        return redirect('/login')
# --- Contact Form DB Setup (from send_to_db.py) ---
CONTACT_DB_PATH = os.path.join(os.path.dirname(__file__), 'contact_submissions.db')
def init_contact_db():
    try:
        with sqlite3.connect(CONTACT_DB_PATH) as conn:
            c = conn.cursor()
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
        print(f"Contact DB initialized at {CONTACT_DB_PATH}")
    except Exception as e:
        print(f"Error initializing contact DB: {e}")
        raise
init_contact_db()


# Helper to read trades from a given DB
# Helper to read trades from a given DB
def get_trades_df(db_path, user_id=None):
    if not os.path.exists(db_path):
        return pd.DataFrame()
    conn = sqlite3.connect(db_path)
    try:
        if user_id:
            df = pd.read_sql_query(
                "SELECT * FROM completed_trades WHERE real_trade = 'yes' AND user_id = ?",
                conn,
                params=(user_id,)
            )
        else:
            df = pd.read_sql_query(
                "SELECT * FROM completed_trades WHERE real_trade = 'yes'",
                conn
            )
    except Exception:
        df = pd.DataFrame()
    finally:
        conn.close()
    return df

# --- Contact Form Helpers and Routes (from send_to_db.py) ---
def get_contact_submissions():
    with sqlite3.connect(CONTACT_DB_PATH) as conn:
        c = conn.cursor()
        c.execute('SELECT id, name, email, phone, message, created_at, read, follow_up FROM submissions ORDER BY created_at DESC')
        return c.fetchall()

@app.route('/send-email', methods=['POST'])
def save_contact_submission():
    print("Received contact form submission")
    data = request.json
    name = data.get('name')
    email = data.get('email')
    phone = data.get('phone', '')
    message = data.get('message')
    if not (name and email and message):
        return jsonify({'success': False, 'message': 'Missing required fields.'}), 400
    if phone and (not phone.isdigit()):
        return jsonify({'success': False, 'message': 'Phone number must contain only digits.'}), 400
    try:
        with sqlite3.connect(CONTACT_DB_PATH) as conn:
            c = conn.cursor()
            c.execute('INSERT INTO submissions (name, email, phone, message) VALUES (?, ?, ?, ?)', (name, email, phone, message))
            conn.commit()
        # Send Telegram notification to both chat IDs
        telegram_text = f"New Contact Submission:\nName: {name}\nEmail: {email}\nPhone: {phone}\nMessage: {message}"
        send_telegram_message(telegram_text)
        return jsonify({'success': True, 'message': 'Submission saved successfully.'}), 200
    except Exception as e:
        print("Error in /send-email:", e)
        traceback.print_exc()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/view-submissions')
def view_contact_submissions():
    submissions = get_contact_submissions()
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

@app.route('/toggle-read', methods=['POST'])
def toggle_contact_read():
    sub_id = request.form.get('id')
    with sqlite3.connect(CONTACT_DB_PATH) as conn:
        c = conn.cursor()
        c.execute('UPDATE submissions SET read = 1-read WHERE id = ?', (sub_id,))
        conn.commit()
    return redirect(url_for('view_contact_submissions'))

@app.route('/toggle-follow', methods=['POST'])
def toggle_contact_follow():
    sub_id = request.form.get('id')
    with sqlite3.connect(CONTACT_DB_PATH) as conn:
        c = conn.cursor()
        c.execute('UPDATE submissions SET follow_up = 1-follow_up WHERE id = ?', (sub_id,))
        conn.commit()
    return redirect(url_for('view_contact_submissions'))


# Helper to get all users from user_dtls table
def get_users(db_path):
    if not os.path.exists(db_path):
        return pd.DataFrame()
    conn = sqlite3.connect(db_path)
    try:
        df = pd.read_sql_query("SELECT id, user FROM user_dtls ORDER BY id", conn)
    except Exception:
        df = pd.DataFrame()
    finally:
        conn.close()
    return df


# Shared report renderer
def render_trade_report(db_path, page_title, investment_amount, pnl_column='pnl', user_id=None):
    df = get_trades_df(db_path, user_id)
    if df.empty:
        html_empty = f"<html><body><h1>{page_title}</h1><p>No data available.</p></body></html>"
        return html_empty

    # Ensure numeric pnl column exists
    if pnl_column not in df.columns:
        df[pnl_column] = 0

    df[pnl_column] = pd.to_numeric(df[pnl_column], errors='coerce').fillna(0)
    df['total_amount'] = df[pnl_column] * 65
    total_amount = df['total_amount'].sum()
    percent_return = (total_amount / investment_amount) * 100 if investment_amount else 0

    # Parse exit_time robustly: handle epoch (ms/s) and diverse string formats
    raw_et = df.get('exit_time')
    if raw_et is None or raw_et.isna().all():
        df['exit_time'] = pd.NaT
    else:
        try:
            # If numeric (epoch), detect unit by max value
            if pd.api.types.is_numeric_dtype(raw_et):
                maxv = raw_et.max()
                unit = 'ms' if pd.notna(maxv) and maxv > 1e12 else 's'
                df['exit_time'] = pd.to_datetime(raw_et, unit=unit, errors='coerce')
            else:
                # Try common datetime formats for strings
                df['exit_time'] = pd.to_datetime(raw_et, format='%Y-%m-%d %H:%M:%S', errors='coerce')
                # If still NaT, try infer_datetime_format as fallback
                mask = df['exit_time'].isna() & raw_et.notna()
                if mask.any():
                    df.loc[mask, 'exit_time'] = pd.to_datetime(
                        raw_et[mask],
                        errors='coerce',
                        infer_datetime_format=True
                    )
        except Exception:
            df['exit_time'] = pd.to_datetime(raw_et, errors='coerce', infer_datetime_format=True)

    df['month_period'] = df['exit_time'].dt.to_period('M')
    monthly_pnl = df[df['month_period'].notna()].groupby('month_period', as_index=False).agg({pnl_column: 'sum'})
    monthly_pnl = monthly_pnl.sort_values('month_period')
    monthly_pnl['total_amount'] = monthly_pnl[pnl_column] * 65
    monthly_pnl['percent_return'] = (monthly_pnl['total_amount'] / investment_amount) * 100 if investment_amount else 0
    monthly_pnl['month'] = monthly_pnl['month_period'].dt.strftime('%b %Y')

    # -------- Monthly chart (loads Plotly from CDN once) --------
    fig_monthly = px.bar(
        monthly_pnl, x='month', y='total_amount',
        title='Monthly Total Amount (PnL × 65)',
        text='percent_return', color_discrete_sequence=['#4CAF50'],
        category_orders={'month': monthly_pnl['month'].tolist()}
    )
    fig_monthly.update_traces(texttemplate='%{text:.2f}%', textposition='outside')
    fig_monthly.update_layout(height=350, margin=dict(l=20, r=20, t=40, b=20), yaxis_title='Total Amount ')
    # Load plotly.js via CDN ONLY for this first chart
    monthly_chart = fig_monthly.to_html(full_html=False, include_plotlyjs='cdn')

    # -------- Strategy-wise chart (reuse Plotly already loaded) --------
    if 'strategy' in df.columns:
        strat_pnl = df.groupby('strategy', as_index=False).agg({pnl_column: 'sum'})
    else:
        strat_pnl = pd.DataFrame({'strategy': ['N/A'], pnl_column: [0]})
    strat_pnl['total_amount'] = strat_pnl[pnl_column] * 65
    strat_pnl['percent_return'] = (strat_pnl['total_amount'] / investment_amount) * 100 if investment_amount else 0

    fig_strat = px.bar(
        strat_pnl, x=strat_pnl.columns[0], y='total_amount',
        title='Strategy-wise Total Amount (PnL × 65)', text='percent_return',
        color_discrete_sequence=['#FF9800']
    )
    fig_strat.update_traces(texttemplate='%{text:.2f}%', textposition='outside')
    fig_strat.update_layout(height=350, margin=dict(l=20, r=20, t=40, b=20), yaxis_title='Total Amount ')
    # DO NOT include plotly.js again
    strat_chart = fig_strat.to_html(full_html=False, include_plotlyjs=False)

    # -------- Key-wise chart (reuse Plotly already loaded) --------
    if 'key' in df.columns:
        key_pnl = df.groupby('key', as_index=False).agg({pnl_column: 'sum'})
    else:
        key_pnl = pd.DataFrame({'key': ['N/A'], pnl_column: [0]})
    key_pnl['total_amount'] = key_pnl[pnl_column] * 65
    key_pnl['percent_return'] = (key_pnl['total_amount'] / investment_amount) * 100 if investment_amount else 0

    fig_key = px.bar(
        key_pnl, x=key_pnl.columns[0], y='total_amount',
        title='Key-wise Total Amount (PnL × 65)', text='percent_return',
        color_discrete_sequence=['#2196F3']
    )
    fig_key.update_traces(texttemplate='%{text:.2f}%', textposition='outside')
    fig_key.update_layout(height=350, margin=dict(l=20, r=20, t=40, b=20), yaxis_title='Total Amount ')
    # DO NOT include plotly.js again
    key_chart = fig_key.to_html(full_html=False, include_plotlyjs=False)

    # NOTE: Raw Data section removed from HTML
    html = f'''
    <html>
    <head>
        <title>{page_title}</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 0; padding: 0; background: #f7f7f7; }}
            .container {{ max-width: 1100px; margin: 30px auto; background: #fff; padding: 30px 40px; border-radius: 10px; box-shadow: 0 2px 8px #ccc; }}
            h1 {{ margin-top: 0; }}
            h2 {{ margin-bottom: 10px; margin-top: 30px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>{page_title}</h1>
            <h2>Total Amount (PnL × 65): {{{{ total_amount }}}}</h2>
            <h2>Percentage Return (on {investment_amount:,}): {{{{ percent_return }}}}%</h2>

            <h2>Monthly PnL</h2>
            {{{{ monthly_chart|safe }}}}

            <h2>Strategy-wise PnL</h2>
            {{{{ strat_chart|safe }}}}

            <h2>Key-wise PnL</h2>
            {{{{ key_chart|safe }}}}
        </div>
    </body>
    </html>
    '''
    return render_template_string(
        html,
        monthly_chart=monthly_chart,
        strat_chart=strat_chart,
        key_chart=key_chart,
        df=df,
        total_amount=f"{total_amount:,.2f}",
        percent_return=f"{percent_return:.2f}"
    )


@app.route('/pmk')
def report():
    return render_trade_report(
        '/home/harshilkhatri2808/pmk_all_in_one/Trading.db',
        'Completed Trades Analytics',
        TRADING_INVESTMENT,
        pnl_column='pnl'
    )


@app.route('/hedge_report')
def hedge_report():
    user_id = request.args.get('id', type=int)
    users_df = get_users('/home/harshilkhatri2808/prod/tradeJenie/Trading.db')
    users_list = users_df[['id', 'user']].values.tolist() if not users_df.empty else []

    # Build user selector HTML with user name only (ID hidden as value)
    user_options = ''.join([
        f'<option value="{uid}" {"selected" if uid == user_id else ""}>{uname}</option>'
        for uid, uname in users_list
    ])
    user_selector = f'''
    <div style="margin-bottom: 20px; padding: 15px; background: #e3f2fd; border-radius: 4px;">
        <form method="get" action="/hedge_report" style="display: inline-flex; gap: 10px; align-items: center;">
            <label for="id" style="font-weight: bold;">Select User:</label>
            <select name="id" id="id" required style="padding: 6px 10px; border-radius: 4px; border: 1px solid #ddd;">
                <option value="">-- Select User --</option>
                {user_options}
            </select>
            <button type="submit" style="padding: 6px 14px; border-radius: 4px; border: none; background: #2196F3; color: #fff; cursor: pointer;">Apply</button>
        </form>
    </div>
    '''

    user_ids = [uid for uid, _ in users_list]
    if user_id and user_id in user_ids:
        # Get user name for display
        user_name = next((uname for uid, uname in users_list if uid == user_id), 'Unknown')
        # Get report for selected user
        report_html = render_trade_report(
            '/home/harshilkhatri2808/prod/tradeJenie/Trading.db',
            f'Trading Hedge Analytics - {user_name}',
            HEDGE_INVESTMENT,
            pnl_column='total_pnl',
            user_id=user_id
        )
        # Insert user selector at the top
        report_html = report_html.replace('<div class="container">', f'<div class="container">{user_selector}', 1)
        return report_html
    else:
        # Show user selector only
        selector_html = f'''
        <html>
        <head>
            <title>Trading Hedge Analytics - Select User</title>
            <style>
                body {{ font-family: Arial, sans-serif; background: #f7f7f7; margin: 0; padding: 0; }}
                .container {{ max-width: 600px; margin: 50px auto; background: #fff; padding: 30px 40px; border-radius: 10px; box-shadow: 0 2px 8px #ccc; }}
                h1 {{ margin-top: 0; }}
                select {{ padding: 8px 12px; font-size: 16px; border-radius: 4px; border: 1px solid #ddd; }}
                button {{ padding: 8px 16px; margin-left: 10px; border-radius: 4px; border: none; background: #2196F3; color: #fff; cursor: pointer; }}
                button:hover {{ background: #1976D2; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Trading Hedge Analytics</h1>
                <p>Select a user to view their trading analytics:</p>
                <form method="get" action="/hedge_report">
                    <select name="id" required>
                        <option value="">-- Select User --</option>
                        {user_options}
                    </select>
                    <button type="submit">View Report</button>
                </form>
            </div>
        </body>
        </html>
        '''
        return selector_html

import manualtrading
if __name__ == '__main__':
    print("=" * 60)
    print("🚀 Starting Trade Report Server")
    print("📊 Trading Report: http://localhost:8000/")
    print("📈 Hedge Report: http://localhost:8000/hedge_report")
    print("=" * 60)
    sys.stdout.flush()
    sys.stderr.flush()

    try:
        app.run(host='0.0.0.0', port=8000, debug=False, use_reloader=False, threaded=True)
    except KeyboardInterrupt:
        print("\n✅ Trade Report Server stopped")
        sys.exit(0)
