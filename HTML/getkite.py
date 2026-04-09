import sys, os, sqlite3, datetime, logging
from flask import Flask, render_template, jsonify, request, Blueprint, session, redirect, url_for
import htmlconfig

# 1. Configuration & Path Setup
getkite_bp = Blueprint('getkite_bp', __name__)

if htmlconfig.PATH not in sys.path:
    sys.path.append(htmlconfig.PATH)

from kitefunction import get_kite_client
from kitelogin import do_login

app = Flask(__name__)

# This dictionary will store logged-in user data once they are selected
# Key: user_id, Value: user_dict (with active session)
user_sessions = {}

def get_all_active_user():
    """
    Returns a list of dicts for all active users from user_dtls table.
    """
    try:
        conn = sqlite3.connect(htmlconfig.DB_PATH)
        c = conn.cursor()
        sql = "SELECT * FROM user_dtls WHERE active_flag = 1"
        c.execute(sql)
        rows = c.fetchall()
        columns = [desc[0] for desc in c.description]
        users = [dict(zip(columns, row)) for row in rows]
        conn.close()
        return users
    except Exception as e:
        logging.error(f"❌ Error fetching active users: {e}")
        return []

def get_or_login_user(user_id):
    """
    Checks if user is in user_sessions. If not, fetches from DB and logs in.
    """
    if user_id in user_sessions:
        return user_sessions[user_id]
    
    # Not in cache, fetch from DB
    all_users = get_all_active_user()
    matched_user = next((u for u in all_users if u.get('id') == user_id), None)
    
    if matched_user:
        print(f"🔄 Initializing session for user: {matched_user.get('user')}")
        do_login(matched_user) # This should update the dict with session tokens
        user_sessions[user_id] = matched_user
        return matched_user
    
    return None

def get_logged_in_admin():
    """
    Returns the logged-in active admin row from user_dtls, or None.
    """
    try:
        user_id = session.get('user_id')
        username = session.get('username')

        if not user_id or not username:
            logging.warning(f"No session data: user_id={user_id}, username={username}")
            return None

        conn = sqlite3.connect(htmlconfig.DB_PATH)
        conn.row_factory = sqlite3.Row
        admin_user = conn.execute(
            """
            SELECT *
            FROM user_dtls
            WHERE id = ?
              AND active_flag = 1
              AND user_type = 'ADMIN'
            """,
            (user_id,)
        ).fetchone()
        conn.close()

        if not admin_user:
            logging.warning(f"User {user_id} is not an active ADMIN")
        
        return admin_user
    except Exception as e:
        logging.error(f"Error validating admin session: {e}")
        import traceback
        traceback.print_exc()
        return None

@getkite_bp.route('/kiteadmin')
def index():
    admin_user = get_logged_in_admin()
    if not admin_user:
        logging.warning(f"Admin user not found or not logged in. Redirecting to login.")
        session.clear()
        return redirect(url_for('login_bp.login'))

    # Only fetch user list for the dropdown; do NOT login here
    users = get_all_active_user()
    return render_template('getkite.html', users=users)

@getkite_bp.route('/api/portfolio/<int:user_id>')
def get_portfolio(user_id):
    try:
        # Lazy login: only logs in the user if they aren't already active
        matched_user = get_or_login_user(user_id)
        
        if not matched_user: 
            return jsonify({'success': False, 'message': 'User not found in Database'}), 404

        # 1. Fetch DB Trades
        conn = sqlite3.connect(htmlconfig.DB_PATH)
        conn.row_factory = sqlite3.Row
        db_trades = conn.execute("SELECT * FROM open_trades WHERE user_id = ?", (user_id,)).fetchall()
        conn.close()

        # 2. Fetch Live Data from Kite
        kite = get_kite_client(matched_user)
        live_positions = kite.positions().get('net', [])
        kite_holdings = kite.holdings()
        
        db_trades_list = [dict(t) for t in db_trades]
        live_symbols = {p['tradingsymbol']: p for p in live_positions}

        # 3. Map Live Data to DB Trades
        for db_trade in db_trades_list:
            symbol = db_trade['option_symbol']
            db_trade['is_live'] = symbol in live_symbols
            if db_trade['is_live']:
                db_trade['ltp'] = live_symbols[symbol]['last_price']
                db_trade['live_pnl'] = live_symbols[symbol]['pnl']

        return jsonify({
            'success': True,
            'db_open_trades': db_trades_list,
            'kite_positions': live_positions,
            'kite_holdings': kite_holdings
        })
    except Exception as e:
        logging.error(f"Portfolio Error: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

@getkite_bp.route('/api/exit-trade/<int:trade_id>', methods=['POST'])
def exit_trade(trade_id):
    conn = sqlite3.connect(htmlconfig.DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    try:
        # 1. Get the current trade details
        trade = cursor.execute("SELECT * FROM open_trades WHERE id = ?", (trade_id,)).fetchone()
        if not trade: return jsonify({'success': False, 'message': 'Trade not found'}), 404

        # 2. Get User and Kite Client
        matched_user = get_or_login_user(trade['user_id'])
        kite = get_kite_client(matched_user)
        
        # 3. Square Off (Market Orders)
        # Main Leg
        kite.place_order(variety=kite.VARIETY_REGULAR, exchange=kite.EXCHANGE_NFO,
                         tradingsymbol=trade['option_symbol'], transaction_type=kite.TRANSACTION_TYPE_BUY,
                         quantity=trade['qty'], product=kite.PRODUCT_NRML, order_type=kite.ORDER_TYPE_MARKET)

        # Hedge Leg
        if trade['hedge_option_symbol']:
            kite.place_order(variety=kite.VARIETY_REGULAR, exchange=kite.EXCHANGE_NFO,
                             tradingsymbol=trade['hedge_option_symbol'], transaction_type=kite.TRANSACTION_TYPE_SELL,
                             quantity=trade['hedge_qty'], product=kite.PRODUCT_NRML, order_type=kite.ORDER_TYPE_MARKET)

        # 4. Move to Completed Trades
        exit_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        opt_buy_price = 0.0 
        pnl = (trade['option_sell_price'] - opt_buy_price) * trade['qty']

        cursor.execute('''
            INSERT INTO completed_trades (
                signal, spot_entry, option_symbol, strike, expiry, option_sell_price, entry_time,
                option_buy_price, exit_time, pnl, qty, interval, real_trade, entry_reason, 
                strategy, key, user_id, hedge_option_symbol, hedge_strike, hedge_option_buy_price,
                hedge_qty, hedge_entry_time, total_pnl
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        ''', (
            trade['signal'], trade['spot_entry'], trade['option_symbol'], trade['strike'], 
            trade['expiry'], trade['option_sell_price'], trade['entry_time'],
            opt_buy_price, exit_time, pnl, trade['qty'], trade['interval'], 
            trade['real_trade'], trade['entry_reason'], trade['strategy'], trade['key'], 
            trade['user_id'], trade['hedge_option_symbol'], trade['hedge_strike'], 
            trade['hedge_option_buy_price'], trade['hedge_qty'], trade['hedge_entry_time'], pnl
        ))

        cursor.execute("DELETE FROM open_trades WHERE id = ?", (trade_id,))
        conn.commit()
        return jsonify({'success': True})
    except Exception as e:
        conn.rollback()
        return jsonify({'success': False, 'message': f"Kite/DB Error: {str(e)}"}), 500
    finally:
        conn.close()

# Register blueprint if necessary
app.register_blueprint(getkite_bp)

if __name__ == '__main__':
    # No pre-login here; login happens on-demand via the UI
    app.run(debug=True, port=5000)
