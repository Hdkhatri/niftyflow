
import logging
import os
import sqlite3
from flask import jsonify, render_template, render_template_string, request, redirect, url_for
import pandas as pd
import plotly.express as px
import sys
from flask import Blueprint

hk_bp = Blueprint('hk_bp', __name__)
from htmlconfig import DB_PATH, PATH
if PATH and PATH not in sys.path:
    sys.path.insert(0, PATH)
from commonFunction import convertIntoHeikinashi, delete_open_position, generate_god_signals, get_hedge_option, get_lot_size, get_optimal_option, hd_strategy, is_market_open, railway_track_strategy, record_trade, save_open_position
from config import SYMBOL, SERVER, INSTRUMENTS_FILE,CANDLE_DAYS as DAYS, HEDGE_NEAREST_LTP
from kitefunction import get_historical_df, get_quotes, get_token_for_symbol, place_option_hybrid_order
from kitelogin import do_login
from telegrambot import send_telegram_message
import time
import datetime
from datetime import timedelta

# Constants for investments
HEDGE_INVESTMENT = 80000
TRADING_INVESTMENT = 180000

instruments_df = pd.read_csv(INSTRUMENTS_FILE)
def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def MANUAL_EXIT(user, trade, config):
    logging.info(f"Inside Manual exit called for user: {user['user']} | trade: {trade} | config: {config}")
    try:
        current_ltp = get_quotes(trade["OptionSymbol"] ,user)
        entry_ltp = trade["OptionSellPrice"]
        instrument_token = get_token_for_symbol(SYMBOL)
        lot_size = get_lot_size(config, instruments_df)
        config['QTY'] = lot_size*int(config['LOT'])
        key = config.get('KEY')
        df = get_historical_df(instrument_token, config['INTERVAL'], DAYS, user)
        latest = df.iloc[-1]
        close = latest['close']
        current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            
        trade.update({
            "SpotExit": close,
            "ExitTime": current_time,
            "OptionBuyPrice": get_quotes(trade["OptionSymbol"] , user),
        })
        trade["PnL"] = trade["OptionSellPrice"] - trade["OptionBuyPrice"]
        trade["qty"] = trade.get("qty",config['QTY'])
        print(f"?? {user['user']} {SERVER}  |  {key}  |  {config['INTERVAL']} Exiting SELL: Buying back {trade['OptionSymbol']} | Qty: {trade['qty']}")
        logging.info(f"??INTERVAL {config['INTERVAL']} | Exiting SELL: Buying back {trade['OptionSymbol']} | Qty: {trade['qty']}")
        
        order_id ,avg_price,qty = place_option_hybrid_order(trade["OptionSymbol"], trade["qty"], "BUY",config, user)
        order_id ,avg_price,qty = None, None, None
        if config['HEDGE_TYPE'] != "NH":
            hedge_order_id , hedge_avg_price, hedge_qty = place_option_hybrid_order(trade["hedge_option_symbol"], trade["qty"], "SELL", config, user)
            hedge_order_id , hedge_avg_price, hedge_qty = None, None, None

        logging.info(f"order_id : {order_id} | opt_symbol : {trade['OptionSymbol']} avg_price : {avg_price} | qty : {qty}")

        if avg_price is None:
            avg_price = get_quotes(trade["OptionSymbol"], user)
            qty = config['QTY']
        if config['HEDGE_TYPE'] != "NH":
            if hedge_avg_price is None:
                hedge_avg_price = get_quotes(trade["hedge_option_symbol"], user)
                hedge_qty = config['QTY']

            trade.update({
                "OptionBuyPrice": avg_price,
                "ExitTime": current_time,
                "PnL": trade["OptionSellPrice"] - avg_price,
                "qty": qty,
                "ExitReason": "MANUAL_EXIT",
                "hedge_option_sell_price": hedge_avg_price,
                "hedge_exit_time": current_time,
                "hedge_pnl": hedge_avg_price - trade["hedge_option_buy_price"] ,
                "total_pnl": (trade["OptionSellPrice"] - avg_price) + (hedge_avg_price - trade["hedge_option_buy_price"] )
            })  
        else:
            trade.update({
                "OptionBuyPrice": avg_price,
                "ExitTime": current_time,
                "PnL": trade["OptionSellPrice"] - avg_price,
                "qty": qty,
                "ExitReason": "MANUAL_EXIT",
                "hedge_option_sell_price": 0.0,
                "hedge_exit_time": "-",
                "hedge_pnl": 0.0 ,
                "total_pnl": trade["OptionSellPrice"] - avg_price
            })  
        logging.info(f"??INTERVAL {config['INTERVAL']} | Exiting SELL: Buying back {trade['OptionSymbol']} | Qty: {trade['qty']}")
        record_trade(trade, config, user['id'])
        delete_open_position(trade["OptionSymbol"], config, trade, user['id'])
        if config['HEDGE_TYPE'] != "NH":
            send_telegram_message(f"INTERVAL {config['INTERVAL']} | {user['user']} {SERVER}  |  {key}  |  {config['INTERVAL']} Exit SELL\n{trade['OptionSymbol']} @ ?{trade['OptionBuyPrice']:.2f}. Hedge Exit Symbol {trade['hedge_option_symbol']} | @ ?{trade['hedge_option_sell_price']:.2f} | profit per quantity :{trade['total_pnl']}",user['telegram_chat_id'], user['telegram_token'])
        else:
            send_telegram_message(f"INTERVAL {config['INTERVAL']} | {user['user']} {SERVER}  |  {key}  |  {config['INTERVAL']} Exit SELL\n{trade['OptionSymbol']} @ ?{trade['OptionBuyPrice']:.2f}. profit per quantity :{trade['total_pnl']}",user['telegram_chat_id'], user['telegram_token'])
    except Exception as e:
        logging.error(f"Error in MANUAL_EXIT: {e}")
        return {'status': 'error', 'message': str(e)}


def manual_entry(config, user):
    logging.info(f"Inside manual_entry called for user: {user['user']} | config: {config}")
    do_login(user)
    # placeholder for actual manual order handling
    # `config` is expected to be a dict of trade_config columns for the requested key
    instrument_token = get_token_for_symbol(SYMBOL)
    lot_size = get_lot_size(config, instruments_df)
    config['QTY'] = lot_size*int(config['LOT'])
    key = config.get('KEY')
    df = get_historical_df(instrument_token, config['INTERVAL'], DAYS, user)
    if config['STRATEGY'] == "GOD":
        df = generate_god_signals(df)
    elif config['STRATEGY'] == "HDSTRATEGY":
        df = convertIntoHeikinashi(df)
        df = hd_strategy(df)
    elif config['STRATEGY'] == "RAILWAY_TRACK":
        df = railway_track_strategy(df)
    latest = df.iloc[-1]
    close = latest['close']
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    signal = "BUY" if latest['trend'] == 1 else "SELL"

    result = get_optimal_option(signal, close, config['NEAREST_LTP'], instruments_df, config, user)
    strike = result[1]
    if config['HEDGE_TYPE'] != "NH":
        if(config['HEDGE_TYPE'] == "H-P10" ):
            hedge_result = get_optimal_option(signal, close, HEDGE_NEAREST_LTP, instruments_df, config, user)
        elif(config['HEDGE_TYPE'] == "H-M100" or config['HEDGE_TYPE'] == "H-M200"):
            hedge_result = get_hedge_option(signal, close, strike, instruments_df, config, user)
    if result is None or result[0] is None:
        logging.error(f"?INTERVAL {config['INTERVAL']} | {user['user']} {SERVER}  |  {key}  |  {config['INTERVAL']}: No suitable option found for BUY signal.")
        send_telegram_message(f"?INTERVAL {config['INTERVAL']} | {user['user']} {SERVER}  |  {key}  |  {config['INTERVAL']}: No suitable option found for BUY signal.",user['telegram_chat_id'], user['telegram_token'])
        
    else:
        opt_symbol, strike, expiry, ltp = result
        if config['HEDGE_TYPE'] != "NH":
            hedge_opt_symbol, hedge_strike, hedge_expiry, hedge_ltp = hedge_result
            print(f"??INTERVAL {config['INTERVAL']} | {user['user']} {SERVER}  |  {key}  |  {config['INTERVAL']} Entering HEDGE BUY: {hedge_opt_symbol} | Strike: {hedge_strike} | Expiry: {hedge_expiry} | LTP: ?{hedge_ltp:.2f}")
            logging.info(f"??INTERVAL {config['INTERVAL']} | {user['user']} {SERVER}  |  {key}  |  {config['INTERVAL']} Entering HEDGE BUY: {hedge_opt_symbol} | Strike: {hedge_strike} | Expiry: {hedge_expiry} | LTP: ?{hedge_ltp:.2f}")
            logging.info(f"Placing Hedge BUY order for {hedge_opt_symbol} | Qty: {config['QTY']} | User: {user} | Key: {key}")
            hedge_order_id, hedge_avg_price, hedge_qty = place_option_hybrid_order(hedge_opt_symbol, config['QTY'], "BUY", config, user)
            hedge_order_id , hedge_avg_price, hedge_qty = None, None, None
            logging.info(f"hedge_order_id : {hedge_order_id} | hedge_opt_symbol : {hedge_opt_symbol} hedge_avg_price : {hedge_avg_price} | hedge_qty : {hedge_qty}")

        print(f"??INTERVAL {config['INTERVAL']} | {user['user']} {SERVER}  |  {key}  |  {config['INTERVAL']}  {opt_symbol} | Strike: {strike} | Expiry: {expiry} | LTP: ?{ltp:.2f}")
        logging.info(f"??INTERVAL {config['INTERVAL']} | {user['user']} {SERVER}  |  {key}  |  {config['INTERVAL']}  {opt_symbol} | Strike: {strike} | Expiry: {expiry} | LTP: ?{ltp:.2f}")

        logging.info(f"Placing Sell order for {opt_symbol} | Qty: {config['QTY']} | User: {user['user']} | Key: {key}")
        order_id ,avg_price,qty = place_option_hybrid_order(opt_symbol, config['QTY'], "SELL", config, user)
        order_id ,avg_price,qty = None, None, None
        logging.info(f"{key} | order_id : {order_id} | opt_symbol : {opt_symbol} avg_price : {avg_price} | qty : {qty}")
        time.sleep(2)
        
        if config['HEDGE_TYPE'] != "NH":
            if hedge_avg_price is None:
                hedge_avg_price = hedge_ltp
                hedge_qty = config['QTY']
        
        if avg_price is None:
            avg_price = ltp
            qty = config['QTY']

        logging.info(f"??INTERVAL {config['INTERVAL']} | Avg price for {opt_symbol}: ?{avg_price:.2f} | Qty: {qty}")

        if config['HEDGE_TYPE'] != "NH":
            trade = {
                "Signal": signal, "SpotEntry": close, "OptionSymbol": opt_symbol,
                "Strike": strike, "Expiry": expiry,
                "OptionSellPrice": avg_price, "EntryTime": current_time,
                "qty": qty, "interval": config['INTERVAL'], "real_trade": config['REAL_TRADE'],
                "EntryReason":"MANUAL_ENTRY", "ExpiryType":config['EXPIRY'],
                "Strategy":config['STRATEGY'], "Key":key, "hedge_option_symbol":hedge_opt_symbol,
                "hedge_strike":hedge_strike, "hedge_option_buy_price":hedge_avg_price,
                "hedge_qty":hedge_qty, "hedge_entry_time": current_time
            }
            send_telegram_message(f"??INTERVAL {config['INTERVAL']} | {user['user']} {SERVER}  |  {key}  |  {config['INTERVAL']} \n{opt_symbol} | Avg ?{avg_price:.2f} | Qty: {qty}. \n Hedge Symbol {trade['hedge_option_symbol']} | @ ?{trade['hedge_option_buy_price']:.2f}",user['telegram_chat_id'], user['telegram_token'])
        else:
            trade = {
                "Signal": signal, "SpotEntry": close, "OptionSymbol": opt_symbol,
                "Strike": strike, "Expiry": expiry,
                "OptionSellPrice": avg_price, "EntryTime": current_time,
                "qty": qty, "interval": config['INTERVAL'], "real_trade": config['REAL_TRADE'],
                "EntryReason":"MANUAL_ENTRY", "ExpiryType":config['EXPIRY'],
                "Strategy":config['STRATEGY'], "Key":key, "hedge_option_symbol":"-",
                "hedge_strike":"-", "hedge_option_buy_price":0.0,
                "hedge_qty":"-", "hedge_entry_time": "-"
            }
            send_telegram_message(f"??INTERVAL {config['INTERVAL']} | {user['user']} {SERVER}  |  {key}  |  {config['INTERVAL']} \n{opt_symbol} | Avg ?{avg_price:.2f} | Qty: {qty}.",user['telegram_chat_id'], user['telegram_token'])
        save_open_position(trade, config, user['id'])
    
    return {'status': 'ok', 'message': f"MANUAL_ENTRY processed for key {key}"}



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
        title='Monthly Total Amount (PnL*65)',
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
        title='Strategy-wise Total Amount (PnL*65)', text='percent_return',
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
        title='Key-wise Total Amount (PnL*65)', text='percent_return',
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
            <h2>Total Amount (PnL*65): {{{{ total_amount }}}}</h2>
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


@hk_bp.route('/admin')
def admin_index():
    conn = get_db_connection()
    # fetch id and user (name) to show friendly names in dropdown
    users = conn.execute('SELECT id, user FROM user_dtls ORDER BY id').fetchall()
    conn.close()
    return render_template('adminManualTrade.html', users=users)

@hk_bp.route('/get_keys/<int:user_id>')
def get_keys(user_id):
    conn = get_db_connection()
    keys = conn.execute(
        'SELECT key FROM trade_config WHERE user_Id = ?', 
        (user_id,)
    ).fetchall()
    conn.close()
    return jsonify([key['key'] for key in keys])


@hk_bp.route('/show_existing_trade')
def show_existing_trade():
    """Return latest open_trades row for given user_id and key as JSON array (or empty array)."""
    user_id = request.args.get('user_id', type=int)
    key = request.args.get('key')
    if not user_id or not key:
        return jsonify({'status': 'error', 'message': 'user_id and key required'}), 400
    conn = get_db_connection()
    row = conn.execute(
        """
        SELECT signal, spot_entry, option_symbol, strike, expiry,
               option_sell_price, entry_time, qty, interval, real_trade,
               entry_reason, expiry_type, strategy, key, user_id,
               hedge_option_symbol, hedge_strike, hedge_option_buy_price, hedge_qty, hedge_entry_time
        FROM open_trades
        WHERE user_id = ? AND key = ?
        ORDER BY id DESC LIMIT 1
        """,
        (user_id, key)
    ).fetchone()
    conn.close()
    if not row:
        return jsonify([])
    result = {k: row[k] for k in row.keys()}
    return jsonify([result])


@hk_bp.route('/open_trades')
def open_trades():
        """Render a page showing all open trades for a given user_id and key, with manual close buttons."""
        user_id = request.args.get('user_id', type=int)
        key = request.args.get('key')
        if not user_id or not key:
                return redirect(url_for('index'))
        conn = get_db_connection()
        rows = conn.execute(
                "SELECT id, option_symbol, qty, option_sell_price, hedge_option_symbol, hedge_option_buy_price, entry_time "
                "FROM open_trades WHERE user_id = ? AND key = ? ORDER BY id DESC",
                (user_id, key)
        ).fetchall()
        userrow = conn.execute('SELECT user FROM user_dtls WHERE id = ?', (user_id,)).fetchone()
        conn.close()

        user_name = userrow['user'] if userrow else f'User {user_id}'

        html = f"""
        <html>
        <head>
            <title>Open Trades for {key}</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
        </head>
        <body>
            <div class="container py-4">
                <h3>Open Trades for Key: <strong>{key}</strong></h3>
                <p>User: <strong>{user_name}</strong></p>
                <table class="table table-sm table-bordered">
                    <thead>
                        <tr>
                            <th>Option Symbol</th>
                            <th>Qty</th>
                            <th>Sell Price</th>
                            <th>Hedge Symbol</th>
                            <th>Hedge Buy Price</th>
                            <th>Entry Time</th>
                            <th>Action</th>
                        </tr>
                    </thead>
                    <tbody>
        """

        for r in rows:
                html += f"""
                        <tr>
                            <td>{r['option_symbol'] or ''}</td>
                            <td>{r['qty'] or ''}</td>
                            <td>{r['option_sell_price'] or ''}</td>
                            <td>{r['hedge_option_symbol'] or ''}</td>
                            <td>{r['hedge_option_buy_price'] or ''}</td>
                            <td>{r['entry_time'] or ''}</td>
                            <td>
                                <form method="post" action="/close_open_trade" style="display:inline;">
                                    <input type="hidden" name="id" value="{r['id']}">
                                    <input type="hidden" name="user_id" value="{user_id}">
                                    <input type="hidden" name="key" value="{key}">
                                    <button class="btn btn-sm btn-danger" type="submit">Close Manually</button>
                                </form>
                            </td>
                        </tr>
                """

        html += f"""
                    </tbody>
                </table>
                <a href="/admin" class="btn btn-secondary">Back to Keys</a>
            </div>
        </body>
        </html>
        """
        return html


@hk_bp.route('/close_open_trade', methods=['POST'])
def close_open_trade():
        """Delete the selected open_trades row (manual close) and redirect back to the open_trades page."""
        row_id = request.form.get('id', type=int)
        user_id = request.form.get('user_id', type=int)
        key = request.form.get('key')
        if not row_id:
            return redirect(url_for('index'))
        
        conn = get_db_connection()
        trade_row = conn.execute('SELECT * FROM open_trades WHERE id = ? AND user_id = ? AND key = ?', (row_id, user_id, key)).fetchone()
        conn.close()
        
        if not trade_row:
            return redirect(url_for('index'))
        
        # Convert sqlite Row to dict
        trade = {k: trade_row[k] for k in trade_row.keys()}
        trade['OptionSymbol'] = trade.get('option_symbol')

        trade = {
                "OptionSymbol": trade.get('option_symbol'),
                "OptionSellPrice": trade.get('option_sell_price'),
                "EntryReason": trade.get('entry_reason') , "ExpiryType":trade.get('expiry_type'),
                "hedge_option_symbol": trade.get('hedge_option_symbol'),
                "hedge_option_buy_price": trade.get('hedge_option_buy_price'),
                "Signal": trade.get('signal'),
                "SpotEntry": trade.get('spot_entry'),    
                "Strike": trade.get('strike'),
                "Expiry": trade.get('expiry'),
                "EntryTime": trade.get('entry_time'),
                "Key": trade.get('key'),
                "hedge_strike": trade.get('hedge_strike'),
                "hedge_qty": trade.get('hedge_qty'),
                "hedge_entry_time": trade.get('hedge_entry_time')
            }
        
        # Fetch user and config data
        conn = get_db_connection()
        print( f"user_id : {user_id} | key : {key}")
        userrow = conn.execute('SELECT * FROM user_dtls WHERE id = ?', (user_id,)).fetchone()
        print( f"userrow : {userrow}")
        configrow = conn.execute('SELECT * FROM trade_config WHERE key = ? AND user_Id = ?', (key, user_id)).fetchone()
        print( f"configrow : {configrow}")
        conn.close()
        
        if userrow is None or configrow is None:
            return redirect(url_for('index'))
        
        user = {k: userrow[k] for k in userrow.keys()}
        config = {k: configrow[k] for k in configrow.keys()}
        print( f"user : {user}" )
        print( f"config : {config}" )
        # Call MANUAL_EXIT
        try:
            MANUAL_EXIT(user, trade, config)
        except Exception as e:
            logging.error(f"Error in MANUAL_EXIT: {e}")
        
        
        return redirect(url_for('open_trades', user_id=user_id, key=key))



@hk_bp.route('/manual_order', methods=['POST'])
def manual_order():
    # Accept a JSON body with user_id and key, and acknowledge receipt.
    data = request.get_json() or {}
    user_id = data.get('user_id')
    key = data.get('key')
    if not user_id or not key:
        return jsonify({'status': 'error', 'message': 'user_id and key required'}), 400
    # Fetch trade configuration for this key and user from DB
    conn = get_db_connection()
    # try to locate the specific config row for the user + key
    row = conn.execute('SELECT * FROM trade_config WHERE key = ? AND user_Id = ?', (key, user_id)).fetchone()
    userrow = conn.execute('SELECT * FROM user_dtls WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    if userrow is None:
        return jsonify({'status': 'error', 'message': 'No userdata found for provided user id'}), 404
    if row is None:
        return jsonify({'status': 'error', 'message': 'No trade_config found for provided key'}), 404

    # build config dict from sqlite Row
    config = {k: row[k] for k in row.keys()}

    # build config dict from sqlite Row
    user = {k: userrow[k] for k in userrow.keys()}

    # call manual_entry with the collected config
    try:
        result = manual_entry(config, user)
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'manual_entry failed: {e}'}), 500

    # Ensure result is JSON-serializable; return it directly if dict-like
    if isinstance(result, dict):
        return jsonify(result)
    return jsonify({'status': 'ok', 'message': 'manual_entry called'})


@hk_bp.route('/ManualTrading')
def manual_trading():
    """Render the Manual Trading page for the logged-in user"""
    try:
        from flask import session
        user_id = session.get('user_id')
        if not user_id:
            return redirect(url_for('login_bp.login'))
        
        conn = get_db_connection()
        user = conn.execute('SELECT id, user FROM user_dtls WHERE id = ?', (user_id,)).fetchone()
        conn.close()
        
        if not user:
            return redirect(url_for('login_bp.login'))
        
        return render_template('manualTrading.html', user_id=user_id, username=user['user'])
    except Exception as e:
        logging.error(f"Error loading Manual Trading page: {e}")
        return redirect(url_for('login_bp.login'))


@hk_bp.route('/managestrategies')
def manage_strategies():
    """Render the Manage Strategies page for the logged-in user"""
    try:
        from flask import session
        user_id = session.get('user_id')
        if not user_id:
            return redirect(url_for('login_bp.login'))
        
        conn = get_db_connection()
        user = conn.execute('SELECT id, user FROM user_dtls WHERE id = ?', (user_id,)).fetchone()
        conn.close()
        
        if not user:
            return redirect(url_for('login_bp.login'))
        
        return render_template('manageStrategies.html', user_id=user_id, username=user['user'])
    except Exception as e:
        logging.error(f"Error loading Manage Strategies page: {e}")
        return redirect(url_for('login_bp.login'))


@hk_bp.route('/managestrategy', methods=['GET'])
def manage_strategy():
    """Render the Manage Strategy (edit form) page for a specific strategy"""
    try:
        from flask import session
        user_id = session.get('user_id')
        if not user_id:
            return redirect(url_for('login_bp.login'))
        
        strategy_id = request.args.get('strategy_id')
        if not strategy_id:
            return redirect(url_for('hk_bp.manage_strategies'))
        
        conn = get_db_connection()
        user = conn.execute('SELECT id, user FROM user_dtls WHERE id = ?', (user_id,)).fetchone()
        
        if not user:
            conn.close()
            return redirect(url_for('login_bp.login'))
        
        # Verify strategy belongs to user
        try:
            strategy_id = int(strategy_id)
        except ValueError:
            conn.close()
            return redirect(url_for('hk_bp.manage_strategies'))
        
        strategy = conn.execute(
            'SELECT * FROM trade_config WHERE ID = ? AND user_Id = ?', 
            (strategy_id, user_id)
        ).fetchone()
        conn.close()
        logging.info(f"strategy_id strategy: {strategy}")
        if not strategy:
            logging.warning(f"Strategy {strategy_id} not found for user {user_id}")
            return redirect(url_for('hk_bp.manage_strategies'))
        
        return render_template('manageStrategy.html', user_id=user_id, username=user['user'])
    except Exception as e:
        logging.error(f"Error loading Manage Strategy page: {e}")
        return redirect(url_for('login_bp.login'))


@hk_bp.route('/api/user-strategies')
def api_user_strategies():
    """API endpoint to fetch user strategies"""
    try:
        user_id_str = request.args.get('user_id')
        if not user_id_str:
            return jsonify({'success': False, 'message': 'user_id required'}), 400
        
        try:
            user_id = int(user_id_str)
        except (ValueError, TypeError):
            return jsonify({'success': False, 'message': 'Invalid user_id format'}), 400
        
        conn = get_db_connection()
        # Check if user exists
        user = conn.execute('SELECT id FROM user_dtls WHERE id = ?', (user_id,)).fetchone()
        if not user:
            conn.close()
            return jsonify({'success': False, 'message': 'User not found'}), 404
        
        # Fetch trade configurations as strategies
        strategies = conn.execute('''
            SELECT 
                tc.ID AS id,
                tc.key AS key,
                tc.key AS name,
                tc.interval AS interval_type,
                tc.strategy AS description,

                CASE 
                    WHEN tc.ACTIVE_FLAG = 1 THEN 'active'
                    ELSE 'not active'
                END AS status,

                COUNT(ot.key) AS trades_count

            FROM trade_config tc
            LEFT JOIN open_trades ot 
                ON tc.key = ot.key
                AND ot.user_Id = tc.user_Id     -- important

            WHERE tc.user_Id = ?
            AND tc.ACTIVE_FLAG IN (0,1)

            GROUP BY tc.ID, tc.key, tc.interval, tc.ACTIVE_FLAG
            ORDER BY tc.ACTIVE_FLAG DESC, tc.key;
        ''', (user_id,)).fetchall()
        
        conn.close()
        
        strategies_list = []
        for s in strategies:
            strategies_list.append({
                'id': s['id'],
                'key': s['key'],
                'name': s['name'],
                'description': s['description'],
                'status': s['status'],
                'type': 'Manual',
                'trades_count': s['trades_count']
            })
        
        logging.info(f"Fetched {len(strategies_list)} strategies for user {user_id}")
        return jsonify({'success': True, 'strategies': strategies_list})
    except Exception as e:
        logging.error(f"Error fetching user strategies: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500


@hk_bp.route('/api/strategy-details')
def api_strategy_details():
    """API endpoint to fetch strategy details"""
    try:
        strategy_id = request.args.get('strategy_id')
        user_id = request.args.get('user_id', type=int)
        
        if not strategy_id or not user_id:
            return jsonify({'success': False, 'message': 'strategy_id and user_id required'}), 400
        
        conn = get_db_connection()
        # Fetch strategy details
        strategy = conn.execute('''
            SELECT key as id, key as name, interval,
                   'Manual Trading Strategy' as description, 'active' as status, 
                   'Manual' as type, 0 as trades_count, 0 as total_pnl, 0 as win_rate
            FROM trade_config WHERE user_Id = ? AND key = ?
        ''', (user_id, strategy_id)).fetchone()
        
        conn.close()
        
        if not strategy:
            return jsonify({'success': False, 'message': 'Strategy not found'}), 404
        
        strategy_dict = {
            'id': strategy['id'],
            'name': strategy['name'],
            'description': strategy['description'],
            'status': strategy['status'],
            'type': strategy['type'],
            'trades_count': strategy['trades_count'],
            'total_pnl': strategy['total_pnl'],
            'win_rate': strategy['win_rate']
        }
        
        return jsonify({'success': True, 'strategy': strategy_dict})
    except Exception as e:
        logging.error(f"Error fetching strategy details: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500


@hk_bp.route('/api/open-trades')
def api_open_trades():
    """API endpoint to fetch open trades for user"""
    try:
        user_id_str = request.args.get('user_id')
        if not user_id_str:
            return jsonify({'success': False, 'message': 'user_id required'}), 400
        
        try:
            user_id = int(user_id_str)
        except (ValueError, TypeError):
            return jsonify({'success': False, 'message': 'Invalid user_id format'}), 400
        
        conn = get_db_connection()
        # Fetch open trades with hedge information
        trades = conn.execute('''
            SELECT id, key, option_symbol as symbol, option_sell_price as entry_price, 
                   qty as quantity, entry_time, 
                   COALESCE(option_sell_price, 0) as current_price,
                   hedge_option_symbol, hedge_option_buy_price
            FROM open_trades WHERE user_id = ?
            ORDER BY entry_time DESC
        ''', (user_id,)).fetchall()
        
        conn.close()
        
        trades_list = []
        for trade in trades:
            trades_list.append({
                'id': trade['id'],
                'strategy_key': trade['key'],
                'symbol': trade['symbol'],
                'entry_price': float(trade['entry_price']) if trade['entry_price'] else 0.0,
                'current_price': float(trade['current_price']) if trade['current_price'] else 0.0,
                'quantity': trade['quantity'],
                'entry_time': str(trade['entry_time']),
                'hedge_symbol': trade['hedge_option_symbol'] or None,
                'hedge_buy_price': float(trade['hedge_option_buy_price']) if trade['hedge_option_buy_price'] else None
            })
        
        logging.info(f"Fetched {len(trades_list)} open trades for user {user_id}")
        return jsonify({'success': True, 'trades': trades_list})
    except Exception as e:
        logging.error(f"Error fetching open trades: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500


@hk_bp.route('/api/manual-entry', methods=['POST'])
def api_manual_entry():
    """API endpoint to trigger manual entry for a strategy (similar to manual_entry function)"""
    try:
        data = request.get_json() or {}
        
        # Parse and validate data types
        try:
            user_id = int(data.get('user_id'))
            strategy_id = data.get('strategy_id')
        except (ValueError, TypeError) as e:
            return jsonify({'success': False, 'message': f'Invalid data format: {str(e)}...'}), 400
        
        if not all([user_id, strategy_id]):
            return jsonify({'success': False, 'message': 'user_id and strategy_id are required...'}), 400
        
        # Check if market is open
        if not is_market_open():
            return jsonify({'success': False, 'message': 'Market is currently closed. Please try during market hours.'}), 403
        
        conn = get_db_connection()
        try:
            # Fetch user data
            user_row = conn.execute('SELECT * FROM user_dtls WHERE id = ?', (user_id,)).fetchone()
            if not user_row:
                conn.close()
                return jsonify({'success': False, 'message': 'User not found'}), 404
            
            user = {k: user_row[k] for k in user_row.keys()}
            
            # Fetch trade config for the strategy
            config_row = conn.execute('SELECT * FROM trade_config WHERE id = ? AND user_Id = ?', 
                                     (strategy_id, user_id)).fetchone()
            if not config_row:
                conn.close()
                return jsonify({'success': False, 'message': 'Strategy configuration not found'}), 404
            
            config = {k: config_row[k] for k in config_row.keys()}
            
            conn.close()
            
            # Call the manual_entry function
            result = manual_entry(config, user)
            
            logging.info(f"Manual entry executed for user {user_id}, strategy {strategy_id}: {result}")
            
            return jsonify({
                'success': True, 
                'message': f'Manual entry triggered for strategy {strategy_id}.',
                'details': result
            })
        except Exception as e:
            if conn:
                conn.close()
            raise e
    except Exception as e:
        logging.error(f"Error in manual entry API: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500


@hk_bp.route('/api/close-trade', methods=['POST'])
def api_close_trade():
    """API endpoint to close an open trade using MANUAL_EXIT"""
    try:
        data = request.get_json() or {}
        
        try:
            trade_id = int(data.get('trade_id', 0))
            user_id = int(data.get('user_id', 0))
        except (ValueError, TypeError):
            return jsonify({'success': False, 'message': 'Invalid trade_id or user_id format'}), 400
        
        if not trade_id or not user_id:
            return jsonify({'success': False, 'message': 'trade_id and user_id required'}), 400
        
        # Check if market is open
        if not is_market_open():
            return jsonify({'success': False, 'message': 'Market is currently closed. Please try during market hours.'}), 403
        
        
        conn = get_db_connection()
        try:
            # Fetch trade data
            trade_row = conn.execute('SELECT * FROM open_trades WHERE id = ? AND user_id = ?', (trade_id, user_id)).fetchone()
            
            if not trade_row:
                conn.close()
                return jsonify({'success': False, 'message': 'Trade not found'}), 404
            
            # Convert sqlite Row to dict
            trade = {k: trade_row[k] for k in trade_row.keys()}
            key = trade.get('key')
            
            # Fetch user and config data
            userrow = conn.execute('SELECT * FROM user_dtls WHERE id = ?', (user_id,)).fetchone()
            configrow = conn.execute('SELECT * FROM trade_config WHERE key = ? AND user_Id = ?', (key, user_id)).fetchone()
            
            if userrow is None or configrow is None:
                conn.close()
                return jsonify({'success': False, 'message': 'User or config not found'}), 404
            
            user = {k: userrow[k] for k in userrow.keys()}
            config = {k: configrow[k] for k in configrow.keys()}
            
            # Prepare trade dict for MANUAL_EXIT
            trade = {
                "OptionSymbol": trade.get('option_symbol'),
                "OptionSellPrice": trade.get('option_sell_price'),
                "EntryReason": trade.get('entry_reason'),
                "ExpiryType": trade.get('expiry_type'),
                "hedge_option_symbol": trade.get('hedge_option_symbol'),
                "hedge_option_buy_price": trade.get('hedge_option_buy_price'),
                "Signal": trade.get('signal'),
                "SpotEntry": trade.get('spot_entry'),
                "Strike": trade.get('strike'),
                "Expiry": trade.get('expiry'),
                "EntryTime": trade.get('entry_time'),
                "Key": trade.get('key'),
                "hedge_strike": trade.get('hedge_strike'),
                "hedge_qty": trade.get('hedge_qty'),
                "hedge_entry_time": trade.get('hedge_entry_time')
            }
            
            # Call MANUAL_EXIT
            MANUAL_EXIT(user, trade, config)
            logging.info(f"Trade {trade_id} closed successfully for user {user_id}...")
            
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()
        
        return jsonify({'success': True, 'message': 'Trade closed successfully'})
    except Exception as e:
        logging.error(f"Error closing trade: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500


@hk_bp.route('/api/close-strategy', methods=['POST'])
def api_close_strategy():
    """API endpoint to close a strategy"""
    try:
        data = request.get_json() or {}
        strategy_id = data.get('strategy_id')
        
        try:
            user_id = int(data.get('user_id', 0))
        except (ValueError, TypeError):
            return jsonify({'success': False, 'message': 'Invalid user_id format'}), 400
        
        if not strategy_id or not user_id:
            return jsonify({'success': False, 'message': 'strategy_id and user_id required'}), 400
        
        conn = get_db_connection()
        try:
            # Update strategy status to inactive
            conn.execute('''
                UPDATE trade_config SET active = 0 WHERE user_Id = ? AND key = ?
            ''', (user_id, strategy_id))
            
            conn.commit()
            logging.info(f"Strategy {strategy_id} closed for user {user_id}")
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()
        
        return jsonify({'success': True, 'message': 'Strategy closed successfully'})
    except Exception as e:
        logging.error(f"Error closing strategy: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500


@hk_bp.route('/api/dashboard-stats')
def api_dashboard_stats():
    """API endpoint to fetch dashboard statistics"""
    try:
        user_id_str = request.args.get('user_id')
        if not user_id_str:
            return jsonify({'success': False, 'message': 'user_id required'}), 400
        
        try:
            user_id = int(user_id_str)
        except (ValueError, TypeError):
            return jsonify({'success': False, 'message': 'Invalid user_id format'}), 400
        
        conn = get_db_connection()
        
        # Get total profit (sum of pnl * qty from completed_trades)
        total_profit_row = conn.execute('''
            SELECT COALESCE(SUM(total_pnl * qty), 0) as total_profit
            FROM completed_trades WHERE user_id = ? AND real_trade = 'yes'
        ''', (user_id,)).fetchone()
        
        total_profit = float(total_profit_row['total_profit']) if total_profit_row else 0.0
        
        # Get active strategies count (from trade_config)
        active_strategies = conn.execute('''
            SELECT COUNT(*) as count FROM trade_config WHERE user_Id = ? AND active_flag = 1
        ''', (user_id,)).fetchone()
        
        active_strategies_count = active_strategies['count'] if active_strategies else 0
        
        # Get active trades count (from open_trades)
        active_trades = conn.execute('''
            SELECT COUNT(*) as count FROM open_trades WHERE user_id = ?
        ''', (user_id,)).fetchone()
        
        active_trades_count = active_trades['count'] if active_trades else 0
        
        conn.close()
        
        logging.info(f"Dashboard stats for user {user_id}: profit={total_profit}, strategies={active_strategies_count}, trades={active_trades_count}")
        
        return jsonify({
            'success': True,
            'total_profit': total_profit,
            'active_strategies': active_strategies_count,
            'active_trades': active_trades_count
        })
    except Exception as e:
        logging.error(f"Error fetching dashboard stats: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500


@hk_bp.route('/api/get-strategy-config', methods=['GET'])
def get_strategy_config():
    """Fetch strategy configuration for editing"""
    try:
        user_id = request.args.get('user_id')
        strategy_id = request.args.get('strategy_id')
        
        if not user_id or not strategy_id:
            return jsonify({'success': False, 'message': 'Missing user_id or strategy_id'}), 400
        
        try:
            user_id = int(user_id)
            strategy_id = int(strategy_id)
        except ValueError as e:
            logging.error(f"Type conversion error: {e}")
            return jsonify({'success': False, 'message': f'Invalid user_id or strategy_id format: {str(e)}'}), 400
        
        conn = get_db_connection()
        
        # Fetch strategy config
        strategy = conn.execute('''
            SELECT * FROM trade_config 
            WHERE ID = ? AND user_Id = ?
        ''', (strategy_id, user_id)).fetchone()
        
        conn.close()
        
        if not strategy:
            logging.warning(f"Strategy {strategy_id} not found for user {user_id}")
            return jsonify({'success': False, 'message': 'Strategy not found'}), 404
        
        # Convert to dict
        config = dict(strategy)
        
        logging.info(f"Fetched strategy config: {config['KEY']} for user {user_id}")
        print(config)
        return jsonify({
            'success': True,
            'strategy': config
        })
    except Exception as e:
        logging.error(f"Error fetching strategy config: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500


@hk_bp.route('/api/update-strategy-config', methods=['POST'])
def update_strategy_config():
    """Update strategy configuration"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'success': False, 'message': 'No data provided'}), 400
        
        user_id = data.get('user_id')
        strategy_id = data.get('strategy_id')
        
        if not user_id or not strategy_id:
            return jsonify({'success': False, 'message': 'Missing user_id or strategy_id'}), 400
        
        try:
            user_id = int(user_id)
            strategy_id = int(strategy_id)
        except ValueError as e:
            logging.error(f"Type conversion error: {e}")
            return jsonify({'success': False, 'message': f'Invalid user_id or strategy_id format: {str(e)}'}), 400
        
        # Validate and convert numeric fields
        try:
            nearest_ltp = int(data.get('nearest_ltp', 0))
            monthly_stoploss = int(data.get('monthly_stoploss', 0))
            activate_monthly_sl = int(data.get('activate_monthly_sl', 0))
            stoploss_per_trade = int(data.get('stoploss_per_trade', 0))
            activate_sl_per_trade = int(data.get('activate_sl_per_trade', 0))
        except ValueError as e:
            logging.error(f"Numeric conversion error: {e}")
            return jsonify({'success': False, 'message': f'Invalid numeric field value: {str(e)}'}), 400
        
        conn = get_db_connection()
        
        # Verify user owns this strategy
        strategy = conn.execute('''
            SELECT * FROM trade_config WHERE ID = ? AND user_Id = ?
        ''', (strategy_id, user_id)).fetchone()
        
        if not strategy:
            conn.close()
            logging.warning(f"Strategy {strategy_id} not found for user {user_id}")
            return jsonify({'success': False, 'message': 'Strategy not found'}), 404
        
        # Update strategy config
        try:
            conn.execute('''
                UPDATE trade_config SET
                    interval = ?,
                    lot = ?,
                    nearest_ltp = ?,
                    intraday = ?,
                    new_trade = ?,
                    real_trade = ?,
                    expiry = ?,
                    strategy = ?,
                    hedge_type = ?,
                    hedge_rollover_type = ?,
                    
                    monthly_stoploss = ?,
                    activate_monthly_sl = ?,
                    stoploss_per_trade = ?,
                    activate_sl_per_trade = ?,
                    lst_updt_dt = ?
                WHERE ID = ? AND user_Id = ?
            ''', (
                data.get('interval'),
                data.get('lot'),
                nearest_ltp,
                data.get('intraday'),
                data.get('new_trade'),
                data.get('real_trade'),
                data.get('expiry'),
                data.get('strategy'),
                data.get('hedge_type'),
                data.get('hedge_rollover_type'),
                monthly_stoploss,
                activate_monthly_sl,
                stoploss_per_trade,
                activate_sl_per_trade,
                datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                strategy_id,
                user_id
            ))
            
            conn.commit()
            conn.close()
            
            logging.info(f"Updated strategy config for strategy ID {strategy_id}, user {user_id}")
            
            return jsonify({
                'success': True,
                'message': 'Strategy configuration updated successfully'
            })
        except Exception as e:
            conn.close()
            logging.error(f"Database update error: {e}")
            import traceback
            traceback.print_exc()
            return jsonify({'success': False, 'message': f'Database error: {str(e)}'}), 500
    except Exception as e:
        logging.error(f"Error updating strategy config: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500




