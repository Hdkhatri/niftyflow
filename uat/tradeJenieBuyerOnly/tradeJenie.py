    # emalive.py

import sys
import time
import datetime
from datetime import timedelta
import pandas as pd
import sqlite3
import logging
from commonFunction import check_monthly_stoploss_hit, close_position_and_no_new_trade, convertIntoHeikinashi, delete_open_position, generate_god_signals, get_next_candle_time, get_robust_optimal_option, get_trade_configs, hd_strategy, init_db, is_market_open, load_open_position, railway_track_strategy, record_trade, save_open_position, update_trade_config_on_failure, validate_trade_prices, wait_until_next_candle, who_tried, will_market_open_within_minutes,get_hedge_option,get_lot_size,check_trade_stoploss_hit,get_keywise_trade_config,is_valid_trade_data,get_clean_trade
from config import  HEDGE_NEAREST_LTP, PATH, SYMBOL,SEGMENT, CANDLE_DAYS as DAYS, REQUIRED_CANDLES, LOG_FILE,INSTRUMENTS_FILE, OPTION_SYMBOL, SERVER, ROLLOVER_CALC
from crud import get_stoploss_by_trade_config
from kitefunction import get_entire_quote, get_historical_df, place_option_hybrid_order, get_token_for_symbol, get_quotes_with_retry, place_robust_limit_order
from telegrambot import send_telegram_message,send_telegram_message_admin
import importlib
import threading
import pandas as pd
from requests.exceptions import ReadTimeout
from kiteconnect import exceptions
import random

from updateinstrument import get_tradable_symbols_and_save_filtered

# ====== Setup Logging ======
logging.basicConfig(
    filename=LOG_FILE,
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
instrument_token = None
# instrument_token = get_token_for_symbol(SYMBOL)

# if instrument_token is None:
#     logging.error(f"{SERVER} | ❌ Instrument token for {SYMBOL} not found. Exiting.")
#     exit(1)
# logging.info(f"{SERVER} | ℹ️ Instrument token for {SYMBOL}: {instrument_token} at current time {current_time}")

def _log_trade_mode(config, key, user):
    logging.info(f"{key} | {user['user']} {SERVER} Inside def _log_trade_mode")
    if config['REAL_TRADE'].lower() != "yes":
        print(f"🚫{key} | {user['user']} {SERVER}  | TRADE mode is OFF SIMULATED_ORDER will be tracked")
        # send_telegram_message(f"🛠️ {user['user']} {SERVER}  |  {key}  | OnlyLive {config['INTERVAL']} running in {'SIMULATION' if config['REAL_TRADE'].lower() != 'yes' else 'LIVE'} mode.",user['telegram_chat_id'], user['telegram_token'])
        logging.info(f"🚫 {key} | {user['user']} {SERVER}  | TRADE mode is OFF. Running in SIMULATION mode.")
    else:
        print(f"🚀 {key} | {user['user']} {SERVER}  | TRADE mode is ON LIVE_ORDER will be placed")
        # send_telegram_message(f"🚀 {user['user']} {SERVER}  |  {key}  | {config['INTERVAL']} Live trading started!",user['telegram_chat_id'], user['telegram_token'])
        logging.info(f"🚀 {key} | {user['user']} {SERVER}  | TRADE mode is ON. Running in LIVE mode.")


def _load_trade_state(config, key, user, send_resume_alert):
    logging.info(f"{key} | {user['user']} {SERVER} Inside def _load_trade_state")
    open_trade = load_open_position(config, key, user, user['id'])
    if open_trade:
        trade = open_trade
        position = open_trade["Signal"]
        logging.info(
            f"📌 {key}  |   {user['user']} {SERVER}  | Resumed open position: {position} | "
            f"{open_trade['OptionSymbol']} @ ₹{open_trade['OptionBuyPrice']} | Qty: {open_trade['qty']} | "
            f"Hedge Symbol: {open_trade['hedge_option_symbol']} @ ₹{open_trade['hedge_option_sell_price']} | "
            f"Hedge Qty: {open_trade['hedge_qty']}"
        )
        print(
            f"📌 {key}  |   {user['user']} {SERVER}  | Resumed open position: {position} | "
            f"{open_trade['OptionSymbol']} @ ₹{open_trade['OptionBuyPrice']} | Qty: {open_trade['qty']} | "
            f"Hedge Symbol: {open_trade['hedge_option_symbol']} @ ₹{open_trade['hedge_option_sell_price']} | "
            f"Hedge Qty: {open_trade['hedge_qty']}"
        )
        if send_resume_alert:
            send_telegram_message(
                f"📌 {key} | {user['user']} {SERVER}  | Resumed open position: {position} | "
                f"{open_trade['OptionSymbol']} @ ₹{open_trade['OptionBuyPrice']} | Qty: {open_trade['qty']} | "
                f"Hedge Symbol: {open_trade['hedge_option_symbol']} @ ₹{open_trade['hedge_option_sell_price']} | "
                f"Hedge Qty: {open_trade['hedge_qty']}",
                user['telegram_chat_id'],
                user['telegram_token']
            )
        return trade, position

    trade = {}
    position = None
    print(f"ℹ️ {key} | {user['user']} {SERVER}  |   No open position. Waiting for next signal...")
    logging.info(f"ℹ️ {key} | {user['user']} {SERVER}  |   No open position. Waiting for next signal...")
    return trade, position


def _refresh_trade_state_in_loop(config, key, user):
    logging.info(f"{key} | {user['user']} {SERVER} Inside def _refresh_trade_state_in_loop")
    open_trade = load_open_position(config, key, user, user['id'])
    if open_trade:
        trade = open_trade
        position = open_trade["Signal"]
        logging.info(
            f"📌 {key}  | {user['user']} {SERVER}  | Resumed open position: {position} | "
            f"{open_trade['OptionSymbol']} @ ₹{open_trade['OptionBuyPrice']} | Qty: {open_trade['qty']} | "
            f"Hedge Symbol: {open_trade['hedge_option_symbol']} @ ₹{open_trade['hedge_option_sell_price']} | "
            f"Hedge Qty: {open_trade['hedge_qty']}"
        )
        print(
            f"➡️ {key}  |  {user['user']} {SERVER} | Resumed open position: {position} | "
            f"{open_trade['OptionSymbol']} @ ₹{open_trade['OptionBuyPrice']} | Qty: {open_trade['qty']} | "
            f"Hedge Symbol: {open_trade['hedge_option_symbol']} @ ₹{open_trade['hedge_option_sell_price']} | "
            f"Hedge Qty: {open_trade['hedge_qty']}"
        )
        # send_telegram_message(f"📌 {key}  | {user['user']} {SERVER}  |  {config['INTERVAL']} Resumed open position: {position} | {open_trade['OptionSymbol']} @ ₹{open_trade['OptionBuyPrice']} | Qty: {open_trade['qty']} | Hedge Symbol: {open_trade['hedge_option_symbol']} @ ₹{open_trade['hedge_option_sell_price']} | Hedge Qty: {open_trade['hedge_qty']}",user['telegram_chat_id'], user['telegram_token'])
        return trade, position

    trade = {}
    position = None
    print(f"ℹ️ {key} | {user['user']} {SERVER} No open position. Waiting for next signal...")
    logging.info(f"ℹ️ {key} | {user['user']} {SERVER} No open position. Waiting for next signal...")
    return trade, position


def _refresh_runtime_config(key, instruments_df):
    logging.info(f"{key} |{SERVER} Inside def _refresh_runtime_config")
    # configs = get_trade_configs(user['id'])
    config = get_keywise_trade_config(key)
    lot_size = get_lot_size(config, instruments_df)
    logging.info(f"{key} | {SERVER} Lot size is {lot_size}")
    config['QTY'] = lot_size * int(config['LOT'])
    return config


def _should_stop_for_no_new_trade(config, trade, key, user):
    
    logging.info(f"{key} | {user['user']} {SERVER} Inside def _should_stop_for_no_new_trade")
    
    if config['NEW_TRADE'].lower() == "no" and trade == {}:
        print(f"🚫 {key}  | {user['user']} {SERVER}, There is no live trade present, No new trades allowed. So Closing the program")
        logging.info(f"🚫 {key}  |{user['user']} {SERVER}, There is no live trade present, No new trades allowed. So Closing the program")
        send_telegram_message(f"🕒 {key}  | {user['user']} {SERVER}, There is no live trade present, No new trades allowed. So Closing the program",user['telegram_chat_id'], user['telegram_token'])
        return True
    return False


def _handle_market_availability(key, user):
    logging.info(f"{key} | {user['user']} {SERVER} Inside def _handle_market_availability")
   
    if not is_market_open():
        print(f" {key}  | {user['user']} {SERVER} Market is closed. Checking if market will open within 60 minutes...")
        if will_market_open_within_minutes(60):
            print(f" {key} | {user['user']} {SERVER}Market will open within 60 minutes. Continuing to wait...")
            time.sleep(60)
            return "continue"
        print(f"{key}  | {user['user']} {SERVER}, Market will not open within 60 minutes. Stopping program.")
        send_telegram_message(f"🛑 {key}  | {user['user']} {SERVER}, Market will not open within 60 minutes. Stopping program.",user['telegram_chat_id'], user['telegram_token'])
        return "return"
    return None


def _should_stop_for_intraday_cutoff(config, trade, key, user):
    logging.info(f"{key} | {user['user']} {SERVER} Inside def _should_stop_for_intraday_cutoff")
   
    if config['INTRADAY'].lower() == "yes" and trade == {} and datetime.datetime.now().time() >= datetime.time(15, 15):
        print(f"🚫 {key}  | {user['user']} {SERVER} | There is no live trade present, No new trades allowed. So Closing the program")
        logging.info(f"🚫{key}  |{user['user']} {SERVER} | There is no live trade present, No new trades allowed. So Closing the program")
        send_telegram_message(f"🕒 {key}  | {user['user']} {SERVER} | There is no live trade present, No new trades allowed. So Closing the program",user['telegram_chat_id'], user['telegram_token'])
        return True
    return False


def _fetch_historical_data_or_wait(instrument_token, config, key, user):
    logging.info(f"{key} | {user['user']} {SERVER} Inside def _fetch_historical_data_or_wait")
   
    df = get_historical_df(instrument_token, config['INTERVAL'], DAYS, user)
    print(f"🕵️‍♀️{key} | {user['user']} {SERVER} Candles available: {len(df)} / Required: {REQUIRED_CANDLES}")

    if len(df) < REQUIRED_CANDLES:
        print(f"⚠️ {key}  | {user['user']} {SERVER} Not enough candles. Waiting...")
        logging.warning(f"⚠️ {key}  | {user['user']} {SERVER} Not enough candles. Waiting...")
        time.sleep(60)
        return None
    return df


def _prepare_signal_context(instrument_token, config, key, user):
    logging.info(f"{key} | {user['user']} {SERVER} Inside def _prepare_signal_context")
   
    df = _fetch_historical_data_or_wait(instrument_token, config, key, user)
    if df is None:
        return None

    df = _apply_strategy(df, config['STRATEGY'])
    latest = _pick_latest_signal_row(df)
    ts, close, current_time = _log_signal_snapshot(key, user, config, latest, df)
    return df, latest, ts, close, current_time


def _should_stop_before_new_entry(
    config,
    user,
    new_trade_print_msg,
    new_trade_log_msg,
    monthly_stoploss_print_msg=None,
    monthly_stoploss_log_msg=None
):
    logging.info(f"{user['user']} {SERVER} Inside def _should_stop_before_new_entry")
 
    if config['NEW_TRADE'].lower() == "no":
        print(new_trade_print_msg)
        logging.info(new_trade_log_msg)
        return True

    if check_monthly_stoploss_hit(user, config):
        if monthly_stoploss_print_msg:
            print(monthly_stoploss_print_msg)
        if monthly_stoploss_log_msg:
            logging.info(monthly_stoploss_log_msg)
        return True

    return False


def _print_position_snapshot(key, user, config, trade):
    #logging.info(f"{key} | {user['user']} {SERVER} Inside def _print_position_snapshot")

    if not (trade and "OptionSymbol" in trade):
        return

    current_ltp = get_quotes_with_retry(trade["OptionSymbol"], user)
    entry_ltp = trade["OptionBuyPrice"]
    if current_ltp is None or entry_ltp is None:
        return

    yestime = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    percent_change = round(((current_ltp - entry_ltp) / entry_ltp) * 100, 2)
    print(
        f"{key} | {user['user']} | position at {yestime}: {trade['Signal']} | {trade['OptionSymbol']} | "
        f"Entry LTP: ₹{entry_ltp:.2f} | Current LTP: ₹{current_ltp:.2f} | Chg % {percent_change} | Qty: {trade['qty']}"
    )


def _print_position_snapshot_nh(user, config, trade):
    # logging.info(f"{config['KEY']} | Inside def _print_position_snapshot_nh")

    if not (trade and "OptionSymbol" in trade):
        return

    current_ltp = get_quotes_with_retry(trade["OptionSymbol"], user)
    entry_ltp = trade["OptionBuyPrice"]
    if current_ltp is None or entry_ltp is None:
        return

    yestime = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    percent_change = round(((current_ltp - entry_ltp) / entry_ltp) * 100, 2)
    print(
        f"{user['user']} | {config['STRATEGY']} | {config['INTERVAL']} position at {yestime}: "
        f"{trade['Signal']} | {trade['OptionSymbol']} | Entry LTP: ₹{entry_ltp:.2f} "
        f"| Current LTP: ₹{current_ltp:.2f} | Chg % {percent_change} | Qty: {trade['qty']}"
    )


def _sleep_random_monitor_interval():
    random_number = random.randint(7, 15)
    time.sleep(random_number)


def _find_option_with_retry(search_fn, max_attempts, retry_print_msg, retry_log_msg):
    logging.info(f"{SERVER} Inside def _find_option_with_retry")

    result = (None, None, None, None, None)
    for attempt in range(max_attempts):
        result = search_fn()
        if result and result[0] is not None:
            break
        print(retry_print_msg.format(attempt=attempt + 1))
        logging.info(retry_log_msg.format(attempt=attempt + 1))
        time.sleep(2)
    return result



def _build_signal_entry_trade(
    signal,
    close,
    opt_symbol,
    strike,
    expiry,
    avg_price,
    current_time,
    qty,
    config,
    key,
    hedge_option_symbol,
    hedge_strike,
    hedge_avg_price,
    entry_reason="SIGNAL_GENERATED"
):
    logging.info(f"{key} | {SERVER} Inside def _build_signal_entry_trade")
    return {
        "Signal": signal,
        "SpotEntry": close,
        "OptionSymbol": opt_symbol,
        "Strike": strike,
        "Expiry": expiry,
        "OptionBuyPrice": avg_price,
        "EntryTime": current_time,
        "qty": qty,
        "interval": config['INTERVAL'],
        "real_trade": config['REAL_TRADE'],
        "EntryReason": entry_reason,
        "ExpiryType": config['EXPIRY'],
        "Strategy": config['STRATEGY'],
        "Key": key,
        "hedge_option_symbol": hedge_option_symbol,
        "hedge_strike": hedge_strike,
        "hedge_option_sell_price": hedge_avg_price,
        "hedge_qty": qty if hedge_avg_price > 0 else 0,
        "hedge_entry_time": current_time
    }

def _monitor_nh_position_until_next_candle(
    trade,
    position,
    close,
    ts,
    config,
    user,
    key,
    current_time,
    instruments_df
):
    logging.info(f" {config['KEY']} | INSIDE _monitor_nh_position_until_next_candle")
    logging.info(f"  {config['KEY']} | position : {position} | close : {close}")

    next_candle_time = get_next_candle_time(config['INTERVAL'])
    print('⏳ Waiting until next candle at', next_candle_time.time())
    logging.info(f'⏳ {config["KEY"]} |  Waiting until next candle at {next_candle_time.time()}')
    target_hit = False
    while datetime.datetime.now() < next_candle_time:
        _print_position_snapshot_nh(user, config, trade)

        # --------------------------------
        # INTRADAY EXIT
        # --------------------------------
        now = datetime.datetime.now()

        if now.time().hour == 15 and now.time().minute >= 15 and trade and position:
            config = _refresh_runtime_config(key, instruments_df)
            if config['INTRADAY'] == "yes":
                trade, position = close_position_and_no_new_trade(
                    trade, position, close, ts, config, user, key, reason="Intraday exit current position"
                )

                msg = f"⏰ {key} | {user['user']} {SERVER} |  Intraday exit triggered at 3:15 PM. Stopping further trades for the day."

                print(msg)
                logging.info(msg)

                send_telegram_message(
                    msg,
                    user['telegram_chat_id'],
                    user['telegram_token']
                )

                break

        # --------------------------------
        # TARGET / STOPLOSS MANAGEMENT
        # --------------------------------
        if trade and "OptionSymbol" in trade and "OptionBuyPrice" in trade and target_hit == False:
            current_ltp = get_quotes_with_retry(trade["OptionSymbol"], user)
            entry_ltp = trade["OptionBuyPrice"]

            # STOPLOSS
            if check_trade_stoploss_hit(user, trade, config):
                trade, position = close_position_and_no_new_trade(
                    trade, position, close, ts, config, user, key, reason="Stoploss hit so exiting position"
                )
                break

            # Target completed of 40%. Hence exiting current positions for Rollover.
            if current_ltp and entry_ltp and entry_ltp != 0 and current_ltp <= ROLLOVER_CALC * entry_ltp:
                target_hit = True

                print(f"📥 {key} | {SERVER} | Current {trade['OptionSymbol']} of Qty {trade['qty']} hit the target of 40%. Hence exiting position for Rollover."
                )
                logging.info(f"📥 {key} | {SERVER} | Current {trade['OptionSymbol']} of Qty {trade['qty']} hit the target of 40%. Hence exiting position for Rollover.")

                exit_qty, avg_price, hedge_avg = execute_robust_exit(
                    trade,
                    config,
                    user,
                    expiry_match="DIFF",
                    reason="Target hit so exiting current position."
                )
                logging.info(f"📤{key} | Exited without Hedge position {trade['OptionSymbol']} with Avg price: ₹{avg_price:.2f} | Qty: {exit_qty}" )

                if not is_valid_trade_data(exit_qty, avg_price, hedge_avg, hedge_required=False):
                    err_msg = f"⚠️ {key} | {SERVER} | FAILED EXIT:{trade['OptionSymbol']} of Qty ({exit_qty}) or Price ({avg_price}) is 0. Database NOT updated."
                    logging.error(err_msg)
                    send_telegram_message_admin(err_msg)
                    update_trade_config_on_failure(config['KEY'], err_msg, user)
                    return trade, position, True
                else:
                    trade.update({
                        "SpotExit": close,
                        "ExitTime": current_time,
                        "OptionSellPrice": avg_price,
                        "PnL": avg_price - entry_ltp,
                        "qty": exit_qty,
                        "ExitReason": "TARGET_HIT",
                        "hedge_option_buy_price": hedge_avg,
                        "hedge_exit_time": current_time,
                        "hedge_pnl": hedge_avg - trade.get("hedge_option_sell_price",0),
                        "total_pnl": (avg_price - entry_ltp) +
                                    (hedge_avg - trade.get("hedge_option_sell_price",0))
                    })

                    trade = get_clean_trade(trade)
                    record_trade(trade, config, user['id'])
                    delete_open_position(trade["OptionSymbol"], config, trade, user['id'])

                    send_telegram_message(
                        f"📤 Exit {trade['Signal']}\n"
                        f"Main {trade['OptionSymbol']} @ ₹{avg_price:.2f} | "
                        f"PnL Per Qty ₹{trade['total_pnl']:.2f}",
                        user['telegram_chat_id'],
                        user['telegram_token']
                    )
                    logging.info(f"🔴 {key} | {user['user']} {SERVER} | Target triggered for {trade['OptionSymbol']} at ₹{current_ltp:.2f}")

                    last_expiry = trade["Expiry"]
                    signal = trade["Signal"]

                    trade = {}

                # --------------------------------
                # REENTRY RULES
                # --------------------------------

                if config['NEW_TRADE'].lower() == "no":
                    position = None
                    break

                if check_monthly_stoploss_hit(user, config):
                    break


        _sleep_random_monitor_interval()

    return trade, position, False

def _handle_nh_buy_signal(trade, position, latest, close, current_time, config, user, key, instruments_df, entry_reason="SIGNAL_GENERATED"):
    logging.info(f" {config['KEY']} | INSIDE _handle_nh_buy_signal")
    logging.info(f"  {config['KEY']} | position : {position} | close : {close} | latest :{latest}")
    if entry_reason != "MANUAL_ENTRY":
        if not (latest['buySignal'] and position != "BUY"):
            return trade, position, "none", False

    # Exit without Hedge position and Enter new position on BUY Signal Generation.
    if position == "SELL":
        # EXIT CODE EXECUTION :: START
        existing_qty = int(trade.get("qty", config['QTY']))

        print(f"📥{key} | {user['user']} {SERVER} |  Exit Signal Generated: Buying back {trade['OptionSymbol']}")
        logging.info(f"📥{key} | {user['user']} {SERVER}  | Exit Signal Generated: Buying back {trade['OptionSymbol']}")

        exit_qty, avg_price = execute_robust_exit(
            trade,
            config,
            user,
            expiry_match="DIFF",
            reason="Buy signal generated so exiting current position."
        )
        hedge_avg_price = 0
        print(f"📤{key} | Exited without Hedge position {trade['OptionSymbol']} with Avg price: ₹{avg_price:.2f} | Qty: {exit_qty}" )
        logging.info(f"📤{key} | Exited without Hedge position {trade['OptionSymbol']} with Avg price: ₹{avg_price:.2f} | Qty: {exit_qty}" )

        if not is_valid_trade_data(exit_qty, avg_price, hedge_avg_price, hedge_required=False):
            err_msg = f"⚠️ {key} | {SERVER} | FAILED EXIT:{trade['OptionSymbol']} or {trade['hedge_option_symbol']} of Qty ({exit_qty}) or Price ({avg_price}) is 0. Database NOT updated."
            print(err_msg)
            logging.error(err_msg)
            send_telegram_message_admin(err_msg)
            update_trade_config_on_failure(config['KEY'], err_msg, user)
            return trade, position, "return", True
        else:
            trade.update({
                "OptionSellPrice": avg_price,
                "SpotExit": close,
                "ExitTime": current_time,
                "PnL":  avg_price - trade["OptionBuyPrice"],
                "qty": exit_qty,
                "ExitReason": "SIGNAL_GENERATED",
                "hedge_option_buy_price": hedge_avg_price,
                "hedge_exit_time": current_time,
                "hedge_pnl": (hedge_avg_price - trade.get("hedge_option_sell_price", 0)) if hedge_avg_price > 0 else 0.0,
            })

            trade["total_pnl"] = trade["PnL"] + trade.get("hedge_pnl", 0)

            trade = get_clean_trade(trade)
            record_trade(trade, config, user['id'])
            delete_open_position(trade["OptionSymbol"], config, trade, user['id'])

            send_telegram_message(f"📤 {key} | {user['user']} {SERVER} | Exit Signal Generated: Buy back {trade['OptionSymbol']} @ ₹{avg_price:.2f} \n {trade['hedge_option_symbol']} @ ₹{hedge_avg_price}. Profit/Qty: {trade['total_pnl']:.2f}", user['telegram_chat_id'], user['telegram_token'])
        # EXIT CODE EXECUTION :: END

    if _should_stop_before_new_entry(
        config,
        user,
        f"🚫 {user['user']} | {key} | No new trades allowed. Skipping BUY signal.",
        f"🚫 {user['user']} | {key} | No new trades allowed. Skipping BUY signal.",
        f"🚫 {user['user']} | {key} | Monthly StopLoss hit. No new trades allowed for the rest of the month.",
        f"🚫 {user['user']} | {key} | Monthly StopLoss hit. No new trades allowed for the rest of the month."
    ):
        return trade, position, "break", True

    result = _find_option_with_retry(
        search_fn=lambda: get_robust_optimal_option("BUY", close, instruments_df, config, user),
        max_attempts=3,
        retry_print_msg=f"⚠️{key} | {user['user']} {SERVER} | Search Attempt {{attempt}} failed to find an option within tolerance. Retrying in 2s...",
        retry_log_msg=f"⚠️{key} | {user['user']} {SERVER} | Search Attempt {{attempt}} failed to find an option within tolerance. Retrying in 2s..."
    )

    if not result or result[0] is None:
        print(f"❌{key} | {user['user']} {SERVER} | No suitable option found for BUY signal.")
        logging.error(f"❌{key} | {user['user']} {SERVER} | No suitable option found for BUY signal.")
        send_telegram_message(
            f"❌ {key} | {user['user']} {SERVER} | No suitable option found for BUY signal.",
            user['telegram_chat_id'],
            user['telegram_token']
        )
        return trade, position, "continue", True

    opt_symbol, strike, expiry, ltp = result

    print(f"📤 {key} | {user['user']} | BUY Enter Signal Generated : Selling {opt_symbol} | Strike: {strike} | Expiry: {expiry} | LTP ₹{ltp:.2f}")
    logging.info(f"📤 {key} | {user['user']} | BUY Enter Signal Generated : Selling {opt_symbol} | Strike: {strike} | Expiry: {expiry} | LTP ₹{ltp:.2f}")

    temp_trade_symbols = {
        "OptionSymbol": opt_symbol,
        "hedge_option_symbol": '-'
    }

    new_qty, avg_price = execute_robust_entry(
        temp_trade_symbols,
        config,
        user,
        reason="Buy signal generated"
    )
    hedge_avg_price = 0
    print(f"📤{key} | Entered without Hedge position {opt_symbol} with Avg price: ₹{avg_price:.2f} | Qty: {new_qty}.")
    logging.info(f"📤{key} | Entered without Hedge position {opt_symbol} with Avg price: ₹{avg_price:.2f} | Qty: {new_qty}.")

    if not is_valid_trade_data(new_qty, avg_price, hedge_avg_price, hedge_required=False):
        err_msg = f"⚠️ {key} | {SERVER} | FAILED ENTRY:{opt_symbol} of Qty ({new_qty}) or Price ({avg_price}) is 0. Database NOT updated."
        print(err_msg)
        logging.error(err_msg)
        send_telegram_message_admin(err_msg)
        return trade, position, "break", True
    else:
        trade = _build_signal_entry_trade(
            signal="BUY",
            close=close,
            opt_symbol=opt_symbol,
            strike=strike,
            expiry=expiry,
            avg_price=avg_price,
            current_time=current_time,
            qty=new_qty,
            config=config,
            key=key,
            hedge_option_symbol=temp_trade_symbols["hedge_option_symbol"],
            hedge_strike=0,
            hedge_avg_price=hedge_avg_price,
            entry_reason=entry_reason
        )

        trade = get_clean_trade(trade)
        save_open_position(trade, config, user['id'])

        position = "BUY"
        print(f"✅ {key} | {user['user']} {SERVER} | BUY Entry Signal Executed: Sold {opt_symbol} | Avg Price: ₹{avg_price:.2f} | Qty: {new_qty}")
        logging.info(f"✅ {key} | {user['user']} {SERVER} | BUY Entry Signal Executed: Sold {opt_symbol} | Avg Price: ₹{avg_price:.2f} | Qty: {new_qty}")
        send_telegram_message(
            f"🟢{key} | BUY Entry Signal Generated\n Selling {opt_symbol} | Avg ₹{avg_price:.2f} | Qty: {new_qty}",
            user['telegram_chat_id'],
            user['telegram_token']
        )

        return trade, position, "none", True


def _handle_nh_sell_signal(trade, position, latest, close, current_time, config, user, key, instruments_df, entry_reason="SIGNAL_GENERATED"):
    logging.info(f" {config['KEY']} | INSIDE _handle_nh_sell_signal")
    logging.info(f"  {config['KEY']} | position : {position} | close : {close} | latest :{latest}")
    
    if entry_reason != "MANUAL_ENTRY":
        if not (latest['sellSignal'] and position != "SELL"):
            return trade, position, "none", False

    if position == "BUY":
        existing_qty = int(trade.get("qty", config['QTY']))

        print(f"📥 {key} | {user['user']} {SERVER} | Exit Signal Generated: Buying back {trade['OptionSymbol']} | Qty: {existing_qty}")
        logging.info(f"📥 {key} | {user['user']} {SERVER} | Exit Signal Generated: Buying back {trade['OptionSymbol']} | Qty: {existing_qty}")

        exit_qty, avg_price = execute_robust_exit(
            trade,
            config,
            user,
            expiry_match="DIFF",
            reason="Sell signal generated so exiting current position."
        )
        hedge_avg_price = 0
        logging.info(f"📤{key} | Exited without Hedge position {trade['OptionSymbol']} with Avg price: ₹{avg_price:.2f} | Qty: {exit_qty}" )

        if not is_valid_trade_data(exit_qty, avg_price, hedge_avg_price, hedge_required=False):
            err_msg = f"⚠️ {key} | {SERVER} | FAILED EXIT:{trade['OptionSymbol']} of Qty ({exit_qty}) or Price ({avg_price}) is 0. Database NOT updated."
            logging.error(err_msg)
            send_telegram_message_admin(err_msg)
            update_trade_config_on_failure(config['KEY'], err_msg, user)
            return trade, position, "return", True
        else:
            trade.update({
                "OptionSellPrice": avg_price,
                "SpotExit": close,
                "ExitTime": current_time,
                "PnL":  avg_price - trade["OptionBuyPrice"],
                "qty": exit_qty,
                "ExitReason": "SIGNAL_GENERATED",
                "hedge_option_buy_price": hedge_avg_price,
                "hedge_exit_time": current_time,
                "hedge_pnl": (hedge_avg_price - trade.get("hedge_option_sell_price", 0)) if hedge_avg_price else 0.0
            })

            trade["total_pnl"] = trade["PnL"] + trade.get("hedge_pnl", 0)

            trade = get_clean_trade(trade)
            record_trade(trade, config, user['id'])
            delete_open_position(trade["OptionSymbol"], config, trade, user['id'])

            send_telegram_message(
                f"📤 {user['user']} {SERVER} | {key} |  Exit Signal Generated:\n"
                f" Buying {trade['OptionSymbol']} @ ₹{avg_price:.2f} | Profit/Qty: {trade['total_pnl']:.2f}",
                user['telegram_chat_id'],
                user['telegram_token']
            )

    if _should_stop_before_new_entry(
        config,
        user,
        f"🚫 {key} | {user['user']} | No new trades allowed. Skipping SELL signal.",
        f"🚫 {key} | {user['user']} | No new trades allowed. Skipping SELL signal.",
        f"🚫 {user['user']} | {key} | Monthly StopLoss hit. No new trades allowed for the rest of the month.",
        f"🚫 {user['user']} | {key} | Monthly StopLoss hit. No new trades allowed for the rest of the month."
    ):
        return trade, position, "break", True

    result = _find_option_with_retry(
        search_fn=lambda: get_robust_optimal_option("SELL", close, instruments_df, config, user),
        max_attempts=3,
        retry_print_msg=f"⚠️ {key} | Search Attempt {{attempt}} failed to find an option within tolerance. Retrying in 2s...",
        retry_log_msg=f"⚠️ {key} | Search Attempt {{attempt}} failed to find an option within tolerance. Retrying in 2s..."
    )

    if not result or result[0] is None:
        print(f"❌ {key} | {SERVER} | No suitable option found for SELL signal.")
        logging.error(f"❌ {key} | {SERVER} | No suitable option found for SELL signal.")
        send_telegram_message(
            f"❌ {key} | {user['user']} {SERVER} | No suitable option found for SELL signal.",
            user['telegram_chat_id'],
            user['telegram_token']
        )
        return trade, position, "continue", True

    opt_symbol, strike, expiry, ltp = result
    print(f"📤 {key} | {user['user']} | SELL Enter Signal Generated : Selling {opt_symbol} | Strike: {strike} | Expiry: {expiry} | LTP ₹{ltp:.2f}")
    logging.info(f"📤 {key} | {user['user']} | SELL Enter Signal Generated : Selling {opt_symbol} | Strike: {strike} | Expiry: {expiry} | LTP ₹{ltp:.2f}")

    temp_trade_symbols = {
        "OptionSymbol": opt_symbol,
        "hedge_option_symbol": "-"
    }

    new_qty, avg_price = execute_robust_entry(
        temp_trade_symbols,
        config,
        user,
        reason="Sell signal generated."
    )
    hedge_avg_price = 0
    print(f"📤{key} | Entered without Hedge position {opt_symbol} with Avg price: ₹{avg_price:.2f} | Qty: {new_qty}.")
    logging.info(f"📤{key} | Entered without Hedge position {opt_symbol} with Avg price: ₹{avg_price:.2f} | Qty: {new_qty}.")

    if not is_valid_trade_data(new_qty, avg_price, hedge_avg_price, hedge_required=False):
        err_msg = f"⚠️ {key} | {SERVER} | FAILED ENTRY:{opt_symbol} of Qty ({new_qty}) or Price ({avg_price}) is 0. Database NOT updated."
        print(err_msg)
        logging.error(err_msg)
        send_telegram_message_admin(err_msg)
        return trade, position, "break", True
    else:
        trade = _build_signal_entry_trade(
            signal="SELL",
            close=close,
            opt_symbol=opt_symbol,
            strike=strike,
            expiry=expiry,
            avg_price=avg_price,
            current_time=current_time,
            qty=new_qty,
            config=config,
            key=key,
            hedge_option_symbol=temp_trade_symbols["hedge_option_symbol"],
            hedge_strike=0,
            hedge_avg_price=hedge_avg_price,
            entry_reason=entry_reason
        )

        trade = get_clean_trade(trade)
        save_open_position(trade, config, user['id'])

        position = "SELL"
        send_telegram_message(
            f"🔴{key} | SELL Enter Signal Generated\n"
            f" Sell {opt_symbol} | Avg ₹{avg_price:.2f} | Qty: {new_qty}",
            user['telegram_chat_id'],
            user['telegram_token']
        )
        print(f"🔴{key} | SELL Enter Signal Generated |  Sell {opt_symbol} | Avg ₹{avg_price:.2f} | Qty: {new_qty}")
        logging.info(f"🔴{key} | SELL Enter Signal Generated |  Sell {opt_symbol} | Avg ₹{avg_price:.2f} | Qty: {new_qty}")

        return trade, position, "none", True


def _apply_strategy(df, strategy):
    logging.info(f"{SERVER} Inside def _apply_strategy")
    if strategy == "GOD":
        return generate_god_signals(df)
    if strategy == "HDSTRATEGY":
        return hd_strategy(convertIntoHeikinashi(df))
    if strategy == "RAILWAY_TRACK":
        return railway_track_strategy(df)
    return df


def _pick_latest_signal_row(df):
    logging.info(f"{SERVER} Inside def _pick_latest_signal_row")
    # Use latest candle if it has signal, otherwise fallback to previous candle signal.
    if df.iloc[-1]['buySignal'] or df.iloc[-1]['sellSignal']:
        return df.iloc[-1]
    if df.iloc[-2]['buySignal'] or df.iloc[-2]['sellSignal']:
        return df.iloc[-2]
    return df.iloc[-1]


def _log_signal_snapshot(key, user, config, latest, df):
    logging.info(f"{key} | {user['user']} {SERVER} Inside def _log_signal_snapshot")
    ts = latest['date'].strftime('%Y-%m-%d %H:%M')
    close = latest['close']
    snapshot_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    logging.info(f"🕒{key} | Signal Received at Current Time: {snapshot_time}\n{df.tail(5)}")
    msg = (
        f"{key} | {config['STRATEGY']} | Candle time {ts} | Close: {close} | "
        f"Buy: {latest['buySignal']} | Sell: {latest['sellSignal']} | "
        f"Trend: {latest['trend']} | Current Time: {snapshot_time}"
    )
    logging.info(msg)
    print(msg)
    return ts, close, snapshot_time

def get_instrument_token(symbol,instrument_df):
    instrument_token = get_token_for_symbol(symbol,instrument_df)

    if instrument_token is None:
        logging.error(f"{SERVER} | ❌ Instrument token for {SYMBOL} not found. Exiting.")
        exit(1)
    logging.info(f"{SERVER} | ℹ️ Instrument token for {SYMBOL}: {instrument_token} at current time {current_time}")
    return instrument_token

# ====== Main Live Trading Loconfig['REAL_TRADE']op ======
def live_trading(instruments_df, config, key, user):
    logging.info(f"{key} | {user['user']} {SERVER} Inside def live_trading")

    _log_trade_mode(config, key, user)
    instrument_token = get_instrument_token(symbol = config['TRADABLE_SYMBOL'][0]['trading_symbol'],instrument_df=instruments_df)


    trade, position = _load_trade_state(config, key, user, send_resume_alert=True)
   
    

    while True:
        trade, position = _refresh_trade_state_in_loop(config, key, user)
        Stoplosses = get_stoploss_by_trade_config(key)
   
        try:
            config = _refresh_runtime_config(key, instruments_df)

            if _should_stop_for_no_new_trade(config, trade, key, user):
                break

            market_action = _handle_market_availability(key, user)
            if market_action == "continue":
                continue
            if market_action == "return":
                return

            if _should_stop_for_intraday_cutoff(config, trade, key, user):
                break

            if config['TRADE_BASE_ON'] == "MAIN_SYMBOL":
                
                signal_context = _prepare_signal_context(instrument_token, config, key, user)
                if signal_context is None:
                    continue
                df, latest, ts, close, current_time = signal_context
 
                # NH STRATEGY (No Hedge) - Only execute main leg, skip all hedge logic
                if config['HEDGE_TYPE'] == "NH":
                    
                    trade, position, action, handled = _handle_nh_buy_signal(
                        trade=trade,
                        position=position,
                        latest=latest,
                        close=close,
                        current_time=current_time,
                        config=config,
                        user=user,
                        key=key,
                        instruments_df=instruments_df
                    )
                    if action == "return":
                        return
                    if action == "break":
                        break
                    if action == "continue":
                        continue

                    if not handled:
                        trade, position, action, _ = _handle_nh_sell_signal(
                            trade=trade,
                            position=position,
                            latest=latest,
                            close=close,
                            current_time=current_time,
                            config=config,
                            user=user,
                            key=key,
                            instruments_df=instruments_df
                        )
                        if action == "return":
                            return
                        if action == "break":
                            break
                        if action == "continue":
                            continue
                    trade, position, should_return = _monitor_nh_position_until_next_candle(
                    trade,
                    position,
                    close,
                    ts,
                    config,
                    user,
                    key,
                    current_time,
                    instruments_df
                    )
                    if should_return:
                        return
                    

                
        except ReadTimeout as re:
            # Ignore read timeout
            logging.error(f"⚠️ {user['user']} {SERVER}  |  {key}  | Exception: {re}", exc_info=True)
            send_telegram_message_admin(f"⚠️ {user['user']} {SERVER}  |  {key}  |  {config['INTERVAL']} ReadTimeout Error: {re}")
            pass


        except exceptions.NetworkException:
            # Ignore network exception
            pass

        
        except Exception as e:
            logging.error(f"{user['user']} {SERVER}  | Exception: {e}", exc_info=True)
            # send_telegram_message(f"⚠️ {user['user']} {SERVER}  |  {key}  |  {config['INTERVAL']} Error: {e}",user['telegram_chat_id'], user['telegram_token'])
            send_telegram_message_admin(f"⚠️ {user['user']} {SERVER}  |  {key}  |  {config['INTERVAL']} Error: {e}")
            time.sleep(60)



# ====== Run ======
def init_and_run(user):
    while True:
        try:
            who_tried(user)
            
            
            threads = []

            print("*"*60)
            configs = get_trade_configs(user['id'])
            
            print(configs)
            print("*"*60)
            keys = configs.keys()
            
            for key in keys:
                config = configs[key]
                tradable_symbol = config['TRADABLE_SYMBOL'][0]['trading_symbol']
                file = get_tradable_symbols_and_save_filtered(tradable_symbol)
                if file is None:
                    logging.error(f"❌ {user['user']} {SERVER} | No instruments file found for {tradable_symbol}. Skipping this config.")
                    continue
                INSTRUMENTS_FILE = PATH + file
                instruments_df = pd.read_csv(INSTRUMENTS_FILE)
                init_db()
                # print(f"PPP {key} | {user['user']} {SERVER} {instrument_token} {config} | Fetching data and preparing signal context...")
                
                t = threading.Thread(target=live_trading, args=(instruments_df, config, key, user))
                t.start()
                threads.append(t)
            for t in threads:
                t.join()
            break
        except Exception as e:
            logging.error(f"{SERVER} | Fatal error: {e}")
            logging.error(f"{SERVER} | Restarting emalive in 10 seconds...")
            time.sleep(10)


def execute_robust_entry(trade, config, user, reason="Nothing"):
    """
    SINGLE-SHOT ENTRY:
    Executes Hedge and Main Leg with mismatch recovery logic.
    """
    logging.info(f" {config['KEY']} | INSIDE execute_robust_entry")
    logging.info(f"  {config['KEY']} | Trying to execute trade : {trade}  | reason : {reason}")

    target_qty = int(config.get('QTY', 0))
    if config['REAL_TRADE'] != "yes":
        print(f"⚠️ {config['KEY']} | Real Trade is set to NO. Skipping actual order placement for {trade['OptionSymbol']}. Returning target qty: {target_qty} and price 0.")
        logging.info(f"⚠️ {config['KEY']} | Real Trade is set to NO. Skipping actual order placement for {trade['OptionSymbol']}. Returning target qty: {target_qty} and price 0.")
        final_m_avg = get_quotes_with_retry(trade["OptionSymbol"], user)
        return target_qty, final_m_avg
    
    skip_hedge = True

    main_filled_total = 0
    main_total_val = 0.0
    hedge_filled_total = 0
    hedge_total_val = 0.0

    print(f"🚀{config['KEY']} |  Starting execute_robust_entry for {user['user']} | {trade['OptionSymbol']} | Target Qty: {target_qty} | Skip Hedge: {skip_hedge}")
    logging.info(f"🚀{config['KEY']} |  Starting execute_robust_entry for {user['user']} | {trade['OptionSymbol']} | Target Qty: {target_qty} | Skip Hedge: {skip_hedge}")
    
    # PRE-TRADE PRICE VALIDATION
    if not validate_trade_prices(trade["OptionSymbol"], trade["hedge_option_symbol"], config, user):
        logging.warning(f"🛑 {config['KEY']} |  ENTRY ABORTED: Price validation failed for {user['user']} | {trade['OptionSymbol']}")
        print(f"🛑 {config['KEY']} |  ENTRY ABORTED: Price validation failed for {user['user']} | {trade['OptionSymbol']}")
        return 0, 0
    
    if skip_hedge:
        print(f"⚡{config['KEY']} | Placing Main BUY order for {trade['OptionSymbol']} | Target Qty: {target_qty}")
        logging.info(f"⚡{config['KEY']} | Placing Main BUY order for {trade['OptionSymbol']} | Target Qty: {target_qty}")
        m_id, m_avg, m_f = place_robust_limit_order(trade["OptionSymbol"], target_qty, "BUY", config, user, action="ENTRY")
        if m_f > 0:
            main_total_val = (m_avg * m_f)
            main_filled_total = m_f
    else:
        print(f" {config['KEY']} |  Not Enable yet for Hedged")
        logging.info(f" {config['KEY']} |  Not Enable yet for Hedged")
    

    final_m_avg = main_total_val / main_filled_total if main_filled_total > 0 else 0

    
    logging.info(f"🏁 ENTRY SUMMARY | Main: {main_filled_total} @ {round(final_m_avg, 2)}")
    return main_filled_total, final_m_avg


def execute_robust_exit(trade, config, user, expiry_match="DIFF", reason="Nothing"):
    """
    SINGLE-SHOT STRICT EXIT:
    - Removes 3-attempt loop; relies on 5s robust price chasing.
    - If Main exits and Hedge fails (or vice versa), triggers KILL THREAD.
    """
    print(f"🚪 {config['KEY']} | Starting EXIT of Symbol {trade['OptionSymbol']}")
    logging.info(f"🚪 {config['KEY']} | Starting EXIT of Symbol {trade['OptionSymbol']} | Reason : {reason}")
    target_qty_new = int(config.get('QTY', 0))
    existing_qty = int(trade.get('qty', 0))
    qty_changed = (target_qty_new != existing_qty)

    if config['REAL_TRADE'] != "yes":
        print(f"⚠️ {config['KEY']} | Real Trade is set to NO. Skipping actual order placement for {trade['OptionSymbol']}. Returning target qty: {existing_qty} and price Ltp.")
        logging.info(f"⚠️ {config['KEY']} | Real Trade is set to NO. Skipping actual order placement for {trade['OptionSymbol']}. Returning target qty: {existing_qty} and price Ltp.")
        final_m_avg = get_quotes_with_retry(trade["OptionSymbol"], user)
        return existing_qty, final_m_avg

    # --- EXIT GATEKEEPER ---
    skip_hedge = True 

    
    main_filled_total = 0
    main_total_val = 0.0


    print(f"🚪 {config['KEY']} | Starting EXIT | Target Qty: {existing_qty} ")
    logging.info(f"🚪 {config['KEY']} | Starting EXIT | Target Qty: {existing_qty} ")

    # 1. Main Leg Leads (BUY to exit a SELL position)
    m_id, m_avg, m_f = place_robust_limit_order(
        trade["OptionSymbol"], existing_qty, "BUY", config, user, action="EXIT"
    )
    print(f"Main exit {config['KEY']} M :{trade['OptionSymbol']} M_orderid {m_id},m_avg {m_avg},m_f {m_f} ")
    logging.info(f"Main exit {config['KEY']} M :{trade['OptionSymbol']} OrderId{m_id},{m_avg},{m_f}")
    if m_f > 0:
        print(f"🚪 {config['KEY']} | Main EXIT filled {m_f}/{existing_qty} for {trade['OptionSymbol']} at Avg ₹{m_avg:.2f}.")
        logging.info(f"🚪 {config['KEY']} | Main EXIT filled {m_f}/{existing_qty} for {trade['OptionSymbol']} at Avg ₹{m_avg:.2f}.")

        main_total_val = (m_avg * m_f)
        main_filled_total = m_f
        
        
    # --- RECONCILIATION & KILL SWITCH ---
    # Case A: Hedge mismatch (Main filled 100, Hedge filled 50)
    print(f"🚪 {config['KEY']} | Main {trade['OptionSymbol']} filled {main_filled_total} ")
    logging.info(f"🚪 {config['KEY']} | Main {trade['OptionSymbol']} filled {main_filled_total}  ")
    

    # Case B: Incomplete exit (Target was 100, but only 80 filled)
    incomplete = (main_filled_total < existing_qty)

    if  incomplete:
        reason = f"EXIT FAILURE: M:{main_filled_total} vs Target:{existing_qty}"
        update_trade_config_on_failure(config['KEY'], reason, user)
        print(f"☢️ {user['user']} | THREAD KILLED: {reason}")
        logging.critical(f"☢️ {user['user']} | THREAD KILLED: {reason}")
        # Give some time for logs to flush before exiting
        time.sleep(5)
        sys.exit(reason)

    final_m_avg = main_total_val / main_filled_total
    
    print(f"🏁 EXIT Complete | Main: {main_filled_total} @ ₹{round(final_m_avg, 2)} ")
    logging.info(f"🏁 EXIT Complete | Main: {main_filled_total} @ ₹{round(final_m_avg, 2)}")
    return main_filled_total, final_m_avg
