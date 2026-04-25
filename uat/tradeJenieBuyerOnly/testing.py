from datetime import timedelta

import pandas as pd

from commonFunction import get_keywise_trade_config, get_monthly_strategy_total_pnl, get_robust_optimal_option, get_trade_configs
from config import OPTION_SYMBOL, PATH, SEGMENT

from crud import get_stoploss_by_trade_config
from kitefunction import get_exchange, get_quotes_with_retry
from tradeJenie import _refresh_trade_state_in_loop
from updateinstrument import get_tradable_symbols_and_save_filtered
from userdtls import get_all_active_user


# # configs = get_trade_configs(user['id'])
# # print(f"Configs for user {user['user']}: {configs}")

# print(f"Using config: {config}")
# tradable_symbol = config['TRADABLE_SYMBOL'][0]['trading_symbol']
# file = get_tradable_symbols_and_save_filtered(tradable_symbol)
# if file is None:
#     print("Failed to get tradable symbols. Exiting.")
# INSTRUMENTS_FILE = PATH + file
# print(f"Using instruments file: {INSTRUMENTS_FILE}")
# instruments_df = pd.read_csv(INSTRUMENTS_FILE)


# signal = "SELL"
# spot = 54086
# best_option = get_robust_optimal_option(signal, spot, instruments_df, config, user)
# print(f"Best option for signal {signal} at spot {spot}: {best_option}")



def check_trade_stoploss_hit(user, trade, config):
    Stoplosses = get_stoploss_by_trade_config(config['KEY'])
    if Stoplosses is None or len(Stoplosses) == 0:
        print(f"ℹ️ {config['KEY']} | No Stoplosses found for trade check.")
        return False

    trade_sls = [sl for sl in Stoplosses if sl['SCOPE'] == 'PER_TRADE']
    if not trade_sls:
        print(f"ℹ️ {config['KEY']} | No PER_TRADE Stoplosses found.")
        return False

    print(f"ℹ️ Checking TRADE_STOPLOSS for {config['KEY']} interval on trade {trade['OptionSymbol']}")
    current_ltp = get_quotes_with_retry(trade["OptionSymbol"], user)
    entry_ltp = trade["OptionBuyPrice"]
    total_pnl = None
    
    if config['HEDGE_TYPE'] != "NH":
        hedge_current_ltp = get_quotes_with_retry(trade["hedge_option_symbol"], user)
        hedge_entry_ltp = trade["hedge_option_sell_price"]
        if hedge_current_ltp is not None and hedge_entry_ltp is not None and current_ltp is not None and entry_ltp is not None:
            total_pnl = (current_ltp - entry_ltp) + (hedge_current_ltp - hedge_entry_ltp)
    else:
        if current_ltp is not None and entry_ltp is not None:
            total_pnl = (current_ltp - entry_ltp)
            
    if total_pnl is None:
        return False
    
    total_pnl = total_pnl * trade.get("qty", 65)

    # Check all stoploss entries - return True if any is hit
    for sl in trade_sls:
        trade_stopLoss = None
        
        if sl['SL_TYPE'] == 'STATIC':
            trade_stopLoss = sl['SL_VALUE']
        elif sl['SL_TYPE'] == 'PERCENTAGE':
            stopLoss_percentage = sl['SL_VALUE']
            total_buy_price = trade["OptionBuyPrice"] * trade.get("qty", config['QTY'])
            trade_stopLoss = (stopLoss_percentage / 100) * total_buy_price

        if trade_stopLoss is not None and total_pnl <= -abs(trade_stopLoss):
            print(f"🚫 {config['KEY']} | TRADE_STOPLOSS limit reached for {trade['OptionSymbol']} ({total_pnl} <= -{trade_stopLoss}). Closing position.")
            return True

    print(f"✅ {config['KEY']} | TRADE_STOPLOSS limits not reached for {trade['OptionSymbol']} (PnL: {total_pnl}).")
    return False

def check_monthly_stoploss_hit(user, config):
    Stoplosses = get_stoploss_by_trade_config(config['KEY'])
    
    if Stoplosses is None or len(Stoplosses) == 0:
        print(f"ℹ️ {config['KEY']} | No Stoplosses found for monthly check.")
        return False

    monthly_sls = [sl for sl in Stoplosses if sl['SCOPE'] == 'MONTHLY']
    if not monthly_sls:
        print(f"ℹ️ {config['KEY']} | No MONTHLY Stoplosses found.")
        return False

    if not config['ACTIVATE_MONTHLY_SL']:
        print(f"ℹ️ {config['KEY']} | {user['user']} | MONTHLY_STOPLOSS not activated.")
        return False

    total_pnl = get_monthly_strategy_total_pnl(user, config)
    
    # Check all monthly stoploss entries - return True if any is hit
    for sl in monthly_sls:
        monthly_stopLoss = None
        
        if sl['SL_TYPE'] == 'STATIC':
            monthly_stopLoss = sl['SL_VALUE']
        # elif sl['SL_TYPE'] == 'PERCENTAGE':
        #     # For monthly stoploss, percentage could be based on total monthly capital/profit
        #     stopLoss_percentage = sl['SL_VALUE']
        #     monthly_stopLoss = (stopLoss_percentage / 100) * abs(total_pnl) if total_pnl else 0

        if monthly_stopLoss is not None and total_pnl <= -abs(monthly_stopLoss):
            print(f"🚫 {config['KEY']} | {user['user']} | MONTHLY_STOPLOSS limit reached ({total_pnl} <= -{monthly_stopLoss}). No new trades allowed. Skipping till next month.")
            return True

    print(f"✅ {config['KEY']} | {user['user']} | MONTHLY_STOPLOSS limits not reached (PnL: {total_pnl}).")
    return False


if __name__ == "__main__":
    try:
        # Example usage
        print("Testing the functions...")
        user = get_all_active_user()[0]
        print(f"Using user: {user})")
        key = "HDK_NIFTY_RLY_NH_H01_W"
        config = get_keywise_trade_config(key)
        trade, position = _refresh_trade_state_in_loop(config, key, user)
        Stoploss_hit = check_trade_stoploss_hit(user, trade, config)
        print(f"Stop-loss hit for key {key}: {Stoploss_hit}")
        monthly_sl_hit = check_monthly_stoploss_hit(user, config)
        print(f"Monthly stop-loss hit for key {key}: {monthly_sl_hit}")

    except Exception as e:
        print(f"❌ Failed: {e}")
