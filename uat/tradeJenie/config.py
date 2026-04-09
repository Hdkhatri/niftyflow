# config.py
from datetime import datetime
import os

SYMBOL = "NIFTY 50"
OPTION_SYMBOL = "NIFTY"
CANDLE_DAYS = 11
REQUIRED_CANDLES = 20
SEGMENT = "NFO-OPT"

#UAT
PATH = "/home/harshilkhatri2808/uat/tradeJenie/"
#PROD
# PATH = "/home/harshilkhatri2808/prod/tradeJenie/"
#Local
# PATH = "C:/Users/Hdkhatri/Desktop/ALGOTRADE/GCP/backup/2026_04_06/uat/tradeJenie - working copy/"



ACCESS_TOKEN_FILE = "access_token.json"
INSTRUMENTS_FILE = PATH + "nifty_instruments.csv"


TODAY_DATE = datetime.now().strftime("%Y-%m-%d")
LOG_FILE = PATH + f"log/live_trading_{TODAY_DATE}.log"
DB_FILE = PATH + "Trading.db"

os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

#SERVER = "LOCAL - HEDGE"
SERVER = "GCP - UAT"  # PROD or TEST

HEDGE_NEAREST_LTP = 10  # Nearest strike price for hedge option
HEDGE_STRIKE_DIFF = 100  # Nearest strike price for hedge option

ROLLOVER_AT_PERCENT = 20  # Roll over when current option's premium is less than this percentage of the initial premium
ROLLOVER_CALC = (100 - ROLLOVER_AT_PERCENT)/100  # 0.6, i.e., 60% of the initial premium 
HARDLIMIT = 30  # Previous HL is 25   ::::: Absolute LTP difference for finding OPTIMAL OPTION   e.g. if nearest_price is 100, we want an option with LTP between 75 and 125. If no option is found in this range, we skip the trade. This prevents taking trades with very high premium difference which may not be ideal for our strategy.                                                                                                                        
