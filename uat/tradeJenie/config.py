# config.py
SYMBOL = "NIFTY 50"
OPTION_SYMBOL = "NIFTY"
CANDLE_DAYS = 11
REQUIRED_CANDLES = 20
SEGMENT = "NFO-OPT"

ACCESS_TOKEN_FILE = "access_token.json"
INSTRUMENTS_FILE = "nifty_instruments.csv"

LOG_FILE = "live_trading.log"
DB_FILE = "Trading.db"

#SERVER = "LOCAL - HEDGE"
SERVER = "GCP - UAT"  # PROD or TEST

HEDGE_NEAREST_LTP = 10  # Nearest strike price for hedge option
HEDGE_STRIKE_DIFF = 100  # Nearest strike price for hedge option
