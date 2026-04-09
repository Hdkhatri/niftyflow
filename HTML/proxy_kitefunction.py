#proxy_kitefunction.py
import datetime

from flask import Blueprint, request, jsonify
import sys
import logging
from getkite import get_or_login_user
import htmlconfig
from kiteconnect import KiteConnect
import time

# Create Blueprint
proxy_bp = Blueprint("proxy_bp", __name__)

# Ensure path for imports
if htmlconfig.PATH not in sys.path:
    sys.path.append(htmlconfig.PATH)

from userdtls import get_all_active_user
import sqlite3


# 🔧 Setup logging (optional but recommended)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

default_user = None
default_user_id = 2

def get_default_user():
    global default_user
    if default_user is None:
        default_user = get_or_login_user(default_user_id)
        if not default_user:
            logging.info(f"👉User not found in Database")
        else:
            logging.info(f"default_user : {default_user}")
    return default_user


# ✅ Get Kite client safely
def get_kite_client(user):
    try:
        # Fetch token data from kite_session table
        conn = sqlite3.connect(htmlconfig.DB_PATH)
        c = conn.cursor()
        c.execute("""
            SELECT access_token, api_key, api_secret 
            FROM kite_session 
            WHERE user_id = ?
        """, (user['id'],))
        row = c.fetchone()
        conn.close()
        
        if not row:
            print(f"❌ No session found for user_id: {user['id']}")
            logging.error(f"No session found for user_id: {user['id']}")
            return None
        
        access_token, api_key, api_secret = row
        kite = KiteConnect(api_key=api_key)
        kite.set_access_token(access_token)
        return kite
    except Exception as e:
        print("❌ Could not load access token:", e)
        logging.error(f"Error loading access token: {e}")
        return None

def get_kite_client_status(user):
    try:
        kite = get_kite_client(user)

        if kite is None:
            return {
                "status": "error",
                "message": "Kite client not available"
            }

        # Try a lightweight call to verify session
        profile = kite.profile()

        return {
            "status": "success",
            "user_id": profile.get("user_id"),
            "user_name": profile.get("user_name")
        }

    except Exception as e:
        logging.error(f"🔥 Kite status error: {e}")
        return {
            "status": "error",
            "message": str(e),
            "type": type(e).__name__
        }

# 🔁 Core function (runs ONLY on static IP)
def get_entire_quote(symbol, user):
    try:
        logging.info(f"👉 Request for symbol: {symbol} for user {get_default_user()}")

        kite = get_kite_client(get_default_user())

        if kite is None:
            return {
                "error": "Kite client not available",
                "type": "KiteInitError"
            }

        full_symbol = f"NFO:{symbol}"
        logging.info(f"👉 Full symbol: {full_symbol}")

        quote = kite.quote([full_symbol])

        if full_symbol not in quote:
            return {
                "error": f"Symbol not found: {full_symbol}",
                "type": "InvalidSymbol"
            }

        logging.info("✅ Quote fetched successfully")

        return quote[full_symbol]

    except Exception as e:
        logging.error(f"🔥 ERROR in get_entire_quote: {e}")

        return {
            "error": str(e),
            "type": type(e).__name__
        }

def get_profile_data(user):
    try:
        logging.info(f"👉 Fetching profile for user {user}")

        kite = get_kite_client(user)

        if kite is None:
            return {"error": "Kite client not available"}

        profile = kite.profile()

        return {
            "user_name": profile.get("user_name"),
            "user_id": profile.get("user_id"),
            "email": profile.get("email")
        }

    except Exception as e:
        logging.error(f"🔥 Profile error: {e}")
        return {"error": str(e)}


def get_ltp(symbol, user):
    try:
        logging.info(f"👉 Fetching LTP for {symbol}")
        kite = get_kite_client(get_default_user())

        if kite is None:
            return {"error": "Kite client not available"}

        full_symbol = f"NFO:{symbol}"
        quote = kite.ltp([full_symbol])

        if full_symbol not in quote:
            return {"error": f"Invalid symbol: {full_symbol}"}

        ltp = quote[full_symbol].get("last_price", 0)
        return {"ltp": ltp}

    except Exception as e:
        logging.error(f"🔥 LTP error: {e}")
        return {"error": str(e)}
    

def get_historical_data_core(instrument_token, interval, days, user):
    try:
        logging.info(f"👉 Fetching historical for token {instrument_token}")

        kite = get_kite_client(get_default_user())

        if kite is None:
            return {"error": "Kite client not available"}

        now = datetime.datetime.now()
        from_date = (now - datetime.timedelta(days=days)).strftime('%Y-%m-%d')
        to_date = now.strftime('%Y-%m-%d')

        data = kite.historical_data(
            instrument_token,
            from_date,
            to_date,
            interval
        )

        if not data:
            return {"error": "No historical data found"}

        return {"data": data}  # list of dicts

    except Exception as e:
        logging.error(f"🔥 Historical error: {e}")
        return {"error": str(e)}

def get_ltp_with_retry(symbol, user, retries=3, delay=1):
    try:
        for attempt in range(retries):
            result = get_ltp(symbol, user)

            if "error" not in result and result["ltp"] > 0:
                return result

            logging.warning(
                f"{user.get('user')} | Attempt {attempt+1}: Failed for {symbol}"
            )

            time.sleep(delay)

        return {"error": "Failed after retries"}

    except Exception as e:
        logging.error(f"🔥 Retry LTP error: {e}")
        return {"error": str(e)}
    

def get_historical_order_core(order_id, user):
    try:
        logging.info(f"👉 Fetching order history for {order_id}")

        kite = get_kite_client(user)

        if kite is None:
            return {"error": "Kite client not available"}

        orders = kite.order_history(order_id)

        if not orders:
            logging.warning(f"⚠️ No order history for {order_id}")
            return {"data": []}

        order_details = []

        for order in orders:
            order_details.append({
                "order_id": order.get("order_id", ""),
                "tradingsymbol": order.get("tradingsymbol", ""),
                "transaction_type": order.get("transaction_type", ""),
                "quantity": order.get("quantity", 0),
                "status": order.get("status", ""),
                "average_price": order.get("average_price", 0.0),
                "placed_at": order.get("order_timestamp", "")
            })

        return {"data": order_details}

    except Exception as e:
        logging.error(f"🔥 Order history error: {e}")
        return {"error": str(e)}


def get_symbol_quote_core(symbol, user):
    try:
        logging.info(f"👉 Fetching raw quote for {symbol}")

        kite = get_kite_client(get_default_user())

        if kite is None:
            return {"error": "Kite client not available"}

        quote = kite.quote([symbol])

        if not quote:
            return {"error": f"No data returned for {symbol}"}

        return {"data": quote}

    except Exception as e:
        logging.error(f"🔥 Symbol quote error: {e}")
        return {"error": str(e)}

# 🌐 API Route
@proxy_bp.route("/get-entire-quote", methods=["POST"])
def get_entire_quote():
    try:
        # 🔐 API key validation
        api_key = request.headers.get("x-api-key")

        if api_key != htmlconfig.API_KEY:
            return jsonify({"error": "Unauthorized"}), 401

        # 📥 Get request body
        data = request.get_json()

        if not data:
            return jsonify({"error": "Invalid JSON body"}), 400

        symbol = data.get("symbol")
        user = data.get("user")

        logging.info(f"👉 Incoming request: {data}")

        # ✅ Validation
        if not symbol:
            return jsonify({"error": "Missing symbol"}), 400

        if not user:
            return jsonify({"error": "Missing user"}), 400

        # 🔁 Call core function
        result = get_entire_quote(symbol, user)

        # ❌ If error returned
        if isinstance(result, dict) and "error" in result:
            return jsonify(result), 500

        # ✅ Success
        return jsonify({"data": result})

    except Exception as e:
        logging.exception("🔥 Unhandled server error")

        return jsonify({
            "error": str(e),
            "type": type(e).__name__
        }), 500
    

def get_avgprice_from_positions_core(tradingsymbol, user):
    try:
        logging.info(f"👉 Fetching position for {tradingsymbol}")

        kite = get_kite_client(user)

        if kite is None:
            return {"error": "Kite client not available"}

        positions = kite.positions().get("net", [])

        for pos in positions:
            if pos.get("tradingsymbol") == tradingsymbol:

                avg_price = pos.get("average_price", 0.0)
                qty = pos.get("quantity", 0)

                if qty < 0:
                    logging.info(f"🔃 SELL position for {tradingsymbol}, qty {qty}")
                    qty = abs(qty)
                else:
                    logging.info(f"📥 BUY position for {tradingsymbol}, qty {qty}")

                return {
                    "avg_price": avg_price,
                    "qty": qty
                }

        return {"error": f"No position found for {tradingsymbol}"}

    except Exception as e:
        logging.error(f"🔥 Position error: {e}")
        return {"error": str(e)}
    

@proxy_bp.route("/get-profile", methods=["POST"])
def get_profile_route():
    try:
        # 🔐 API key check
        if request.headers.get("x-api-key") != htmlconfig.API_KEY:
            return jsonify({"error": "Unauthorized"}), 401

        data = request.get_json()

        if not data:
            return jsonify({"error": "Invalid JSON"}), 400

        user = data.get("user")

        if not user:
            return jsonify({"error": "Missing user"}), 400

        result = get_profile_data(user)

        if "error" in result:
            return jsonify(result), 500

        return jsonify({"data": result})

    except Exception as e:
        logging.exception("🔥 Profile API crash")
        return jsonify({"error": str(e)}), 500
    
@proxy_bp.route("/get-ltp", methods=["POST"])
def get_ltp_route():
    try:
        if request.headers.get("x-api-key") != htmlconfig.API_KEY:
            return jsonify({"error": "Unauthorized"}), 401

        data = request.get_json()

        symbol = data.get("symbol")
        user = data.get("user")

        if not symbol:
            return jsonify({"error": "Missing symbol"}), 400

        result = get_ltp(symbol, user)

        if "error" in result:
            return jsonify(result), 500

        return jsonify({"data": result})

    except Exception as e:
        logging.exception("🔥 LTP API crash")
        return jsonify({"error": str(e)}), 500
    
@proxy_bp.route("/get-ltp-retry", methods=["POST"])
def get_ltp_retry_route():
    try:
        if request.headers.get("x-api-key") != htmlconfig.API_KEY:
            return jsonify({"error": "Unauthorized"}), 401

        data = request.get_json()

        symbol = data.get("symbol")
        user = data.get("user")
        retries = data.get("retries", 3)
        delay = data.get("delay", 1)

        if not symbol:
            return jsonify({"error": "Missing symbol"}), 400

        result = get_ltp_with_retry(symbol, user, retries, delay)

        if "error" in result:
            return jsonify(result), 500

        return jsonify({"data": result})

    except Exception as e:
        logging.exception("🔥 LTP Retry API crash")
        return jsonify({"error": str(e)}), 500
    

@proxy_bp.route("/get-position-avgprice", methods=["POST"])
def get_position_avgprice_route():
    try:
        if request.headers.get("x-api-key") != htmlconfig.API_KEY:
            return jsonify({"error": "Unauthorized"}), 401

        data = request.get_json()

        if not data:
            return jsonify({"error": "Invalid JSON"}), 400

        tradingsymbol = data.get("tradingsymbol")
        user = data.get("user")

        if not tradingsymbol:
            return jsonify({"error": "Missing tradingsymbol"}), 400

        result = get_avgprice_from_positions_core(tradingsymbol, user)

        if "error" in result:
            return jsonify(result), 500

        return jsonify({"data": result})

    except Exception as e:
        logging.exception("🔥 Position API crash")
        return jsonify({"error": str(e)}), 500
    

@proxy_bp.route("/get-historical", methods=["POST"])
def get_historical_route():
    try:
        if request.headers.get("x-api-key") != htmlconfig.API_KEY:
            return jsonify({"error": "Unauthorized"}), 401

        data = request.get_json()

        if not data:
            return jsonify({"error": "Invalid JSON"}), 400

        instrument_token = data.get("instrument_token")
        interval = data.get("interval")
        days = data.get("days", 1)
        user = data.get("user")

        if not instrument_token:
            return jsonify({"error": "Missing instrument_token"}), 400

        if not interval:
            return jsonify({"error": "Missing interval"}), 400

        result = get_historical_data_core(
            instrument_token,
            interval,
            days,
            user
        )

        if "error" in result:
            return jsonify(result), 500

        return jsonify(result)

    except Exception as e:
        logging.exception("🔥 Historical API crash")
        return jsonify({"error": str(e)}), 500
    

@proxy_bp.route("/get-order-history", methods=["POST"])
def get_order_history_route():
    try:
        # 🔐 API key check
        if request.headers.get("x-api-key") != htmlconfig.API_KEY:
            return jsonify({"error": "Unauthorized"}), 401

        data = request.get_json()

        if not data:
            return jsonify({"error": "Invalid JSON"}), 400

        order_id = data.get("order_id")
        user = data.get("user")

        if not order_id:
            return jsonify({"error": "Missing order_id"}), 400

        result = get_historical_order_core(order_id, user)

        if "error" in result:
            return jsonify(result), 500

        return jsonify(result)

    except Exception as e:
        logging.exception("🔥 Order history API crash")
        return jsonify({"error": str(e)}), 500
    

@proxy_bp.route("/get-kite-client", methods=["POST"])
def kite_status_route():
    try:
        # 🔐 API key check
        if request.headers.get("x-api-key") != htmlconfig.API_KEY:
            return jsonify({"error": "Unauthorized"}), 401

        data = request.get_json()

        if not data:
            return jsonify({"error": "Invalid JSON"}), 400

        user = data.get("user")

        if not user:
            return jsonify({"error": "Missing user"}), 400

        result = get_kite_client_status(user)

        if result.get("status") == "error":
            return jsonify(result), 500

        return jsonify(result)

    except Exception as e:
        logging.exception("🔥 Kite status API crash")
        return jsonify({"error": str(e)}), 500
    

@proxy_bp.route("/get-symbol-quote", methods=["POST"])
def get_symbol_quote_route():
    try:
        if request.headers.get("x-api-key") != htmlconfig.API_KEY:
            return jsonify({"error": "Unauthorized"}), 401

        data = request.get_json()

        if not data:
            return jsonify({"error": "Invalid JSON"}), 400

        symbol = data.get("symbol")
        user = data.get("user")

        if not symbol:
            return jsonify({"error": "Missing symbol"}), 400

        result = get_symbol_quote_core(symbol, user)

        if "error" in result:
            return jsonify(result), 500

        return jsonify(result)

    except Exception as e:
        logging.exception("🔥 Symbol quote API crash")
        return jsonify({"error": str(e)}), 500