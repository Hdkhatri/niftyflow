import os
import sqlite3
from config import DB_FILE

def init_db():
    try:
        # Connect to SQLite database (will create file if it doesn't exist)
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute(""" 
            CREATE TABLE IF NOT EXISTS tradable_symbols (
                "symbols_pk"	INTEGER PRIMARY KEY AUTOINCREMENT,
                "symbol_name"	TEXT NOT NULL,
                "trading_symbol"	TEXT NOT NULL,
                "segment"	TEXT NOT NULL,
                "exchange"	TEXT NOT NULL,
                "tradable_flag"	TEXT DEFAULT 'true',
                PRIMARY KEY("symbols_pk")
            )
        """)

        # Create completed_trades table
        c.execute("""
            CREATE TABLE IF NOT EXISTS completed_trades (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                signal TEXT,
                spot_entry REAL,
                option_symbol TEXT,
                strike INTEGER,
                expiry TEXT,
                option_sell_price REAL,
                entry_time TEXT,
                spot_exit REAL,
                option_buy_price REAL,
                exit_time TEXT,
                pnl REAL,
                qty INTEGER,
                interval TEXT,
                real_trade TEXT,
                entry_reason TEXT,
                exit_reason TEXT,
                expiry_type TEXT,
                strategy TEXT,
                key TEXT,
                user_id INTEGER,
                hedge_option_symbol TEXT,
                hedge_strike INTEGER,
                hedge_option_buy_price REAL,
                hedge_qty INTEGER,
                hedge_entry_time TEXT,
                hedge_exit_time TEXT,
                hedge_option_sell_price REAL,
                hedge_pnl REAL,
                total_pnl REAL
                
            )
        """)

        # Create open_trades table
        c.execute("""
            CREATE TABLE IF NOT EXISTS open_trades (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                signal TEXT,
                spot_entry REAL,
                option_symbol TEXT,
                strike INTEGER,
                expiry TEXT,
                option_sell_price REAL,
                entry_time TEXT,
                qty INTEGER,
                interval TEXT,
                real_trade TEXT,
                entry_reason TEXT,
                expiry_type TEXT,
                strategy TEXT,
                key TEXT,
                user_id INTEGER,
                hedge_option_symbol TEXT,
                hedge_strike INTEGER,
                hedge_option_buy_price REAL,
                hedge_qty INTEGER,
                hedge_entry_time TEXT,
                trade_status TEXT
            )
        """)

        # Create user_dtls table
        c.execute("""
            CREATE TABLE IF NOT EXISTS user_dtls (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user TEXT,
                kite_username TEXT,
                kite_password TEXT,
                kite_api_secret TEXT,
                kite_api_key TEXT,
                kite_totp_token TEXT,
                telegram_chat_id TEXT,
                telegram_token TEXT,
                active_flag INTEGER,
                crt_dt TEXT,
                user_type TEXT DEFAULT 'CLIENT',
                use_default_user TEXT NOT NULL DEFAULT 'no',
                PRIMARY KEY("id" AUTOINCREMENT)
            )
        """)

        # Create trade_config table
        c.execute("""
            CREATE TABLE IF NOT EXISTS trade_config (
                "ID"	INTEGER,
                "USER_ID"	INTEGER,
                "KEY"	TEXT UNIQUE,
                "TRADABLE_MAIN_SYMBOL_PK"	INTEGER NOT NULL DEFAULT 1,
                "TRADE_BASE_ON"	TEXT NOT NULL DEFAULT 'MAIN_SYMBOL',
                "INTERVAL"	TEXT,
                "LOT"	TEXT,
                "NEAREST_LTP"	INTEGER,
                "INTRADAY"	TEXT,
                "NEW_TRADE"	TEXT,
                "REAL_TRADE"	TEXT,
                "EXPIRY"	TEXT,
                "STRATEGY"	TEXT,
                "CRT_DT"	TEXT,
                "LST_UPDT_DT"	TEXT,
                "HEDGE_TYPE"	TEXT,
                "HEDGE_ROLLOVER_TYPE"	TEXT,
                "ACTIVE_FLAG"	INTEGER,
                "MONTHLY_STOPLOSS"	INTEGER,
                "ACTIVATE_MONTHLY_SL"	INTEGER DEFAULT 0,
                "STOPLOSS_PER_TRADE"	INTEGER,
                "ACTIVATE_SL_PER_TRADE"	INTEGER DEFAULT 0,
                "THREAD_STATUS"	TEXT DEFAULT 'ACTIVE',
                "LAST_ERROR_REASON"	TEXT,
                "ERROR_TIMESTAMP"	TEXT,
                PRIMARY KEY("ID" AUTOINCREMENT),
                FOREIGN KEY("TRADABLE_MAIN_SYMBOL_PK") REFERENCES "tradable_symbols"("symbols_pk"),
                FOREIGN KEY("USER_ID") REFERENCES "user_dtls"("id")
            )
            
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS "kite_session" (
                "session_pk"	INTEGER,
                "user_id"	INTEGER,
                "username"	TEXT,
                "access_token"	TEXT,
                "api_key"	TEXT,
                "api_secret"	TEXT,
                "crt_dt"	TEXT,
                "lst_updt_dt"	TEXT,
                PRIMARY KEY("session_pk"),
                FOREIGN KEY("user_id") REFERENCES "user_dtls"("id")
            )
        """)

        c.execute("""
                CREATE TABLE IF NOT EXISTS "stoploss_mst" (
                    "id"	INTEGER,
                    "name"	TEXT NOT NULL,
                    "sl_type"	TEXT NOT NULL CHECK("sl_type" IN ('STATIC', 'PERCENTAGE', 'STRATEGY_BASED', 'TRAILING')),
                    "scope"	TEXT NOT NULL CHECK("scope" IN ('PER_TRADE', 'DAILY', 'WEEKLY', 'MONTHLY')),
                    "sl_Value"	INTEGER,
                    "is_active"	INTEGER DEFAULT 1 CHECK("is_active" IN (0, 1)),
                    "created_at"	TEXT,
                    "updated_at"	TEXT,
                    PRIMARY KEY("id" AUTOINCREMENT)
                );
        """)
        c.execute("""
                CREATE TABLE IF NOT EXISTS "stoploss_mpg" (
                    "id"	INTEGER,
                    "trade_config_id"	TEXT NOT NULL,
                    "stoploss_id"	INTEGER NOT NULL,
                    "is_active"	INTEGER DEFAULT 1 CHECK("is_active" IN (0, 1)),
                    PRIMARY KEY("id" AUTOINCREMENT),
                    FOREIGN KEY("stoploss_id") REFERENCES "stoploss_mst"("id")
                );
        """)

        # Commit changes and close connection
        conn.commit()
        print(f"Database initialized successfully at {os.path.abspath(DB_FILE)}")
    except sqlite3.Error as e:
        print(f"SQLite error: {e}")
    finally:
        if conn:
            conn.close()


def _dict_factory(cursor, row):
    return {col[0]: row[idx] for idx, col in enumerate(cursor.description)}


def _get_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = _dict_factory
    return conn


def _build_filter_clause(filters):
    if not filters:
        return "", []

    clauses = []
    params = []
    for key, value in filters.items():
        clauses.append(f'"{key}" = ?')
        params.append(value)

    return " WHERE " + " AND ".join(clauses), params


def _build_insert_query(table, data):
    columns = [f'"{key}"' for key in data.keys()]
    placeholders = ["?" for _ in data]
    query = f'INSERT INTO "{table}" ({", ".join(columns)}) VALUES ({", ".join(placeholders)})'
    return query, list(data.values())


def _build_update_query(table, data, pk_name):
    assignments = [f'"{key}" = ?' for key in data.keys()]
    query = f'UPDATE "{table}" SET {", ".join(assignments)} WHERE "{pk_name}" = ?'
    return query, list(data.values())


def _fetch_all(query, params=None):
    params = params or []
    with _get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        return cursor.fetchall()


def _execute_write(query, params=None):
    params = params or []
    with _get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        conn.commit()
        return cursor.lastrowid


def get_tradable_symbols(symbols_pk=None, **filters):
    if symbols_pk is not None:
        filters["symbols_pk"] = symbols_pk
    clause, params = _build_filter_clause(filters)
    return _fetch_all(f'SELECT * FROM "tradable_symbols"{clause}', params)


def set_tradable_symbol(data, symbols_pk=None):
    if symbols_pk is None:
        query, params = _build_insert_query("tradable_symbols", data)
    else:
        query, params = _build_update_query("tradable_symbols", data, "symbols_pk")
        params.append(symbols_pk)
    return _execute_write(query, params)


def get_completed_trades(trade_id=None, **filters):
    if trade_id is not None:
        filters["id"] = trade_id
    clause, params = _build_filter_clause(filters)
    return _fetch_all(f'SELECT * FROM "completed_trades"{clause}', params)


def set_completed_trade(data, trade_id=None):
    if trade_id is None:
        query, params = _build_insert_query("completed_trades", data)
    else:
        query, params = _build_update_query("completed_trades", data, "id")
        params.append(trade_id)
    return _execute_write(query, params)


def get_open_trades(trade_id=None, **filters):
    if trade_id is not None:
        filters["id"] = trade_id
    clause, params = _build_filter_clause(filters)
    return _fetch_all(f'SELECT * FROM "open_trades"{clause}', params)


def set_open_trade(data, trade_id=None):
    if trade_id is None:
        query, params = _build_insert_query("open_trades", data)
    else:
        query, params = _build_update_query("open_trades", data, "id")
        params.append(trade_id)
    return _execute_write(query, params)


def get_user_dtls(user_id=None, **filters):
    if user_id is not None:
        filters["id"] = user_id
    clause, params = _build_filter_clause(filters)
    return _fetch_all(f'SELECT * FROM "user_dtls"{clause}', params)


def set_user_dtls(data, user_id=None):
    if user_id is None:
        query, params = _build_insert_query("user_dtls", data)
    else:
        query, params = _build_update_query("user_dtls", data, "id")
        params.append(user_id)
    return _execute_write(query, params)


def get_trade_config(config_id=None, **filters):
    if config_id is not None:
        filters["ID"] = config_id
    clause, params = _build_filter_clause(filters)
    return _fetch_all(f'SELECT * FROM "trade_config"{clause}', params)


def get_trade_configs(user_id):
    return get_trade_config(USER_ID=user_id)


def set_trade_config(data, config_id=None):
    if config_id is None:
        query, params = _build_insert_query("trade_config", data)
    else:
        query, params = _build_update_query("trade_config", data, "ID")
        params.append(config_id)
    return _execute_write(query, params)


def get_kite_sessions(session_pk=None, **filters):
    if session_pk is not None:
        filters["session_pk"] = session_pk
    clause, params = _build_filter_clause(filters)
    return _fetch_all(f'SELECT * FROM "kite_session"{clause}', params)


def set_kite_session(data, session_pk=None):
    if session_pk is None:
        query, params = _build_insert_query("kite_session", data)
    else:
        query, params = _build_update_query("kite_session", data, "session_pk")
        params.append(session_pk)
    return _execute_write(query, params)


def get_stoploss_by_trade_config(key):
    query = """
    SELECT 
        SMST.sl_Value AS SL_VALUE,
        SMST.sl_type AS SL_TYPE,
        SMST.scope AS SCOPE
    FROM stoploss_mst SMST
    JOIN stoploss_mpg SMPG 
        ON SMST.id = SMPG.stoploss_id
    JOIN trade_config TC 
        ON TC.ID = SMPG.trade_config_id
    WHERE TC.KEY = ?
    AND SMPG.is_active = 1
    AND SMST.is_active = 1
    """
    return _fetch_all(query, [key])

