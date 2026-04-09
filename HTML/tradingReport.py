import logging
import sqlite3
from flask import Blueprint, render_template, request, redirect, url_for, session


trading_report_bp = Blueprint('trading_report_bp', __name__)


def get_db_connection():
    from htmlconfig import DB_PATH
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def get_logged_in_user():
    user_id = session.get('user_id')
    username = session.get('username')

    if not user_id or not username:
        return None

    conn = get_db_connection()
    user = conn.execute(
        """
        SELECT id, user
        FROM user_dtls
        WHERE id = ? AND active_flag = 1
        """,
        (user_id,)
    ).fetchone()
    conn.close()
    return user


@trading_report_bp.route('/trading-report')
def trading_report():
    try:
        user = get_logged_in_user()
        if not user:
            session.clear()
            return redirect(url_for('login_bp.login'))

        selected_key = (request.args.get('key') or '').strip()
        start_date = (request.args.get('start_date') or '').strip()
        end_date = (request.args.get('end_date') or '').strip()
        detail = (request.args.get('detail') or '').strip().lower()
        if detail not in {'all', 'profit', 'loss'}:
            detail = ''

        conn = get_db_connection()

        key_rows = conn.execute(
            """
            SELECT DISTINCT "key"
            FROM completed_trades
            WHERE user_id = ?
              AND real_trade = 'yes'
              AND "key" IS NOT NULL
              AND TRIM("key") != ''
            ORDER BY "key"
            """,
            (user['id'],)
        ).fetchall()
        available_keys = [row['key'] for row in key_rows]

        filters = ["user_id = ?", "real_trade = 'yes'"]
        params = [user['id']]

        if selected_key:
            filters.append('"key" = ?')
            params.append(selected_key)
        if start_date:
            filters.append('date(exit_time) >= date(?)')
            params.append(start_date)
        if end_date:
            filters.append('date(exit_time) <= date(?)')
            params.append(end_date)

        where_clause = " AND ".join(filters)

        summary = conn.execute(
            f"""
            SELECT
                COALESCE(SUM(COALESCE(total_pnl, 0) * COALESCE(qty, 0)), 0) AS realized_pnl,
                COUNT(*) AS total_trades,
                SUM(CASE WHEN COALESCE(total_pnl, 0) * COALESCE(qty, 0) > 0 THEN 1 ELSE 0 END) AS profitable_trades,
                SUM(CASE WHEN COALESCE(total_pnl, 0) * COALESCE(qty, 0) < 0 THEN 1 ELSE 0 END) AS losing_trades
            FROM completed_trades
            WHERE {where_clause}
            """,
            params
        ).fetchone()

        trades = []
        detail_title = ''
        if detail:
            detail_filters = list(filters)
            detail_params = list(params)

            if detail == 'profit':
                detail_filters.append('COALESCE(total_pnl, 0) * COALESCE(qty, 0) > 0')
                detail_title = 'Profitable Trades'
            elif detail == 'loss':
                detail_filters.append('COALESCE(total_pnl, 0) * COALESCE(qty, 0) < 0')
                detail_title = 'Losing Trades'
            else:
                detail_title = 'Completed Trades'

            detail_where_clause = " AND ".join(detail_filters)

            trades = conn.execute(
                f"""
                SELECT
                    id,
                    "key",
                    option_symbol,
                    option_buy_price,
                    option_sell_price,
                    hedge_option_symbol,
                    hedge_option_sell_price,
                    hedge_option_buy_price,
                    signal,
                    qty,
                    entry_time,
                    exit_time,
                    total_pnl,
                    COALESCE(total_pnl, 0) * COALESCE(qty, 0) AS realized_pnl
                FROM completed_trades
                WHERE {detail_where_clause}
                ORDER BY datetime(exit_time) DESC, id DESC
                """,
                detail_params
            ).fetchall()

        conn.close()

        return render_template(
            'tradingReport.html',
            username=user['user'],
            available_keys=available_keys,
            selected_key=selected_key,
            start_date=start_date,
            end_date=end_date,
            detail=detail,
            detail_title=detail_title,
            summary=summary,
            trades=trades
        )
    except Exception as e:
        logging.error(f"Error loading trading report: {e}")
        return redirect(url_for('login_bp.login'))
