import requests
import pandas as pd

import sys
import io

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

url = "https://api.kite.trade/instruments"
filename = "instruments.csv"
filtered_filename = "nifty_instruments.csv"

def get_tradable_symbols_and_save_filtered(symbol):
    """
    Downloads instruments, filters by symbol type, saves filtered data to file, and returns list of tradingsymbols.
    
    Args:
        symbol (str): The symbol type, e.g., "Nifty" or "sensex"
    
    Returns:
        list: List of tradingsymbols from the filtered data
    """
    if symbol.lower() == "nifty 50" or symbol.lower() == "nifty":
        filter_names = ["NIFTY 50", "NIFTY"]
        output_filename = "nifty_instruments.csv"
    elif symbol.lower() == "sensex":
        filter_names = ["SENSEX"]
        output_filename = "sensex_instruments.csv"
    elif symbol.lower() == "nifty bank" or symbol.lower() == "banknifty":
        filter_names = ["NIFTY BANK", "BANKNIFTY"]
        output_filename = "banknifty_instruments.csv"
    else:
        raise ValueError(f"Unsupported symbol: {symbol}. Supported: 'Nifty', 'sensex', 'Nifty Bank', 'Banknifty'")
    
    try:
        print("⬇️ Downloading latest instruments.csv...")
        response = requests.get(url)
        response.raise_for_status()  # Raise error for bad response

        with open(filename, "wb") as f:
            f.write(response.content)

        print("✅ instruments.csv downloaded successfully.")

        # Load and filter the CSV
        df = pd.read_csv(filename)
        
        # Filter where 'name' is in filter_names
        filtered_df = df[df['name'].isin(filter_names)]
        
        # Save filtered data
        filtered_df.to_csv(output_filename, index=False)
        print(f"✅ Filtered file saved as: {output_filename} | Rows: {len(filtered_df)}")
        
        # Return list of tradingsymbols
        return output_filename

    except Exception as e:
        print(f"❌ Failed: {e}")
        return None

# if __name__ == "__main__":
#     try:
#         # Example usage
#         tradable_symbols = get_tradable_symbols_and_save_filtered("sensex")
#         print(f"Tradable symbols: {tradable_symbols}")

#     except Exception as e:
#         print(f"❌ Failed: {e}")

