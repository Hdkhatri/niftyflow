# htmlconfig.py
import os

#Current GCP database path
# DB_PATH = '/home/harshilkhatri2808/prod/tradeJenie/Trading.db'
# PATH = '/home/harshilkhatri2808/prod/tradeJenie'
#GCP
#PROD database path
PROD_DB_PATH = '/home/harshilkhatri2808/prod/tradeJenie/Trading.db'
PROD_PATH = '/home/harshilkhatri2808/prod/tradeJenie'
#UAT database path
UAT_DB_PATH = '/home/harshilkhatri2808/uat/tradeJenie/Trading.db'
UAT_PATH = '/home/harshilkhatri2808/uat/tradeJenie'

# #Local
# #PROD database path
# PROD_DB_PATH = 'E:/NonChakApps/Apps/Jenie/websitejenie/prod/Trading.db'
# PROD_PATH = 'E:/NonChakApps/Apps/Jenie/tradejenie/uat/tradeJenie'
# #UAT database path
# UAT_DB_PATH = 'E:/NonChakApps/Apps/Jenie/websitejenie/uat/Trading.db'
# UAT_PATH = 'E:/NonChakApps/Apps/Jenie/tradejenie/uat/tradeJenie'


# Default active environment paths
DB_PATH = ""
PATH = ""

# LOCAL database path
#DB_PATH = 'C:/Users/Hdkhatri/Desktop/ALGOTRADE/LATEST/updating/project/uat/tradeJenie/Trading.db'
#PATH = 'C:/Users/Hdkhatri/Desktop/ALGOTRADE/LATEST/updating/project/uat/tradeJenie'


# 🔐 Optional security
API_KEY = "supersecret"

ENVIRONMENT = os.getenv('HTMLCONFIG_ENV', os.getenv('APP_ENV', 'PROD')).upper()

def set_path(env=None):
    global DB_PATH, PATH
    env = (env or ENVIRONMENT).upper()
    if env == 'PROD':
        print(f"Setting paths for {env} environment")
        DB_PATH = PROD_DB_PATH
        PATH = PROD_PATH
    elif env == 'UAT':
        print(f"Setting paths for {env} environment")
        DB_PATH = UAT_DB_PATH
        PATH = UAT_PATH
    else:
        raise ValueError(f"Unknown environment: {env}")
    return DB_PATH, PATH

set_path()