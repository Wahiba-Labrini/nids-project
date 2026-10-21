from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
import os
from dotenv import load_dotenv
from pathlib import Path
import urllib.parse


load_dotenv(Path(__file__).parent /".env")

db_user=os.getenv('DB_USER')
db_password=os.getenv('DB_PASSWORD')
db_host=os.getenv('DB_HOST')
db_name=os.getenv('DB_NAME')

safe_password=urllib.parse.quote_plus(db_password)

engine=create_engine(f"mysql+pymysql://{db_user}:{safe_password}@{db_host}/{db_name}")
Session=sessionmaker(bind=engine)
session=Session()