from sqlalchemy import Column,Integer,Float,String,DateTime
from sqlalchemy.orm import declarative_base
from database.database import engine

base=declarative_base()

class TrafficWindow(base):
    __tablename__='traffic_windows'
    id=Column(Integer,primary_key=True)
    src_ip=Column(String(15))
    dst_ip=Column(String(15))
    window_start=Column(DateTime)
    packets_per_seconde=Column(Float)
    unique_ports=Column(Integer)


base.metadata.create_all(bind=engine)
print("created sucessfuly")


