import os
import mysql.connector

def insert_alert(source_ip,destination_ip,attack_type,risk_level):
    try :
        db_connection = mysql.connector.connect(
            host="localhost",
            user="root",
            password=os.getenv('DB_PASSWORD'),
            database="nids_db"
        )
        print('DATABASE CONNECTED SUCCESSFULLY !')
       
        cursor=db_connection.cursor()

        sql_query="insert into alerts(source_ip,destination_ip,attack_type,risk_level) values(%s, %s, %s,%s)"
        data=(source_ip,destination_ip,attack_type,risk_level)
        cursor.execute(sql_query,data)
        db_connection.commit()
        print(f"ALERT INSERTED INTO 'alerts'TABLE !")
    except mysql.connector.Error as er:
        print(f"ERREUR :{er}")
    finally:
        if'db_connection' in locals() and db_connection.is_connected():
            cursor.close()
            db_connection.close()
            print("DATABASE CONNECTION CLOSED !")
        
def get_all_alerts():
    try :
        db_connection = mysql.connector.connect(
            host="localhost",
            user="root",
            password=os.getenv('DB_PASSWORD'),
            database="nids_db"
        )
        cursor=db_connection.cursor(dictionary=True)
        cursor.execute("SELECT*FROM alerts ORDER BY detected_at DESC,id DESC")
        res=cursor.fetchall()
        return res
    except mysql.connector.Error as err:
        print(f"ERREUR :{err}")
        return[]
    finally:
        if'db_connection' in locals() and db_connection.is_connected():
            cursor.close()
            db_connection.close()

