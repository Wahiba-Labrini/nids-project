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
        print('connection reusssite a la base donnee !')
       

        cursor=db_connection.cursor()
        sql_query="insert into alerts(source_ip,destination_ip,attack_type,risk_level) values(%s, %s, %s,%s)"
        data=(source_ip,destination_ip,attack_type,risk_level)
        cursor.execute(sql_query,data)
        db_connection.commit()
        print(f"💾donnees inseree avec succes dans tableau 'alerts'!")
    except mysql.connector.Error as error:
        print(f"❌ ERREUR :{error}")
    finally:
        if'db_connection' in locals() and db_connection.is_connected():
            cursor.close()
            db_connection.close()
            print("connection fermee")
        
