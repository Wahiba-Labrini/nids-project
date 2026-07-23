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
    except mysql.connector.Error as er:
        print(f"ERREUR :{er}")
        return[]
    finally:
        if'db_connection' in locals() and db_connection.is_connected():
            cursor.close()
            db_connection.close()


def get_dashboard_stats():
    try:
        db_connection = mysql.connector.connect(
            host="localhost",
            user="root",
            password=os.getenv('DB_PASSWORD'),
            database="nids_db"
        )
        cursor = db_connection.cursor()

        cursor.execute("SELECT COUNT(*) FROM alerts")
        total_alerts = cursor.fetchone()[0]

        cursor.execute("""
            SELECT attack_type, COUNT(*) as total
            FROM alerts
            GROUP BY attack_type
            ORDER BY total DESC
            LIMIT 1
        """)
        most_common_result = cursor.fetchone()
        most_common_attack = most_common_result[0] if most_common_result else "N/A"

        cursor.execute("""
            SELECT DATE(detected_at) as attack_day, COUNT(*) as total
            FROM alerts
            GROUP BY DATE(detected_at)
            ORDER BY total DESC
            LIMIT 1
        """)
        most_active_result = cursor.fetchone()
        most_active_day = most_active_result[0] if most_active_result else "N/A"

        return {
            "total_alerts": total_alerts,
            "most_common_attack": most_common_attack,
            "most_active_day": most_active_day
        }

    except mysql.connector.Error as er:
        print(f"ERREUR: {er}")
        return {"total_alerts": 0, "most_common_attack": "N/A", "most_active_day": "N/A"}
    finally:
        if 'db_connection' in locals() and db_connection.is_connected():
            cursor.close()
            db_connection.close()