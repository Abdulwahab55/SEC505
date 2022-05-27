import mysql.connector
conn = mysql.connector.connect(
    host="localhost",
    user="root",
    passwd=""
) 
cur = conn.cursor()
cur.execute("CREATE DATABASE projDB")
cur.execute("SHOW DATABASES")
for i in cur:
    print(i)
