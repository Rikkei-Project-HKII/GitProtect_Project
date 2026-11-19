import pymysql

conn = pymysql.connect(host='localhost', user='root', password='123456', port=3306)
cursor = conn.cursor()
cursor.execute("DROP DATABASE IF EXISTS gitprotect_db;")
cursor.execute("CREATE DATABASE gitprotect_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;")
cursor.execute("GRANT ALL PRIVILEGES ON gitprotect_db.* TO 'gitprotect_user'@'localhost';")
cursor.execute("FLUSH PRIVILEGES;")
conn.commit()
conn.close()
print("Clean gitprotect_db created!")
