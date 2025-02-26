import sqlite3

try:
    with sqlite3.connect("mydatabase.db") as conn:
        cursor = conn.cursor()
        cursor.execute("DROP TABLE IF EXISTS alembic_version;")
        conn.commit()
    print("Dropped alembic_version table successfully!")
except sqlite3.Error as e:
    print(f"Error occurred while dropping the table: {e}")
