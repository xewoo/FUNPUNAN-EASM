import sqlite3
import os
import stat

def make_db_readable():
    db_path = "easm.db"
    if not os.path.exists(db_path):
        print("Database file does not exist!")
        return

    # Make the file readable
    try:
        # Set file permissions to readable and writable for everyone
        os.chmod(db_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IWGRP | stat.S_IROTH | stat.S_IWOTH)
        print("Database permissions updated successfully!")
    except Exception as e:
        print(f"Error updating permissions: {e}")

    # Test database connection and show contents
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        print("\n=== Database Structure ===")
        # Get list of tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        
        for table in tables:
            table_name = table[0]
            print(f"\n[Table: {table_name}]")
            
            # Get column info
            cursor.execute(f"PRAGMA table_info({table_name})")
            columns = cursor.fetchall()
            print("Columns:")
            for col in columns:
                print(f"- {col[1]} ({col[2]})")
            
            # Show sample data (first 3 rows)
            try:
                cursor.execute(f"SELECT * FROM {table_name} LIMIT 3")
                rows = cursor.fetchall()
                if rows:
                    print("\nSample Data (up to 3 rows):")
                    for row in rows:
                        print(row)
            except sqlite3.Error as e:
                print(f"Error reading data: {e}")
            
            print("\n" + "-"*50)
        
        conn.close()
        
        print("\nTo view this database in detail, you can use DB Browser for SQLite:")
        print("1. Download from: https://sqlitebrowser.org/dl/")
        print("2. Install DB Browser for SQLite")
        print("3. Open DB Browser and click 'Open Database'")
        print("4. Navigate to this folder and select 'easm.db'")
        print("\nThe database should now be readable and accessible!")
        
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    make_db_readable()