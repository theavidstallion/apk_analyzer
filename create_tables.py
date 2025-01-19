import sqlite3

# Define the database file
DATABASE_FILE = 'database.db'

# Define the SQL statements to create the tables
CREATE_USER_TABLE = '''
CREATE TABLE IF NOT EXISTS User (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT,
    is_verified BOOLEAN DEFAULT 0
);
'''

CREATE_APKUPLOAD_TABLE = '''
CREATE TABLE IF NOT EXISTS APKUpload (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    filename TEXT NOT NULL,
    apk_metadata TEXT,
    permissions TEXT,
    date_uploaded DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES User (id)
);
'''

CREATE_USER1_TABLE = '''
CREATE TABLE IF NOT EXISTS user (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT,
    is_verified BOOLEAN DEFAULT 0
);
'''

CREATE_APKUPLOAD1_TABLE = '''
CREATE TABLE IF NOT EXISTS apk_upload (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    filename TEXT NOT NULL,
    apk_metadata TEXT,
    permissions TEXT,
    date_uploaded DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES User (id)
);
'''

def create_tables():
    # Connect to the SQLite database
    connection = sqlite3.connect(DATABASE_FILE)
    cursor = connection.cursor()

    # Print the database being used
    print(f"Using database: {DATABASE_FILE}")

    try:
        # Execute the SQL statements
        cursor.execute(CREATE_USER_TABLE)
        cursor.execute(CREATE_APKUPLOAD_TABLE)
        cursor.execute(CREATE_USER1_TABLE)
        cursor.execute(CREATE_APKUPLOAD1_TABLE)
        
        # Commit the changes
        connection.commit()

        # Check if tables were created
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()

        print("Tables created:", tables)
    except sqlite3.Error as e:
        print("An error occurred:", e)
    finally:
        # Close the connection
        connection.close()

if __name__ == '__main__':
    create_tables()
