import sqlite3
import os
import sys

if getattr(sys, 'frozen', False):
    BASE_PATH = os.path.dirname(sys.executable)
else:
    BASE_PATH = os.path.abspath(".")

DB_NAME = os.path.join(BASE_PATH, "database.db")

def init_db():
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS servers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                host TEXT NOT NULL,
                port INTEGER NOT NULL,
                username TEXT NOT NULL,
                password TEXT,
                latitude REAL,
                longitude REAL,
                order_index INTEGER DEFAULT 0,
                auto_connect INTEGER DEFAULT 0
            )
        ''')
        cursor.execute("PRAGMA table_info(servers)")
        columns = [col[1] for col in cursor.fetchall()]
        if "auto_connect" not in columns:
            cursor.execute("ALTER TABLE servers ADD COLUMN auto_connect INTEGER DEFAULT 0")
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS server_scripts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                server_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                script TEXT NOT NULL,
                FOREIGN KEY (server_id) REFERENCES servers(id)
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS server_stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                server_id INTEGER NOT NULL,
                timestamp INTEGER NOT NULL,
                nginx_count INTEGER,
                tor_count INTEGER,
                FOREIGN KEY (server_id) REFERENCES servers(id)
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS config (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        ''')
        cursor.execute("SELECT value FROM config WHERE key = 'global_auto_connect'")
        if cursor.fetchone() is None:
            cursor.execute("INSERT INTO config (key, value) VALUES ('global_auto_connect', '0')")
        conn.commit()

def get_servers():
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM servers ORDER BY order_index ASC")
        return cursor.fetchall()

def add_server(name, host, port, username, password, latitude, longitude):
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT MAX(order_index) FROM servers")
        result = cursor.fetchone()[0]
        new_order = result + 1 if result is not None else 0
        cursor.execute(
            "INSERT INTO servers (name, host, port, username, password, latitude, longitude, auto_connect, order_index) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)",
            (name, host, port, username, password, latitude, longitude, new_order)
        )
        conn.commit()

def delete_server(server_id):
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM servers WHERE id=?", (server_id,))
        cursor.execute("DELETE FROM server_scripts WHERE server_id=?", (server_id,))
        cursor.execute("DELETE FROM server_stats WHERE server_id=?", (server_id,))
        conn.commit()

def get_server(server_id):
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM servers WHERE id=?", (server_id,))
        return cursor.fetchone()

def update_server(server_id, name, host, port, username, password):
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE servers SET name=?, host=?, port=?, username=?, password=? WHERE id=?",
                       (name, host, port, username, password, server_id))
        conn.commit()

def update_server_auto_connect(server_id, auto_connect):
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE servers SET auto_connect=? WHERE id=?", (1 if auto_connect else 0, server_id))
        conn.commit()

def add_script(server_id, name, script):
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO server_scripts (server_id, name, script) VALUES (?, ?, ?)",
                       (server_id, name, script))
        conn.commit()

def get_scripts(server_id):
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM server_scripts WHERE server_id=?", (server_id,))
        return cursor.fetchall()

def update_script(script_id, name, script):
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE server_scripts SET name=?, script=? WHERE id=?", (name, script, script_id))
        conn.commit()

def delete_script(script_id):
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM server_scripts WHERE id=?", (script_id,))
        conn.commit()

def add_stat(server_id, timestamp, nginx_count, tor_count):
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO server_stats (server_id, timestamp, nginx_count, tor_count) VALUES (?, ?, ?, ?)",
                       (server_id, timestamp, nginx_count, tor_count))
        conn.commit()

def get_stats(server_id):
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT timestamp, nginx_count, tor_count FROM server_stats WHERE server_id=? ORDER BY timestamp ASC",
                       (server_id,))
        return cursor.fetchall()

def swap_server_order(id1, id2):
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT order_index FROM servers WHERE id=?", (id1,))
        order1 = cursor.fetchone()[0]
        cursor.execute("SELECT order_index FROM servers WHERE id=?", (id2,))
        order2 = cursor.fetchone()[0]
        cursor.execute("UPDATE servers SET order_index=? WHERE id=?", (order2, id1))
        cursor.execute("UPDATE servers SET order_index=? WHERE id=?", (order1, id2))
        conn.commit()

def get_global_auto_connect():
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT value FROM config WHERE key = 'global_auto_connect'")
        row = cursor.fetchone()
        return int(row[0]) if row and row[0].isdigit() else 0

def update_global_auto_connect(val):
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT OR REPLACE INTO config (key, value) VALUES ('global_auto_connect', ?)", (str(val),))
        conn.commit()