from flask import Flask, jsonify
import psycopg2
import os

app = Flask(__name__)

# Database Config (Matches Config Guide Step 4)
DB_HOST = "127.0.0.1"
DB_NAME = "testdb"
DB_USER = "testuser"
DB_PASS = "testpass"

@app.route('/')
def index():
    return "Versa SD-WAN Test App Server Online"

@app.route('/db/query')
def db_query():
    try:
        conn = psycopg2.connect(host=DB_HOST, database=DB_NAME, user=DB_USER, password=DB_PASS)
        cur = conn.cursor()
        # Execute a lightweight query (simulates a fast lookup)
        cur.execute("SELECT 1;")
        result = cur.fetchone()
        cur.close()
        conn.close()
        return jsonify({"status": "success", "data": result, "backend": "postgresql"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == '__main__':
    # Listen on port 5000 (standard Flask port)
    app.run(host='0.0.0.0', port=5000)
