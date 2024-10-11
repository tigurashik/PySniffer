import pymysql
from flask import Flask, render_template
from config import DB_CONFIG

app = Flask(__name__)

db = pymysql.connect(**DB_CONFIG)
cursor = db.cursor()

@app.route('/')
def index():
    cursor.execute("SELECT * FROM packets ORDER BY timestamp DESC")
    rows = cursor.fetchall()

    packets = [
        {
            "id": row[0],
            "src_ip": row[1],
            "dst_ip": row[2],
            "src_port": row[3],
            "dst_port": row[4],
            "protocol": row[5],
            "length": row[6],
            "raw_data": row[7],
            "timestamp": row[8]
        }
        for row in rows
    ]

    return render_template('index.html', packets=packets)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
