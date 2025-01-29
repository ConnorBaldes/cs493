from flask import Flask, request
import boat
import load

app = Flask(__name__)
app.register_blueprint(boat.bp)
app.register_blueprint(load.bp)

@app.route('/')
def index():
    return ""

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)