from flask import Flask, request, redirect, url_for
from google.cloud import datastore
import boat

datastore_client = datastore.Client()



# If the application 'entrypoint' is not defined in the app.yaml, App Engine will look for an
# app called 'app' in 'main.py'
app = Flask(__name__)
app.register_blueprint(boat.bp)

@app.route("/")
def root():

    #return a a string
    return "Hello World!"


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=True)