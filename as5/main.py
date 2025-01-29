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



if __name__ == "__main__":

    # This is used when running locally only. 
    # When deploying to Google App Engine, a webserver process serves the app. 
    # You can configure startup instructions by adding `entrypoint` to app.yaml.
    app.run(host="127.0.0.1", port=8080, debug=True)

