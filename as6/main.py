import requests
import secrets
from google.cloud import datastore
from flask import Flask, render_template, redirect, request

# set client ID, secret, and project redirect page
client_id = ""
client_secret = ""
redirect_uri = "https://baldesc-cs493-p6.wn.r.appspot.com/callback"

app = Flask(__name__)
client = datastore.Client()

# Function to generate and store a random state value in Datastore
def generate_and_store_state():

    # the secrets library is used here to generate a safe state
    state = secrets.token_urlsafe(16)

    # that state is then stored in datastoure under the key 'OAuthState'
    key = client.key('OAuthState', state)
    entity = datastore.Entity(key)
    client.put(entity)

    # state is returned as its value is needed for other processes
    return state

# Function to check if a state value exists in Datastore
def is_valid_state(state):

    key = client.key('OAuthState', state)
    return client.get(key) is not None

# Route to home page of application
@app.route("/")
def root():

    # first a unique state is generated 
    state = generate_and_store_state()
    #The state is passed to the home page so that if the login button
    # is clicked the state is sent to the /authorize page
    return render_template("index.html", state=state)

# Authorize is used to build the request needed to get an access code
# from google
@app.route('/authorize', methods=['POST'])
def authorize():

    # this is where the state variable that is passed in the return function of
    # the home page is accessed, so we can send the current 'state' to google for
    # our own protection
    state = request.form.get('state')

    # the state is checked to make sure it is valid
    if not is_valid_state(state):
        return "Invalid state parameter. Possible CSRF attack."

    # setting google authorization url path alond with the scope path
    # to indicate what info we want from the user
    google_auth_url = "https://accounts.google.com/o/oauth2/v2/auth"
    scope = "https://www.googleapis.com/auth/userinfo.profile"

    authorization_url = f"{google_auth_url}?" \
                        f"client_id={client_id}&" \
                        f"redirect_uri={redirect_uri}&" \
                        f"response_type=code&" \
                        f"scope={scope}&" \
                        f"state={state}"

    return redirect(authorization_url)






# Callback endpoint to handle Google's redirect
@app.route('/callback')
def callback():

    #save googel access code 
    code = request.args.get('code')
    state = request.args.get('state')

    # check to make sure the state google sends back matches the 
    # saved state value
    if not is_valid_state(state):
        return "Invalid state parameter. Possible CSRF attack."

    # Set URL to get token with access code
    token_url = "https://oauth2.googleapis.com/token"
    token_params = {
        "code": code,
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code"
    }
    # send POST request to get access token from google
    token_response = requests.post(token_url, data=token_params)
    token_data = token_response.json()

    # Use access token to get user info
    user_info_url = "https://people.googleapis.com/v1/people/me?personFields=names"
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}
    user_info_response = requests.get(user_info_url, headers=headers)
    user_info = user_info_response.json()

    # display user info page
    return render_template('user_info.html', user_info=user_info, state=state)



if __name__ == "__main__":
    # This is used when running locally only. When deploying to Google App
    # Engine, a webserver process such as Gunicorn will serve the app. This
    # can be configured by adding an `entrypoint` to app.yaml.
    # Flask's development server will automatically serve static files in
    # the "static" directory. See:
    # http://flask.pocoo.org/docs/1.0/quickstart/#static-files. Once deployed,
    # App Engine itself will serve those files as configured in app.yaml.
    app.run(host="127.0.0.1", port=8080, debug=True)
