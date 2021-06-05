from dotenv import dotenv_values
import requests
import atexit
from flask import Flask, render_template, request
from base64 import b64encode
import time
from apscheduler.schedulers.background import BackgroundScheduler

config = dotenv_values(".env")

***REMOVED***
***REMOVED***

app = Flask(__name__)

"""
Ask users to either launch app from given link every time, or bookmark their personal link (i.e. the one with their auth code)
"""
# FUNCTIONS #

def get_access_token(auth_code):
    """
    Retrieves an Access Token and Refresh Token given an Authorization Code
    Access Tokens expire after 60 minutes

    Inputs:
        auth_code -- string representing authorization code after user has authorized extension

    Outputs:
        access_token -- string representing user's access_token for API calls
        refresh_token -- string representing user's refresh_token for refreshing access token
    """

    # encodes client ID and client secret into base64 for Authorization header

    str_code = CLIENT_ID + ":" + CLIENT_SEC
    ascii_code = str_code.encode("ascii")

    authorization = "Basic " + str(b64encode(ascii_code))[2:-1]
    content_type = "application/x-www-form-urlencoded"

    headers = {"Authorization": authorization, "Content-Type": content_type}

    redirect_uri = "https://teamdna-zoom.herokuapp.com/"

    url = (
        "https://zoom.us/oauth/token?code="
        + auth_code
        + "&grant_type=authorization_code&redirect_uri="
        + redirect_uri
    )

    response = requests.post(url, headers=headers)
    data = response.json()
    
    access_token = data["access_token"]
    r_token = data["refresh_token"]

    return access_token, r_token


def refresh_token(r_token):
    """
    Used to refresh a user's access token once it has expired
    """

    url = "https://zoom.us/oauth/token?grant_type=refresh_token&refresh_token=" + str(r_token)

    str_code = CLIENT_ID + ":" + CLIENT_SEC
    ascii_code = str_code.encode("ascii")

    authorization = "Basic " + str(b64encode(ascii_code))[2:-1]
    content_type = "application/x-www-form-urlencoded"

    headers = {"Authorization" : authorization, "Content-Type" : content_type}

    response = requests.post(url, headers=headers)
    data = response.json()

    new_access_token = data["access_token"]
    new_r_token = data["refresh_token"]

    return new_access_token, new_r_token


def get_recordings(meeting_id):
    """
    returns a list of meeting recordings given a meeting ID
    """
    authorization2 = "Bearer " + access_token

    headers2 = {"Authorization": authorization2}

    url2 = "https://api.zoom.us/v2/meetings/" + meeting_id + "/recordings"
    response2 = requests.get(url2, headers=headers2)
    data = response2.json()
    # print(data)

    # list of dictionaries
    # recordings = data['recording_files']

    return data


@app.route("/", methods=["POST", "GET"])
def index():

    # app will fail if user has not authenticated OAuth extension
    auth_code = request.args['code']

    access_token, r_token = get_access_token(auth_code)

    refresh_scheduler = BackgroundScheduler()
    refresh_scheduler.add_job(func=refresh_token, trigger="interval", minutes=59, args=[r_token])
    refresh_scheduler.start()

    return render_template("index.html")

@app.route("/received", methods=["POST", "GET"])
def receive():
    if request.method == "POST":
        result = request.form
        meeting_id = result["meetids"]
        # print(meeting_id)
        return render_template("index.html")


if __name__ == "__main__":
    app.run(debug=True)

atexit.register(lambda: refresh_scheduler.shutdown())