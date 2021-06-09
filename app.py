from dotenv import dotenv_values
import requests
# import atexit
from flask import Flask, render_template, request, session
# from flask_apscheduler import APScheduler
from base64 import b64encode
from datetime import date, timedelta
import urllib.request
# from apscheduler.schedulers.background import BackgroundScheduler

config = dotenv_values(".env")

CLIENT_ID = config["CLIENT_ID"]
CLIENT_SEC = config["CLIENT_SECRET"]
REDIRECT = "http://teamdna-zoom.herokuapp.com/"

app = Flask(__name__)

# change this later
app.secret_key = 'EXAMPLE_KEY'

"""
Ask users to either launch app from given link every time, or bookmark their personal link (i.e. the one with their auth code)
"""

# act as global variables
# access_token_lst = [None]
# r_token_lst = [None]

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

    redirect_uri = REDIRECT

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

    # access_token_lst[0] = access_token
    # r_token_lst[0] = r_token

    return access_token, r_token


def get_recordings(meeting_id_lst):
    """
    returns a list of meeting recordings given a meeting ID
    """
    print("Using access token: " + session['a_token'])
    authorization2 = "Bearer " + session['a_token']

    headers2 = {"Authorization": authorization2}

    # if user has too many meetings, not all will be displayed -- see documentation
    # can only display last 30 days of meetings -- api limitation
    today = date.today().isoformat()
    one_month_ago = (date.today()-timedelta(days=30)).isoformat()
    
    url2 = "https://api.zoom.us/v2/users/me/recordings?from=" + one_month_ago
    response2 = requests.get(url2, headers=headers2)
    data = response2.json()
    print(data)
    meetings = data["meetings"]
    # list of dictionaries
    # recordings = data['recording_files']
    print("Meetings:")
    print(meetings)

    meetings_dict = {}
    for meeting_id in meeting_id_lst:
        meetings_dict[meeting_id] = {}
        for meeting in meetings:
            # meeting id is int from zoom
            if str(meeting['id']) == meeting_id:
                uuid = meeting['uuid']
                meetings_dict[meeting_id][uuid] = [meeting['start_time']]
                for file in meeting['recording_files']:
                    if file["file_type"] == "TRANSCRIPT":
                        print("Transcript found")
                        download_url = file["download_url"]
                        meetings_dict[meeting_id][uuid].append(download_url)
                print("UUID: " + meeting['uuid'])
                print("Successfully added meeting instance")
    
    print(meetings_dict)
    for meeting in meetings_dict:
        for meeting_inst in meetings_dict[meeting]:
            file_counter = 0
            for file in meetings_dict[meeting][meeting_inst][1:]:
                """
                filename = meetings_dict[meeting][meeting_inst][0]
                if file_counter == 0:
                    pass
                else:
                    filename += ("(" + str(file_counter) + ")")
                """
                print("Downloading...")
                print(file + ', ' + filename)
                dl_url = file + "?access_token=" + session['a_token']

                response = requests.get(dl_url, stream=True)
                print(response.text)

                file_counter += 1

    return data


@app.route("/", methods=["GET"])
def index():
    # app will fail if user has not authenticated OAuth extension
    auth_code = request.args['code']
    print("Authorization code: " + auth_code)

    access_token, r_token = get_access_token(auth_code)
    print("Access token: " + access_token)
    print("Refresh token: " + r_token)

    session['a_token'] = access_token
    session['r_token'] = r_token

    """
    refresh_scheduler = APScheduler()
    refresh_scheduler.init_app(app)
    def refresh_token():
        
        Used to refresh a user's access token once it has expired
        
        print("Refreshing...")
        r_token = session.get('r_token')
        print(r_token)

        url = "https://zoom.us/oauth/token?grant_type=refresh_token&refresh_token=" + str(r_token)

        str_code = CLIENT_ID + ":" + CLIENT_SEC
        ascii_code = str_code.encode("ascii")

        authorization = "Basic " + str(b64encode(ascii_code))[2:-1]
        content_type = "application/x-www-form-urlencoded"

        headers = {"Authorization" : authorization, "Content-Type" : content_type}

        response = requests.post(url, headers=headers)
        data = response.json()
        print('Response: ' + response.text)

        new_access_token = data["access_token"]
        new_r_token = data["refresh_token"]

        print("New Access: " + new_access_token)

        # access_token_lst[0] = new_access_token
        # r_token_lst[0] = new_r_token

        session['a_token'] = new_access_token
        session['r_token'] = new_r_token

        return new_access_token, new_r_token

    refresh_scheduler.add_job(func=refresh_token, id="refreshing", trigger="interval", seconds=15)
    refresh_scheduler.start()
    """

    return render_template("index.html")


@app.route("/", methods=["POST"])
def receive():
    if request.method == "POST":
        result = request.form
        meeting_ids = result["meetids"]
        meeting_id_lst = meeting_ids.split(", ")
        print("Meeting IDs: ")
        print(meeting_id_lst)
        print("Recordings:")
        get_recordings(meeting_id_lst)
        return render_template("index.html")



if __name__ == "__main__":
    app.run(debug=True)