import requests
from flask import Flask, render_template, request
from base64 import b64encode
import time

app = Flask(__name__)


@app.route("/", methods=["POST", "GET"])
def index():
    # 
    auth_code = None

    return render_template("index.html")


@app.route("/received", methods=["POST", "GET"])
def receive():
    if request.method == "POST":
        result = request.form
        meeting_id = result["meetids"]
        # print(meeting_id)
        return render_template("index.html")


# Meeting ID: 993 7486 2702 rGBSWhHgYX_NSu_bVQwQLeTf1pCb4fldA

# meeting_id = "993 7486 2702"

# baylee's auth code rGBSWhHgYX_NSu_bVQwQLeTf1pCb4fldA

# url = 'https://zoom.us/oauth/token'
# print(url)


def get_access_token(auth_code):
    """
    retrieves access token based on someones auth code
    """
    clientid = "A9Mmyi4xQTaVyh1FwflKVQ"
    clientsec = "4YjioAh3ArPNWGfQRXQ5FChuxznL77Hx"

    str_code = clientid + ":" + clientsec
    ascii_code = str_code.encode("ascii")
    authorization = "Basic " + str(b64encode(ascii_code))[2:-1]

    print(authorization)

    content_type = "application/x-www-form-urlencoded"

    headers = {"Authorization": authorization, "Content-Type": content_type}

    redirect_uri = "https://rice.edu/"

    url = (
        "https://zoom.us/oauth/token?code="
        + auth_code
        + "&grant_type=authorization_code&redirect_uri="
        + redirect_uri
    )

    response = requests.post(url, headers=headers)
    print(response.text)
    data = response.json()
    access_token = data["access_token"]
    # print(access_token)

    return access_token


def refresh_token():
    """
    refresh access token after 60min
    make post request to https://zoom.us/oauth/token

    """


def get_recordings(access_token, meeting_id):
    """
    returns a list of meeting recordings given a meeting ID
    """
    authorization2 = "Bearer " + access_token

    headers2 = {"Authorization": authorization2}

    url2 = "https://api.zoom.us/v2/meetings/" + meeting_id + "/recordings"
    response2 = requests.get(url2, headers=headers2)
    print(response2)
    data = response2.json()
    # print(data)

    # list of dictionaries
    # recordings = data['recording_files']

    return data


# access_token = get_access_token(auth_code)
# print(get_recordings(access_token, "99374862702"))

if __name__ == "__main__":
    app.run()
