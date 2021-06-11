from dotenv import dotenv_values
import requests
# import atexit
from flask import Flask, render_template, request, session
# from flask_apscheduler import APScheduler
from base64 import b64encode
from datetime import datetime, timedelta
import urllib.request
from collections import defaultdict
# from apscheduler.schedulers.background import BackgroundScheduler

config = dotenv_values(".env")

***REMOVED***
***REMOVED***
REDIRECT = "http://a47a9927ab89.ngrok.io"

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

def api_refresh_check(response_data):
    """
    checks response from an api call to see if refresh needed
    """
    did_refresh = False
    try:
        if response_data["code"] == 124:
            refresh_token()
            did_refresh = True
        else:
            pass
    except:
        pass
    return did_refresh

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

def refresh_token():
    """
    Used to refresh a user's access token once it has expired
    """
    
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

def get_participants(meeting_id):
    """
    make this later. need participant info
    zoom api: get meeting participant reports
    """
    authorization = "Bearer " + session['a_token']
    headers = {"Authorization": authorization}
    url = "https://api.zoom.us/v2/report/meetings/" + meeting_id + "/participants"
    response = requests.get(url, headers=headers)
    participants_data = response.json()
    did_refresh = api_refresh_check(participants_data)
    if did_refresh:
        authorization = "Bearer " + session['a_token']
        headers = {"Authorization": authorization}
        response = requests.get(url, headers=headers)
        participants_data = response.json()
    return participants_data

def get_recordings(meeting_id_lst):
    """
    returns a list of meeting recordings given a meeting ID
    """
    print("Using access token: " + session['a_token'])
    authorization = "Bearer " + session['a_token']

    headers = {"Authorization": authorization}

    # if user has too many meetings, not all will be displayed -- see documentation
    # can only display last 30 days of meetings -- api limitation
    today = date.today().isoformat()
    one_month_ago = (date.today()-timedelta(days=30)).isoformat()
    
    url = "https://api.zoom.us/v2/users/me/recordings?from=" + one_month_ago
    response = requests.get(url, headers=headers)
    data = response.json()
    print(data)
    did_refresh = api_refresh_check(data)
    if did_refresh:
        print("Using access token: " + session['a_token'])
        authorization = "Bearer " + session['a_token']
        headers = {"Authorization": authorization}
        response = requests.get(url, headers=headers)
        data = response.json()
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
            for file in meetings_dict[meeting][meeting_inst][1:]:
                """
                filename = meetings_dict[meeting][meeting_inst][0]
                if file_counter == 0:
                    pass
                else:
                    filename += ("(" + str(file_counter) + ")")
                """
                print("Downloading...")
                # print(file + ', ' + filename)
                dl_url = file + "?access_token=" + session['a_token']

                response = requests.get(dl_url, stream=True)
                print(response.text)
                idx = meetings_dict[meeting][meeting_inst].index(file)
                print("Index: " + str(idx))
                meetings_dict[meeting][meeting_inst][idx] = response.text
                p_transcript = parse_transcript(response.text)
                meetings_dict[meeting][meeting_inst][idx] = p_transcript
            meetings_dict[meeting][meeting_inst] = { "transcripts": meetings_dict[meeting][meeting_inst]}
            p_data = get_participants(meeting)["participants"]
            meetings_dict[meeting][meeting_inst]["participants"] = p_data

    # somewhere above call get meeting participants to add more data to meetings dict please
    # TO-DO: determine who was host and add key

    return meetings_dict

def parse_transcript(transcript):
    """
    Inputs:
        transcript, a string
    """
    split_transcript = transcript.split("\r\n")
    p_transcript = []
    # print(split_transcript)
    for idx, line in enumerate(split_transcript):
        if idx == 0:
            continue
        block = []
        if line == "":
            if idx == len(split_transcript) - 1 or idx == len(split_transcript) - 2:
                continue
            # print(idx)
            block.append(int(split_transcript[idx + 1]))
            timestamp = split_transcript[idx + 2].split(" --> ")
            t1 = datetime.strptime(timestamp[0], "%H:%M:%S.%f")
            t2 = datetime.strptime(timestamp[1], "%H:%M:%S.%f")
            timestamp[0] = timedelta(hours=t1.hour, minutes=t1.minute, seconds=t1.second)
            timestamp[1] = timedelta(hours=t2.hour, minutes=t2.minute, seconds=t2.second)
            block.append(tuple(timestamp))
            name_text = split_transcript[idx + 3].split(": ")
            if len(name_text) == 1:
                text = split_transcript[idx + 3].split(": ")[0]
                name = split_transcript[idx - 1].split(": ")[0]
                block.append(name)
                block.append(text)
            else:
                block.append(name_text[0])
                block.append(name_text[1])
            p_transcript.append(block)
        else:
            pass

    print(p_transcript)
    return p_transcript

def speech_instances(transcript_list):
    """
    """
    speech_nums = {}
    for p_transcript in transcript_list[1:]:
        for block in p_transcript:
            if block[2] not in speech_nums:
                speech_nums[block[2]] = 1
            else:
                speech_nums[block[2]] += 1
    print(speech_nums)
    return speech_nums
        
def speech_durations(transcript_list):
    """
    Calculates duration each participant spoke and distribution of speaking time
    """
    durations = collections.defaultdict(lambda: datetime.timedelta())
    for p_transcript in transcript_list[1:]:
        for block in p_transcript:
            tstamp1 = block[1][0]
            tstamp2 = block[1][1]
            partial_duration = abs(tstamp1 - tstamp2)
            durations[block[2]] += partial_duration

    # calculate distribution
    distribution = collections.defaultdict(float)
    total_speaking_time = 0
    for participant in durations:
        total_speaking_time += int(durations[participant].total_seconds())
    for participant in durations:
        distribution[participant] = int(durations[participant].total_seconds()) / total_speaking_time

    return durations, distribution


# idea: instead of auto refresh bc scheduler is not working, try adding error handling for
# every API call (maybe can be separate function for abstraction) and if error code returns expired/invalid access token,
# call refresh function and update session variables.
# then implement time-based auto-check-for-transcripts (w/ webhook notification thingy?)
# aka AVOID SCHEDULER at all costs


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
        meetings_dict = get_recordings(meeting_id_lst)

        ### may change in prod.
        for meeting in meetings_dict:
            for meeting_inst in meetings_dict[meeting]:
                t_list = meetings_dict[meeting][meeting_inst]["transcripts"]
                meeting_vals = meetings_dict[meeting][meeting_inst]
                meeting_vals["instances"] = speech_instances(t_list)
                meeting_vals["durations"] = speech_durations(t_list)[0]
                meeting_vals["distribution"] = speech_durations(t_list)[1]
                print(meeting_vals)
        return render_template("index.html")



if __name__ == "__main__":
    app.run(debug=True)