from dotenv import dotenv_values
import requests
# import atexit
from flask import Flask, render_template, request, session
# from flask_apscheduler import APScheduler
from base64 import b64encode
from datetime import date, datetime, timedelta
import urllib.request
import urllib.parse
from collections import defaultdict
# from apscheduler.schedulers.background import BackgroundScheduler

config = dotenv_values(".env")

***REMOVED***
***REMOVED***
REDIRECT = "http://7bcd16315c95.ngrok.io"

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
    print(meeting_id)
    if (meeting_id[0] == "/") or ("//" in meeting_id):
        print("Encoding...")
        meeting_id = urllib.parse.quote(meeting_id, safe='')
        meeting_id = urllib.parse.quote(meeting_id, safe='')
    url = "https://api.zoom.us/v2/past_meetings/" + meeting_id + "/participants"
    response = requests.get(url, headers=headers)
    participants_data = response.json()
    did_refresh = api_refresh_check(participants_data)
    if did_refresh:
        authorization = "Bearer " + session['a_token']
        headers = {"Authorization": authorization}
        response = requests.get(url, headers=headers)
        participants_data = response.json()
    # prevents unfinished meetings from being included in dashboard
    if "code" in participants_data.keys():
        if participants_data["code"] == 3001:
            return False
    # print(participants_data)
    new_participants = {}
    for participant in participants_data['participants']:
        if participant["name"] in new_participants.keys() and participant["user_email"] == '':
            continue
        new_participants[participant["name"]] = participant["user_email"]
    return new_participants

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
    # print(data)
    did_refresh = api_refresh_check(data)
    if did_refresh:
        # print("Using access token: " + session['a_token'])
        authorization = "Bearer " + session['a_token']
        headers = {"Authorization": authorization}
        response = requests.get(url, headers=headers)
        data = response.json()
        # print(data)
    meetings = data["meetings"]
    # list of dictionaries
    # recordings = data['recording_files']
    # print("Meetings:")
    # print(meetings)

    meetings_dict = {}
    for meeting_id in meeting_id_lst:
        meetings_dict[meeting_id] = {}
        for meeting in meetings:
            # meeting id is int from zoom
            if str(meeting['id']) == meeting_id:
                topic = meeting['topic']
                host_id = meeting['host_id']
                duration = meeting['duration']
                uuid = meeting['uuid']
                timedate = meeting["start_time"]
                timedate = timedate.replace("T", " ")
                timedate = timedate.replace("Z", " GMT")
                meetings_dict[meeting_id][uuid] = [timedate, duration]
                if "topic" not in meetings_dict[meeting_id].keys():
                    meetings_dict[meeting_id]["topic"] = topic
                    meetings_dict[meeting_id]["host_id"] = host_id
                transcript_found = False
                for file in meeting['recording_files']:
                    if file["file_type"] == "TRANSCRIPT":
                        print("Transcript found")
                        transcript_found = True
                        download_url = file["download_url"]
                        meetings_dict[meeting_id][uuid].append(download_url)
                if transcript_found == False:
                    del meetings_dict[meeting_id][uuid]
                    print("UUID contained no transcripts: " + uuid)
                else:
                    print("UUID successfully added")
    
    # print(meetings_dict)
    for meeting in meetings_dict:
        for meeting_inst in meetings_dict[meeting].keys():
            if meeting_inst == "topic" or meeting_inst == "host_id":
                continue
            for file in meetings_dict[meeting][meeting_inst][2:]:
                print("Downloading...")
                # print(file + ', ' + filename)
                dl_url = file + "?access_token=" + session['a_token']

                response = requests.get(dl_url, stream=True)
                # print(response.text)
                idx = meetings_dict[meeting][meeting_inst].index(file)
                # print("Index: " + str(idx))
                meetings_dict[meeting][meeting_inst][idx] = response.text
                p_transcript = parse_transcript(response.text)
                meetings_dict[meeting][meeting_inst][idx] = p_transcript
            meeting_vals = meetings_dict[meeting][meeting_inst]
            meeting_vals = { "transcripts": meeting_vals[2:], "timedate": meeting_vals[0], "duration": meeting_vals[1]}
            meetings_dict[meeting][meeting_inst] = meeting_vals
            # p_data = get_participants(meeting)["participants"]
            # meetings_dict[meeting][meeting_inst]["participants"] = p_data

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
        elif line == "WEBVTT":
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
                for line in reversed(split_transcript[:(idx + 1)]):
                    if len(line.split(": ")) == 2:
                        name = line.split(": ")[0]
                        break
                    else:
                        continue
                block.append(name)
                block.append(text)
            else:
                block.append(name_text[0])
                block.append(name_text[1])
            p_transcript.append(block)
        else:
            pass
    # print("Parsed transcript as follows:")
    # print(p_transcript)
    return p_transcript

def speech_instances(transcript_list):
    """
    """
    speech_nums = {}
    for p_transcript in transcript_list:
        for block in p_transcript:
            if block[2] not in speech_nums:
                speech_nums[block[2]] = 1
            else:
                speech_nums[block[2]] += 1
    # print("Number of")
    # print(speech_nums)
    return speech_nums

def silence_breaking(t_list):
    """
    """
    # breaks = {2.5 = {sophia = {4}, baylee = {3}}, 5 = {tina = 2}, 10 = {}, times = {sophia = [], tina = []}, total = {[]}}}
    breaks = {}
    for p_transcript in t_list:
        for idx, block in enumerate(p_transcript):
            if idx == 0:
                continue
            prev_tstamp = p_transcript[idx-1][1][1]
            prev_speaker = p_transcript[idx-1][2]
            curr_tstamp = block[1][0]
            curr_speaker = block[2]
            silence_dur = curr_tstamp - prev_tstamp
            if silence_dur >= timedelta(seconds=2.5):
                if prev_speaker not in breaks:
                    breaks[prev_speaker] = {"total-breaks":0, "total-starts":0, "avg-break":timedelta(seconds=0), 2.5:0, 5:0, 7.5:0, 10:0, "times":[]}
                if curr_speaker not in breaks:
                    breaks[curr_speaker] = {"total-breaks":0, "total-starts":0, "avg-break":timedelta(seconds=0), 2.5:0, 5:0, 7.5:0, 10:0, "times":[]}
                if silence_dur >= timedelta(seconds=5):
                    if silence_dur >= timedelta(seconds=7.5):
                        if silence_dur >= timedelta(seconds=10):
                            breaks[prev_speaker]["total-starts"] += 1
                            breaks[curr_speaker]["total-breaks"] += 1
                            breaks[curr_speaker][10] += 1
                            breaks[curr_speaker]["times"].append(silence_dur)
                        else:
                            breaks[prev_speaker]["total-starts"] += 1
                            breaks[curr_speaker]["total-breaks"] += 1
                            breaks[curr_speaker][7.5] += 1
                            breaks[curr_speaker]["times"].append(silence_dur)
                            
                    else:
                        breaks[prev_speaker]["total-starts"] += 1
                        breaks[curr_speaker]["total-breaks"] += 1
                        breaks[curr_speaker][5] += 1
                        breaks[curr_speaker]["times"].append(silence_dur)
                else:
                    breaks[prev_speaker]["total-starts"] += 1
                    breaks[curr_speaker]["total-breaks"] += 1
                    breaks[curr_speaker][2.5] += 1
                    breaks[curr_speaker]["times"].append(silence_dur)
    for participant in breaks:
        times_list = breaks[participant]["times"]
        if len(times_list) == 0:
            average = 0
            breaks[participant]["avg-break"] = average
            continue
        average = sum(times_list, timedelta()) / len(times_list)
        breaks[participant]["avg-break"] = average
    print(breaks)
    return breaks



        
def speech_durations(transcript_list):
    """
    Calculates duration each participant spoke and distribution of speaking time
    """
    durations = defaultdict(lambda: timedelta())
    for p_transcript in transcript_list:
        for block in p_transcript:
            tstamp1 = block[1][0]
            tstamp2 = block[1][1]
            partial_duration = abs(tstamp1 - tstamp2)
            durations[block[2]] += partial_duration

    # calculate distribution
    distribution = defaultdict(float)
    total_speaking_time = 0
    for participant in durations:
        total_speaking_time += int(durations[participant].total_seconds())
    for participant in durations:
        distribution[participant] = int(durations[participant].total_seconds()) / total_speaking_time

    return durations, distribution



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

    return render_template("index.html")


@app.route("/", methods=["POST"])
def dashboard():
    if request.method == "POST":
        result = request.form
        meeting_ids = result["meetids"]
        meeting_id_lst = meeting_ids.split(", ")
        print("Meeting IDs: ")
        print(meeting_id_lst)
        meetings_dict = get_recordings(meeting_id_lst)

        ### may change in prod. ###
        for meeting in meetings_dict:
            # print("Meeting: ")
            # print(meetings_dict[meeting])
            for meeting_inst in meetings_dict[meeting]:
                if meeting_inst == "topic" or meeting_inst == "host_id":
                    continue
                meeting_vals = meetings_dict[meeting][meeting_inst]
                # print("MEETING_VALS:")
                # print(meeting_vals)
                participants = get_participants(meeting_inst)
                print("PARTICIPANTS:")
                print(participants)
                if not participants:
                    continue
                meeting_vals["participants"] = participants
                t_list = meeting_vals["transcripts"]
                meeting_vals["instances"] = speech_instances(t_list)
                meeting_vals["durations"] = speech_durations(t_list)[0]
                meeting_vals["distribution"] = speech_durations(t_list)[1]
                meeting_vals["silence-breaking"] = silence_breaking(t_list)
                # print("Meeting Recording Data:")
                # print(meeting_vals)

        ### retroactively update metrics if any participant was excluded ###
        for meeting in meetings_dict:
            for meeting_inst in meetings_dict[meeting]:
                if meeting_inst == "topic" or meeting_inst == "host_id":
                    continue
                meeting_vals = meetings_dict[meeting][meeting_inst]
                if "instances" not in meeting_vals.keys():
                    continue
                instances = meeting_vals["instances"]
                durations = meeting_vals["durations"]
                distribution = meeting_vals["distribution"]
                participants = meeting_vals["participants"]
                # solves participants not in transcript
                for participant in participants.keys():
                    if participant not in instances.keys():
                        instances[participant] = 0
                    if participant not in durations.keys():
                        durations[participant] = timedelta(seconds=0)
                    if participant not in distribution.keys():
                        distribution[participant] = 0.00
                # print("UPDATED MEETING VALS: (LOOK HERE)")
                # print(meeting_vals)
                print("Participants:")
                print(meeting_vals["participants"])
        return render_template("dashboard.html", meetings = meetings_dict)

@app.route('/test')
def dashboard_test():
    test_meetings_dict = {}
    test_meetings_dict["1234567"] = {"host_id":"z8dfkgABBBBBBBfp8uQ", "topic":"REU Daily Zooms :)", "gkABCDEnCkPuA==":{"duration":13, "timedate":"2021-05-21 17:44:32 GMT", "participants":{"Baylee Keevan":"bjk9@rice.edu", "Sophia Rohlfsen":"", "Tina Wen":""}}}
    test_meetings_dict["9876543"] = {"host_id":"08HFJKANmn7asd", "topic":"TeamDNA Bi-Monthly Meetings", "KnmdHFAnsDHA==":{"duration":24, "timedate":"2021-06-07 18:54:25 GMT", "participants":{"Baylee Keevan":"bjk9@rice.edu", "Sophia Rohlfsen":"", "Tina Wen":"", "Margaret Beier":"", "Matthew Wettergreen":"", "Ashu Sabharwal":'', "Matt Barnett":""}}}
    test_meetings_dict["1234567"]["fjHEJmnfmdHf=="] = {"duration":57, "timedate":"2021-05-21 17:44:32 GMT", "participants":{"Baylee Keevan":"bjk9@rice.edu", "Sophia Rohlfsen":"", "Tina Wen":""}}
    test_meetings_dict["9876543"]["hjFDbEUTYZOs=="] = {"duration":46, "timedate":"2021-06-07 18:54:25 GMT", "participants":{"Baylee Keevan":"bjk9@rice.edu", "Sophia Rohlfsen":"", "Tina Wen":"", "Margaret Beier":"", "Matthew Wettergreen":"", "Ashu Sabharwal":'', "Matt Barnett":""}}
    
    return render_template("dashboard-test.html", meetings = test_meetings_dict)

### if someone didnt log in and had to rejoin, they will have two or more instances w/ different ids potentially
# gotta fix it, but uh oh what if two people have same name? thats why gotta check emails
# also retroactive must use email
# basically use email for everything paired w/ name
# idea: early on, instead of name as key/identifier, use tuple of name + email, everywhere, so you can check both

### idea
# zoom marketplace gives option to install app from a site page, so we can make
# a home/landing page with install button that they can bookmark and click button to install/authorize/start analyzing

if __name__ == "__main__":
    app.run(debug=True)