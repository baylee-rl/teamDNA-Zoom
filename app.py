import os
from os.path import basename
import zipfile
from dotenv import dotenv_values
import requests
from flask import Flask, render_template, request, session, redirect, url_for, json, send_file
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.dialects import postgresql
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from wtforms import StringField, PasswordField, BooleanField, DateField
from wtforms.validators import InputRequired, Length, Email, EqualTo
from base64 import b64encode
from datetime import date, datetime, timedelta
import urllib.request
import urllib.parse
from collections import defaultdict
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_user, login_required, UserMixin, logout_user, current_user
from flask_weasyprint import HTML, render_pdf
import igraph
import json
import random
from copy import deepcopy
config = dotenv_values(".env")


# PRODUCTION #
CLIENT_ID = os.environ.get('CLIENT_ID')
CLIENT_SEC = os.environ.get('CLIENT_SECRET')
SECRET_KEY = os.environ.get('SECRET_KEY')
REDIRECT = "https://teamdna-zoom.herokuapp.com/submit"
OAUTH = "https://zoom.us/oauth/authorize?response_type=code&client_id=" + CLIENT_ID + "&redirect_uri=" + REDIRECT
uri = os.environ.get('DATABASE_URL')
SQLALCHEMY_DATABASE_URI = uri.replace("postgres://", "postgresql://", 1)


# to-do:
# check if hash meeting works
# check database if hash is in there
# bug test everything again bc database got reset
# check participants everywhere
# if no meeting selected, dont submit (0 division error)


app = Flask(__name__)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
app.config['WTF_CSRF_ENABLED'] = False
db = SQLAlchemy(app)
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
app.secret_key = SECRET_KEY
login_manager.login_view = 'sign_in'
csrf = CSRFProtect(app)


# MODELS #

# association tables (many-to-many)
Permissions = db.Table('permissions',
    db.Column('id', db.Integer, primary_key=True, autoincrement=True),
    db.Column('user_id', db.Integer, db.ForeignKey('users.id')),
    db.Column('meeting_id', db.String(30), db.ForeignKey('meetings.id')))

MeetingInstParticipants = db.Table('meetinginstparticipants',
    db.Column('id', db.Integer, primary_key=True, autoincrement=True),
    db.Column('uuid', db.String(30), db.ForeignKey('meeting_insts.uuid')),
    db.Column('participant_id', db.String(30), db.ForeignKey('participants.id')))


class User(db.Model, UserMixin):
    __tablename__ = "users"

    # columns
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    pull_meetings = db.relationship('Meeting', secondary=Permissions, back_populates='users')
    sub_meetings = db.relationship('Meeting', back_populates="host")

    def __init__(self, email, password_hash, role):
        self.email = email
        self.password_hash = password_hash
        self.role = role
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Meeting(db.Model):
    __tablename__ = "meetings"

    id = db.Column(db.String(30), primary_key=True)
    topic = db.Column(db.String(120))
    host_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    host = db.relationship("User", back_populates="sub_meetings")
    meeting_insts = db.relationship("Meeting_Inst", back_populates="meeting")
    users = db.relationship('User', secondary=Permissions, back_populates='pull_meetings')

    def __init__(self, id, topic):
        self.id = id
        self.topic = topic

class Meeting_Inst(db.Model):
    __tablename__ = "meeting_insts"

    uuid = db.Column(db.String(30), primary_key=True)
    meeting_id = db.Column(db.String(30), db.ForeignKey('meetings.id'))
    meeting = db.relationship("Meeting", back_populates="meeting_insts")
    duration = db.Column(db.Integer)
    start_time = db.Column(db.String(30))    
    participants = db.relationship("Participant", secondary=MeetingInstParticipants)
    transcripts = db.relationship("Transcript")

    def __init__(self, uuid, meeting_id, duration, start_time):
        self.uuid = uuid
        self.meeting_id = meeting_id
        self.duration = duration
        self.start_time = start_time

class Participant(db.Model):
    __tablename__ = "participants"

    id = db.Column(db.String(30), primary_key=True)
    name = db.Column(db.String(30))
    email = db.Column(db.String(120))
    meeting_insts = db.relationship('Meeting_Inst', secondary=MeetingInstParticipants, back_populates='participants')
    aliases = db.relationship("Alias", back_populates="participant")

    def __init__(self, id, name, email):
        self.id = id
        self.name = name
        self.email = email

class Alias(db.Model):
    __tablename__ = "aliases"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    alias = db.Column(db.String(30))
    participant_id = db.Column(db.String(30), db.ForeignKey('participants.id'))
    participant = db.relationship("Participant", back_populates = "aliases")

    def __init__(self, alias):
        self.alias = alias

class Transcript(db.Model):
    __tablename__ = 'transcripts'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    uuid = db.Column(db.String(30), db.ForeignKey('meeting_insts.uuid'))
    transcript = db.Column(db.Text)
    transcript_blocks = db.relationship("Transcript_Block", order_by='Transcript_Block.sequence')

    def __init__(self, uuid, transcript):
        self.uuid = uuid
        self.transcript = transcript

class Transcript_Block(db.Model):
    __tablename__ = "transcript_blocks"
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    transcript_id = db.Column(db.Integer, db.ForeignKey('transcripts.id'))
    sequence = db.Column(db.Integer)
    starttime = db.Column(postgresql.INTERVAL)
    endtime = db.Column(postgresql.INTERVAL)
    speaker = db.Column(db.String(30))
    speech = db.Column(db.String(500))

    def __init__(self, transcript_id):
        self.transcript_id = transcript_id

with app.app_context():
    db.create_all()

# FORMS #

class LoginForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email')])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=30)])   
    remember = BooleanField('remember me')

class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email')])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=30)])   

class PasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[InputRequired(), Length(min=8, max=30), EqualTo('confirm', 'Passwords must match')])
    confirm = PasswordField('Confirm New Password')

class MeetingSubForm(FlaskForm):
    meetid = StringField('meetid', validators=[InputRequired()])
    recipient = StringField('recipient', validators=[InputRequired(), Email(message="Invalid email")])
    date = StringField('date', render_kw={'placeholder': 'MM/DD/YY'}, validators=[InputRequired()])

# FUNCTIONS #

# authentication

def api_refresh_check(response_data):
    """
    checks response from an api call to see if refresh needed
    """
    did_refresh = False
    try:
        if response_data["code"] == 124:
            try:
                refresh_token()
                did_refresh = True
            except:
                return None
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

def refresh_token(r_token):
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


# retrieval

def get_participants(uuid):
    """
    Given a UUID, retrieves the participants list from Zoom and adds to DB
    Also returns a list of participant names
    """
    authorization = "Bearer " + session['a_token']
    headers = {"Authorization": authorization}
    print(uuid)
    if (uuid[0] == "/") or ("//" in uuid):
        print("Encoding...")
        uuid = urllib.parse.quote(uuid, safe='')
        uuid = urllib.parse.quote(uuid, safe='')
    url = "https://api.zoom.us/v2/past_meetings/" + uuid + "/participants"
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

    print("Participants Data:")
    print(participants_data['participants'])

    if len(participants_data["participants"]) == 0:
        return "error"

    new_participants = []
    for participant in participants_data['participants']:
        if "#" in participant["name"]:
            name = participant['name'].replace("#", ",")
        else:
            name = participant["name"]
        if name in new_participants:
            continue
        id = participant["id"]
        email = participant["user_email"]
        new_participants.append(name)

        print(name, id, email)

        new_participant = Participant.query.filter_by(email=email).first()

        print('Participant: ')
        print(new_participant)

        meeting_inst = Meeting_Inst.query.filter_by(uuid=uuid).first()

        print('Meeting: ')
        print(meeting_inst)

        if new_participant and email != "":
            print('case 1')
            meeting_inst.participants.append(new_participant)
            if new_participant.name != name and name not in [x.alias for x in new_participant.aliases]:
                print('adding alias...')
                print(new_participant.name)
                print(name)
                new_participant.aliases.append(Alias(name))
        elif Participant.query.filter_by(name=name).first():
            print('case 2')
            meeting_inst.participants.append(Participant.query.filter_by(name=name).first())
            if Participant.query.filter_by(name=name).first().email == "":
                Participant.query.filter_by(name=name).first().email = email
        elif Alias.query.filter_by(alias=name).first():
            print('case 3')
            alias = Alias.query.filter_by(alias=name).first()
            a_participant = Participant.query.filter_by(id=alias.participant_id).first()
            meeting_inst.participants.append(a_participant)
        else:
            print('case 4')
            print(id, email, name)
            meeting_inst.participants.append(Participant(id, name, email))
        
    print("All participants added to database")
    db.session.commit()
    return new_participants


def get_recordings(meeting_id, startdate, enddate):
    """
    given a meeting ID, retrieves all information from Zoom and adds information to respective DB tables
    returns a dictionary mapping meeting IDs to UUIDs, host_id, topic, and UUIDs map to start_time, duration, and participants (for display)
    startdate should be a timedelta within 30 days in isoformat
    """
    print("Using access token: " + session['a_token'])
    authorization = "Bearer " + session['a_token']

    headers = {"Authorization": authorization}

    # if user has too many meetings, not all will be displayed -- see documentation
    # can only display last 30 days of meetings -- api limitation
    # one_month = (startdate+timedelta(days=30)).isoformat()
    
    url = "https://api.zoom.us/v2/users/me/recordings?from=" + startdate + "&to=" + enddate
    response = requests.get(url, headers=headers)
    data = response.json()
    did_refresh = api_refresh_check(data)
    if did_refresh:
        authorization = "Bearer " + session['a_token']
        headers = {"Authorization": authorization}
        response = requests.get(url, headers=headers)
        data = response.json()
    elif did_refresh == None:
        return None

    meetings = data["meetings"]
    meetings_dict = {meeting_id : {}}
    m_data = meetings_dict[meeting_id]


    for meeting in meetings:
        # finds all meeting instances matching meeting ID
        if str(meeting['id']) == meeting_id:
            topic = meeting['topic']

            m_data['topic'] = topic

            #add to new meetings to meetings table
            if Meeting.query.filter_by(id=meeting_id).first() == None:
                new_meeting = Meeting(meeting_id, topic)
                db.session.add(new_meeting)
                db.session.commit()

            uuid = meeting['uuid']

            print(uuid)

            m_data[uuid] = {}

            duration = meeting['duration']
            timedate = meeting["start_time"]
            timedate = timedate.replace("T", " ")
            timedate = timedate.replace("Z", " GMT")

            m_data[uuid]['duration'] = duration
            m_data[uuid]['start_time'] = timedate

            transcripts = []
            transcript_found = False
            for file in meeting['recording_files']:
                if file["file_type"] == "TRANSCRIPT":
                    print("Transcript found")
                    transcript_found = True
                    transcripts.append(file["download_url"])
            if transcript_found == True:
                # add UUIDs/Meeting Insts for meetings w/ transcripts available
                if Meeting_Inst.query.filter_by(uuid=uuid).first() == None:
                    meeting_inst = Meeting_Inst(uuid, meeting_id, duration, timedate)
                    db.session.add(meeting_inst)

                    print("UUID successfully added")

                    # retrieve participants and add to DB
                    participants = get_participants(uuid)
                    if participants == 'error':
                        Meeting_Inst.query.filter_by(uuid=uuid).delete()
                        db.session.commit()
                        continue
                    else:
                        m_data[uuid]['participants'] = participants
                        db.session.commit()

                # Parse and add to DB any new transcripts
                if Transcript.query.filter_by(uuid=uuid).all() == []:
                    print("no transcripts yet :)")
                    for file in transcripts:
                        print("Downloading...")

                        dl_url = file + "?access_token=" + session['a_token']
                        response = requests.get(dl_url, stream=True)

                        #add transcript to DB
                        transcript = Transcript(uuid, response.text)
                        print(transcript)
                        db.session.add(transcript)
                        db.session.commit()
                        print("Transcript added to DB")
                        p_transcript = parse_transcript(transcript.id, response.text)

                        #add parsed transcript to DB
                        db.session.add_all(p_transcript)
                        db.session.commit()

    return 

def host_retrieve():
    """
    retrieves submitted meeting info for current user to display
    returns a dictionary containing each meeting ID mapped to its topic and UUIDs,
    and each UUID mapped to its start_time, duration, and participants' names
    """
    curr_id = current_user.id
    hosted_meetings = Meeting.query.filter_by(host_id=curr_id).all()
    meetings_dict = {}
    for meeting in hosted_meetings:
        meeting_id = meeting.id
        meetings_dict[meeting_id] = {}
        meetings_dict[meeting_id]["topic"] = meeting.topic

        # find all UUIDs
        uuids = Meeting_Inst.query.filter_by(meeting_id=meeting.id).all()
        for inst in uuids:
            uuid = inst.uuid
            meetings_dict[meeting_id][uuid] = {}
            meetings_dict[meeting_id][uuid]["start_time"] = inst.start_time
            meetings_dict[meeting_id][uuid]["duration"] = inst.duration
            meetings_dict[meeting_id][uuid]["participants"] = []
            for participant in inst.participants:
                meetings_dict[meeting_id][uuid]["participants"].append(participant.name)

    return meetings_dict

def host_refresh():
    curr_id = current_user.id
    hosted_meetings = Meeting.query.filter_by(host_id=curr_id).all()

    for meeting in hosted_meetings:
        get_recordings(meeting.id)

def instructor_retrieve():
    """
    """
    if current_user.role not in ["Instructor", "Admin"]:
        return None

    curr_id = current_user.id
    # retrieve all meetings w/ current user as recipient
    received_meetings = Meeting.query.filter(Meeting.users.any(id=curr_id)).all()

    meetings_dict = {}
    for meeting in received_meetings:
        meeting_id = meeting.id
        meetings_dict[meeting_id] = {}
        meetings_dict[meeting_id]["topic"] = meeting.topic
        host = User.query.filter_by(id=meeting.host_id).first()
        meetings_dict[meeting_id]["host"] = host.email

        # find all UUIDs
        uuids = Meeting_Inst.query.filter_by(meeting_id=meeting.id).all()
        for inst in uuids:
            uuid = inst.uuid
            meetings_dict[meeting_id][uuid] = {}
            meetings_dict[meeting_id][uuid]["start_time"] = inst.start_time
            meetings_dict[meeting_id][uuid]["duration"] = inst.duration
            meetings_dict[meeting_id][uuid]["participants"] = []
            for participant in inst.participants:
                meetings_dict[meeting_id][uuid]["participants"].append(participant.name)

    return meetings_dict

def transcript_write_to_file(transcript_id):
    transcript = Transcript.query.filter_by(id=transcript_id).first()
    uuid = transcript.uuid
    transcript = transcript.transcript
    meeting_inst = Meeting_Inst.query.filter_by(uuid=uuid).first()
    timedate = meeting_inst.start_time

    with open("static/client/txt/%s_%d.txt" % (timedate, transcript_id), "w") as file:
        file.write(transcript)

    return "static/client/txt/%s_%d.txt" % (timedate, transcript_id)

# parsing

def parse_transcript(transcript_id, transcript):
    """
    Inputs:
        transcript, a string
    Returns a list of Transcript_Block objects
    """
    split_transcript = transcript.split("\r\n")
    p_transcript = []
    # print(split_transcript)
    for idx, line in enumerate(split_transcript):
        if idx == 0:
            continue
        elif line == "WEBVTT":
            continue
        block = Transcript_Block(transcript_id)
        if line == "":
            if idx == len(split_transcript) - 1 or idx == len(split_transcript) - 2:
                continue
            block.sequence = int(split_transcript[idx + 1])
            timestamp = split_transcript[idx + 2].split(" --> ")
            t1 = datetime.strptime(timestamp[0], "%H:%M:%S.%f")
            t2 = datetime.strptime(timestamp[1], "%H:%M:%S.%f")
            block.starttime = timedelta(hours=t1.hour, minutes=t1.minute, seconds=t1.second)
            block.endtime = timedelta(hours=t2.hour, minutes=t2.minute, seconds=t2.second)

            name_text = split_transcript[idx + 3].split(": ")
            if len(name_text) == 1:
                if idx == 1:
                    continue

                text = split_transcript[idx + 3].split(": ")[0]
                for line in reversed(split_transcript[:(idx + 1)]):
                    if len(line.split(": ")) == 2:
                        name = line.split(": ")[0]
                        break
                    else:
                        continue
                block.speaker = name
                block.speech = text
            else:
                block.speaker = name_text[0]
                block.speech = name_text[1]
            p_transcript.append(block)
        else:
            pass

    return p_transcript

def meetings_compilation(given_uuids, meetings_dict):
    """
    Inputs: 
        given_uuids -- a list of uuids collected from dashboard inputs 
        meetings_dict -- dictionary of meeting information 
    Returns:
        transcript_collection -- a list of trascripts form selected meetings formatted so that 
        it can be inputted into any analysis function 
    """
    # list of p_transcript blocks, no seperation between uuids
    # will be formatted so that it can be inputted as "transcript_list" in analysis functions
    transcript_collection = []
    for meeting in meetings_dict:
        for uuid in meetings_dict[meeting].keys():
            if uuid in given_uuids:
                # add to t_list
                for transcript in meetings_dict[meeting][uuid]["transcripts"]:
                    transcript_instance = transcript
                    transcript_collection.append(transcript)

    return transcript_collection

# analysis

# def get_graph(transcript_list):
    """
    # create adjacency matrix as dict
    ad_mat = {}
    for p_transcript in transcript_list:
        for block in range(len(p_transcript)-1):
            if p_transcript[block][2] not in ad_mat:
                ad_mat[p_transcript[block][2]] = {}
            if p_transcript[block + 1][2] not in ad_mat[p_transcript[block][2]]:
                # initialize one turn 
                ad_mat[p_transcript[block][2]][p_transcript[block + 1][2]] = 1
            else: 
                ad_mat[p_transcript[block][2]][p_transcript[block + 1][2]] += 1
                
    # recreate the matrix as list of list 
    # use igraph.Graph.Adjacency for adjacency --> graph     Weighted!!!!
    # rename nodes from dict indexes/names 

    """


def speech_instances(transcript_list, participants):
    """
    """
    speech_nums = {}

    for participant in participants:
        speech_nums[participant] = 0

    for p_transcript in transcript_list:
        for block in p_transcript:
            if block.speaker in speech_nums.keys():
                speech_nums[block.speaker] += 1
            else:
                speech_nums[block.speaker] = 1

    speech_nums_copy = speech_nums.copy()
    for participant in speech_nums_copy.keys():
        p = Participant.query.filter_by(name=participant).first()
        if p:
            aliases = [x.alias for x in p.aliases]
            for alias in aliases:
                if alias in speech_nums.keys():
                    speech_nums[participant] += speech_nums[alias]
                    del speech_nums[alias]

    return speech_nums

def silence_breaking(transcript_list):
    """
    """
    # breaks = {2.5 = {sophia = {4}, baylee = {3}}, 5 = {tina = 2}, 10 = {}, times = {sophia = [], tina = []}, total = {[]}}}
    breaks = {}

    for p_transcript in transcript_list:
        for idx, block in enumerate(p_transcript):
            if idx == 0:
                continue
            prev_tstamp = p_transcript[idx-1].endtime
            prev_speaker = p_transcript[idx-1].speaker
            curr_tstamp = block.starttime
            curr_speaker = block.speaker
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

    breaks_copy = breaks.copy()
    for participant in breaks_copy.keys():
        p = Participant.query.filter_by(name=participant).first()
        if p:
            aliases = [x.alias for x in p.aliases]
            for alias in aliases:
                if alias in breaks.keys():
                    for key in breaks[participant].keys():
                        if key == "times":
                            breaks[participant]["times"].extend(breaks[alias]["times"])
                        else:
                            breaks[participant][key] += breaks[alias][key]
                    del breaks[alias]

    for participant in breaks:
        times_list = breaks[participant]["times"]
        if len(times_list) == 0:
            average = 0
            breaks[participant]["avg-break"] = average
            continue
        average = sum(times_list, timedelta()) / len(times_list)
        breaks[participant]["avg-break"] = average
    # print(breaks)
    return breaks
       
def speech_durations(transcript_list, participants):
    """
    Calculates duration each participant spoke and distribution of speaking time
    """
    durations = {}

    for participant in participants:
        durations[participant] = timedelta(0)

    for p_transcript in transcript_list:
        for block in p_transcript:
            tstamp1 = block.starttime
            tstamp2 = block.endtime
            partial_duration = abs(tstamp1 - tstamp2)
            if block.speaker in durations.keys():
                durations[block.speaker] += partial_duration
            else:
                durations[block.speaker] = partial_duration

    durations_copy = durations.copy()
    for participant in durations_copy.keys():
        p = Participant.query.filter_by(name=participant).first()
        if p:
            aliases = [x.alias for x in p.aliases]
            for alias in aliases:
                if alias in durations.keys():
                    durations[participant] += durations[alias]
                    del durations[alias]

    # calculate distribution
    distribution = defaultdict(float)
    total_speaking_time = 0
    for participant in durations:
        total_speaking_time += int(durations[participant].total_seconds())

    for participant in durations:
        distribution[participant] = round(int(durations[participant].total_seconds()) / total_speaking_time, 4)

    return durations, distribution

def get_graph(transcript_list, participants):
    # create adjacency matrix as dict
    ad_mat = {}
    ad_list = []
    index = 0
    edge_tot = 0
    for p_transcript in transcript_list:
        for idx, block in enumerate(p_transcript):
            if idx == len(p_transcript) - 1:
                continue
            curr_speaker = block.speaker
            next_speaker = p_transcript[idx+1].speaker
            if curr_speaker not in ad_mat:
                ad_mat[curr_speaker] = {}
                ad_mat[curr_speaker]['index'] = index
                index += 1
            if next_speaker not in ad_mat[curr_speaker]:
                # initialize one turn and the edge
                if curr_speaker != next_speaker:
                    edge_tot += 1
                ad_mat[curr_speaker][next_speaker] = 1
            else:
                ad_mat[curr_speaker][next_speaker] += 1
            if next_speaker not in ad_mat:
                ad_mat[next_speaker] = {'index' : index}
                index += 1
    for speaker_1 in ad_mat:
        ad_list.append([])
    for i in range(len(ad_list)):
        for speaker_1 in ad_mat:
            ad_list[i].append(0)
    # print (ad_list)
    for speaker_1 in ad_mat:
        for speaker_2 in ad_mat[speaker_1]:
            if speaker_2 == 'index':
                continue
            ad_list[ad_mat[speaker_1]['index']][ad_mat[speaker_2]['index']] = ad_mat[speaker_1][speaker_2]
    g = igraph.Graph.Weighted_Adjacency(ad_list, mode='directed', attr='weight', loops=True)
    # retroactive addition of non-speakers
    speaker_list = []
    for key in ad_mat.keys():
        speaker_list.append(key)
    for i in range(len(g.vs)):
            # print (ad_mat.keys())
            g.vs[i]["name"] = speaker_list[i]
    for participant in participants:
        if participant not in speaker_list:
            g.add_vertex(name=participant)
            #g.add_edge(participant, ad_mat.keys[0] , weight=None)

    ad_mat_copy = deepcopy(ad_mat)
    for speaker1 in ad_mat_copy.keys():
        for speaker2 in ad_mat_copy[speaker1].keys():
            if speaker2 == "index":
                continue
            p = Participant.query.filter_by(name=speaker2).first()
            if p:
                aliases = [x.alias for x in p.aliases]
                for alias in aliases:
                    if alias in ad_mat[speaker1].keys():
                        ad_mat[speaker1][speaker2] += ad_mat[speaker1][alias]
                        del ad_mat[speaker1][alias]
            else:       
                for participant in participants:
                    p = Participant.query.filter_by(name=participant).first()
                    if p:
                        aliases = [x.alias for x in p.aliases]
                        # change the name of the inner key to its "real name" if it is an alias
                        if speaker2 in aliases:
                            if participant not in ad_mat[speaker1].keys():
                                ad_mat[speaker1][participant] = ad_mat[speaker1][speaker2]
                                del ad_mat[speaker1][speaker2]

    for speaker1 in ad_mat_copy.keys():
        p = Participant.query.filter_by(name=speaker1).first()
        if p:
            aliases = [x.alias for x in p.aliases]
            for alias in aliases:
                if alias in ad_mat.keys():
                    for key in ad_mat[alias]:
                        if key in ad_mat[speaker1].keys():
                            ad_mat[speaker1][key] += ad_mat[alias][key]
                        else:
                            ad_mat[speaker1][key] = ad_mat[alias][key]
                    del ad_mat[alias]
                        
    print(ad_mat)
    # edge_density = edge_tot/(len(participants)*(len(participants)-1))
    edge_density = 0
    # centr_degree = edge_tot
    centr_degree = 0

    return ad_mat, ad_list, g, edge_density, centr_degree

def strength(g, ad_mat):
    degree_mat = {}
    for participant in g.vs['name']:
        degree_mat[participant] = 0
    for speaker1 in ad_mat:
        for speaker2 in ad_mat[speaker1]:
            if speaker2 == 'index' or speaker1 == speaker2:
                continue
            degree_mat[speaker1] += ad_mat[speaker1][speaker2]
            degree_mat[speaker2] += ad_mat[speaker1][speaker2]
    return degree_mat

def graph_to_json(ad_mat, degree_mat):
    nodes = []
    edges = []
    for idx, node in enumerate(degree_mat.keys()):
        node_vals = {"id":node, "label": node, "x": random.random(), "y": random.random(), "size": degree_mat[node]}
        nodes.append(node_vals)
        try:
            for idx2, node2 in enumerate(ad_mat[node].keys()):
                if node2 == "index":
                    continue
                edge_name = node + node2
                size = ad_mat[node][node2]
                # print("Size: " + str(size))
                edge_vals = {"id" : edge_name, "label": size, "source" : node, "target" : node2, "type": "curvedArrow"}
                edges.append(edge_vals)
        except KeyError:
            continue
    
    fh = open("static/client/json/network.json", "w")
    fh.write(json.dumps({"nodes": nodes, "edges": edges}))
    fh.close()

    return {"nodes": nodes, "edges": edges}


# FLASK GLOBALS #
@app.context_processor
def inject_redirect_url():
    return dict(redirect=OAUTH)


# LOGIN MANAGER #
@login_manager.user_loader
def load_user(user_id):
    """
    must take unicode user id
    """
    user = User.query.filter_by(id=user_id).first()
    if user:
        return user
    else:
        return None


# ROUTING #

"""
@app.route("/example", methods=["GET", "POST"])
def example():
    return render_template("example.html")
"""

@app.route("/")
def home_redirect():
    return redirect(url_for('home'))

@app.route("/home")
def home():
    return render_template("home.html")

@app.route("/sign-up", methods=["GET", "POST"])
def sign_up():
    form = RegisterForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        password_hash = generate_password_hash(password)

        other_user = User.query.filter_by(email=email).first()
        if other_user:
            return render_template("sign-up.html", form=form, duplicate_email=True)

        new_user = User(email, password_hash, "User")
        db.session.add(new_user)
        db.session.commit()

        login_user(User.query.filter_by(email=email).first(), force=True)

        return render_template("start-1.html")
    return render_template("sign-up.html", form=form)

@app.route("/sign-in", methods=["GET", "POST"])
def sign_in():
    form = LoginForm()
    if form.validate_on_submit():
        email_entered = form.email.data
        password_entered = form.password.data
        remember=form.remember.data
        user = User.query.filter_by(email=email_entered).first()
        if user is not None and check_password_hash(user.password_hash, password_entered):
            login_user(user, force=True, remember=remember)
            return render_template("sign-in-success.html")
    elif request.method == "POST":
        user = User.query.filter_by(email=form.email.data).first()
        if user == None:
            return render_template("sign-in.html", form=form, error='wrong-email')
        else:
            return render_template("sign-in.html", form=form, error='wrong-pass')
    return render_template("sign-in.html", form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/start-1')
@login_required
def start_1():
    return render_template("start-1.html")

@app.route('/start-2')
@login_required
def start_2():
    return render_template("start-2.html")

@app.route('/faq')
@login_required
def faq():
    return render_template("faq.html")

@app.route('/contact-us')
def contact():
    return render_template("contact.html")

@app.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    form = PasswordForm()
    if form.validate_on_submit():
        user = current_user
        user.password_hash = generate_password_hash(form.password.data)
        db.session.commit()
        return render_template("account.html", form=form, did_update=True)
    return render_template("account.html", form=form)

@app.route("/submit", methods=["GET", "POST"])
@login_required
def submit():
    form = MeetingSubForm()

    if form.validate_on_submit():
        print('success :)')
        meeting_id = form.meetid.data
        recipient_email = form.recipient.data
        startdate = form.date.data
        recipient = User.query.filter_by(email=recipient_email).first()
        if recipient is None:
            return render_template('submit.html', form=form, msg="no-user")
        elif recipient.role not in ["Instructor", "Admin"]:
            return render_template('submit.html', form=form, msg='not-instructor')

        # removes whitespace if present
        meeting_id = meeting_id.replace(" ", "")
        print("Meeting ID: " + meeting_id)

        try:
            startdate = datetime.strptime(startdate, '%m/%d/%y').date()
        except:
            return render_template('submit.html', form=form, msg='invalid-date')
        today = date.today()
        days_remaining = today - startdate
        currdate = startdate

        while days_remaining.days > 0:
            enddate = (currdate+timedelta(days=30))
            get_recordings(meeting_id, currdate.isoformat(), enddate.isoformat())
            currdate = enddate
            days_remaining -= timedelta(days=30)
            if (days_remaining - timedelta(days=30)).days < 0:
                enddate = currdate + timedelta(days=days_remaining.days)
                get_recordings(meeting_id, currdate.isoformat(), enddate.isoformat())
                days_remaining -= days_remaining

        # adds meeting ID to current_user's sub_meetings if new
        if meeting_id not in [meeting.id for meeting in current_user.sub_meetings]:
            meeting = Meeting.query.filter_by(id=meeting_id).first()
            current_user.sub_meetings.append(meeting)
            db.session.commit()

        # adds meeting ID to recipient's permissions/pull_meetings if new
        if meeting_id not in [meeting.id for meeting in recipient.pull_meetings]:
            meeting = Meeting.query.filter_by(id=meeting_id).first()
            recipient.pull_meetings.append(meeting)
            db.session.commit()

        # retrieves info from sub_meetings for current_user
        meetings_dict = host_retrieve()
        print(meetings_dict)

        return render_template("submit.html", form=form, refreshed=False, new_sub=True, meetings=meetings_dict)

    try:
        auth_code = request.args['code']
        try:
            if session['auth_code'] == auth_code:
                access_token = session['access_token']
                r_token = session['r_token']
                print("prev tokens retrieved")
            else:
                session['auth_code'] = auth_code
                access_token, r_token = get_access_token(auth_code)
                print("fresh tokens retrieved")
        except:
            session['auth_code'] = auth_code
            access_token, r_token = get_access_token(auth_code)
            print("fresh tokens retrieved")
    except:
        print('no code or tokens, redirecting')
        return redirect(OAUTH)

    print("Authorization code: " + auth_code)
    
    print("Access token: " + access_token)
    print("Refresh token: " + r_token)

    session['a_token'] = access_token
    session['r_token'] = r_token

    # retrieves info from sub_meetings for current_user
    meetings_dict = host_retrieve()

    return render_template("submit.html", form=form, meetings=meetings_dict, errors=form.errors)

@app.route('/refresh', methods=["GET", "POST"])
@login_required
def refresh():
    form = MeetingSubForm()
    if request.method =="POST":
        host_refresh()
        meetings_dict = host_retrieve()
        print("success!")
        return render_template("submit.html", form=form, refreshed=True, meetings=meetings_dict)

    try:
        auth_code = request.args['code']
        try:
            if session['auth_code'] == auth_code:
                access_token = session['access_token']
                r_token = session['r_token']
                print("prev tokens retrieved")
            else:
                session['auth_code'] = auth_code
                access_token, r_token = get_access_token(auth_code)
                print("fresh tokens retrieved")
        except:
            session['auth_code'] = auth_code
            access_token, r_token = get_access_token(auth_code)
            print("fresh tokens retrieved")
    except:
        print('no code or tokens, redirecting')
        return redirect(OAUTH)

    print("Authorization code: " + auth_code)
    
    print("Access token: " + access_token)
    print("Refresh token: " + r_token)

    session['a_token'] = access_token
    session['r_token'] = r_token

    # retrieves info from sub_meetings for current_user
    meetings_dict = host_retrieve()

    return render_template("submit.html", form=form, meetings=meetings_dict)

@app.route('/dashboard', methods=["GET", "POST"])
@login_required
def dashboard():
    if current_user.role == "Instructor" or current_user.role == "Admin":
        meetings_dict = instructor_retrieve()
        print(meetings_dict)

        if request.method == 'POST':
            uuids = request.form.getlist('checkbox')
            if len(uuids) == 0:
                return render_template("dashboard.html", meetings=meetings_dict, error="no-meet")
            if 'analyze' in request.form:
                print(uuids)

                master_t_list = []
                participants = []
                for uuid in uuids:
                    meeting_inst = Meeting_Inst.query.filter_by(uuid=uuid).first()
                    # print(meeting_inst)
                    t_list = Transcript.query.filter_by(uuid=uuid).all()
                    p_list = meeting_inst.participants

                    for participant in p_list:
                        if participant not in participants:
                            participants.append(participant.name)

                    # print(t_list)
                    for idx, t in enumerate(t_list):
                        p_t_list = Transcript_Block.query.filter_by(transcript_id=t.id).all()
                        # print(p_t_list)
                        t_list[idx] = p_t_list
                    master_t_list.extend(t_list)
                # print(master_t_list)


                a_dict = {}
                a_dict["speech_instances"] = speech_instances(master_t_list, participants)
                a_dict["silence_breaking"] = silence_breaking(master_t_list)
                a_dict["speech_durations"], a_dict["speech_distribution"] = speech_durations(master_t_list, participants)
                a_dict["adjacency_mat"], a_dict["adjacency_lst"], a_dict["network_graph"], a_dict["edge_density"], a_dict["center_deg"]  = get_graph(master_t_list, participants)

                distribution_labels = a_dict["speech_distribution"].keys()
                distribution_values = a_dict["speech_distribution"].values()
                distribution_values = [round(x * 100, 2) for x in distribution_values]

                distribution = [list(distribution_labels), list(distribution_values)]

                instance_labels = a_dict["speech_instances"].keys()
                instance_values = a_dict["speech_instances"].values()

                instances = [list(instance_labels), list(instance_values)]

                degree_mat = strength(a_dict["network_graph"], a_dict["adjacency_mat"])
                graph_to_json(a_dict["adjacency_mat"], degree_mat)

                print(speech_instances(master_t_list, participants))
                # print(silence_breaking(master_t_list))
                # print(speech_durations(master_t_list, participants))
                # print(speech_durations(master_t_list, participants))

                """
                if 'download-checked':
                    html = render_template('analysis.html', name=name)
                    return render_pdf(HTML(string=html))
                """

                return render_template("analysis.html", analysis=a_dict, distribution=distribution, instances=instances)

            elif 'download' in request.form:
                print(uuids)

                id_list = []

                for uuid in uuids:
                    meeting_inst = Meeting_Inst.query.filter_by(uuid=uuid).first()
                    t_list = meeting_inst.transcripts
                    for t in t_list:
                        id_list.append(t.id)

                print(id_list)

                filenames = []

                for t_id in id_list:
                    filenames.append(transcript_write_to_file(t_id))

                print(filenames)

                with zipfile.ZipFile('static/client/zip/transcripts.zip','w', zipfile.ZIP_DEFLATED) as zf: 
                    for file in filenames:
                        print('starting...')
                        print(file)
                        zf.write(file, basename(file))

                print('success')
                return send_file('static/client/zip/transcripts.zip', as_attachment=True)
        

        return render_template("dashboard.html", meetings=meetings_dict)
    else:
        return redirect(url_for('home'))

@app.route('/admin')
@login_required
def admin():
    if current_user.role == "Admin":

        users = User.query.all()

        return render_template("admin.html", users=users)
    else:
        return redirect(url_for('home'))

@app.route('/test')
def submit_test():
    test_meetings_dict = {}
    test_meetings_dict["1234567"] = {"host_id":"z8dfkgABBBBBBBfp8uQ", "topic":"REU Daily Zooms :)", "gkABCDEnCkPuA==":{"duration":13, "timedate":"2021-05-21 17:44:32 GMT", "participants":{"Baylee Keevan":"bjk9@rice.edu", "Sophia Rohlfsen":"", "Tina Wen":""}}}
    test_meetings_dict["9876543"] = {"host_id":"08HFJKANmn7asd", "topic":"TeamDNA Bi-Monthly Meetings", "KnmdHFAnsDHA==":{"duration":24, "timedate":"2021-06-07 18:54:25 GMT", "participants":{"Keevan, Baylee Jade":"bjk9@rice.edu", "Sophia Rohlfsen":"", "Tina Wen":"", "Margaret Beier":"", "Matthew Wettergreen":"", "Ashu Sabharwal":'', "Matt Barnett":""}}}
    test_meetings_dict["1234567"]["fjHEJmnfmdHf=="] = {"duration":57, "timedate":"2021-05-21 17:44:32 GMT", "participants":{"Baylee Keevan":"bjk9@rice.edu", "Sophia Rohlfsen":"", "Tina Wen":""}}
    test_meetings_dict["9876543"]["hjFDbEUTYZOs=="] = {"duration":46, "timedate":"2021-06-07 18:54:25 GMT", "participants":{"Baylee Keevan":"bjk9@rice.edu", "Sophia Rohlfsen":"", "Tina Wen":"", "Margaret Beier":"", "Matthew Wettergreen":"", "Ashu Sabharwal":'', "Matt Barnett":""}}
    
    return render_template("submit-test.html", meetings = test_meetings_dict)


if __name__ == "__main__":
    app.run(debug=True)


# zoom makes comma into hash for participant?!
# also sophia is showing up under participants for a different
# sqlalchemy.orm.exc.FlushError: Can't flush None value found in collection User.sub_meetings
# instructions in context (on page) 
