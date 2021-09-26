import os
from os.path import basename
import zipfile
from dotenv import dotenv_values
import requests
from flask import Flask, render_template, request, session, redirect, url_for, json, send_file
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.dialects import postgresql
from sqlalchemy import asc
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
import igraph
import json
import random
from copy import deepcopy
import csv
config = dotenv_values(".env")


# PRODUCTION #
CLIENT_ID = os.environ.get('CLIENT_ID')
CLIENT_SEC = os.environ.get('CLIENT_SECRET')
SECRET_KEY = os.environ.get('SECRET_KEY')
REDIRECT = "https://teamdna-zoom.herokuapp.com/submit"
OAUTH = "https://zoom.us/oauth/authorize?response_type=code&client_id=" + CLIENT_ID + "&redirect_uri=" + REDIRECT
uri = os.environ.get('DATABASE_URL')
SQLALCHEMY_DATABASE_URI = uri.replace("postgres://", "postgresql://", 1)



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
    Checks the response from a Zoom API call to see if the token needs to be refreshed

    Inputs:
        response_data -- respone object from a Zoom API call
    
    Outputs:
        did_refresh -- boolean representing whether or not refresh_token was executed
    """
    did_refresh = False
    try:
        if response_data["code"] == 124:
            try:
                refresh_token()
                did_refresh = True
            except:
                pass
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

    return access_token, r_token

def refresh_token():
    """
    Refreshes the logged in user's Zoom API access token

    Inputs:
        none, takes the current refresh token from session variables

    Outputs:
        new_access_token -- string, the fresh access token
        new_r_token -- string, the fresh refresh token
    """
    
    r_token = session.get('r_token')

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

    # saves new tokens in session variables
    session['a_token'] = new_access_token
    session['r_token'] = new_r_token

    return new_access_token, new_r_token

# retrieval

def get_participants(uuid):
    """
    Given a UUID of a Zoom meeting, retrieves the list of participants from Zoom and 
    adds each participant to the database. Returns the list of participants' names.

    Inputs:
        uuid -- a string representing the UUID of a Zoom meeting

    Outputs:
        new_participants -- a list of the meeting participants' names
    """
    authorization = "Bearer " + session['a_token']
    headers = {"Authorization": authorization}

    if (uuid[0] == "/") or ("//" in uuid):
        uuid = urllib.parse.quote(uuid, safe='')
        uuid = urllib.parse.quote(uuid, safe='')
    url = "https://api.zoom.us/v2/past_meetings/" + uuid + "/participants"
    response = requests.get(url, headers=headers)
    participants_data = response.json()

    # checks if the access token needs to be refreshed
    did_refresh = api_refresh_check(participants_data)

    # if the token refreshed, makes the API call again
    if did_refresh:
        authorization = "Bearer " + session['a_token']
        headers = {"Authorization": authorization}
        response = requests.get(url, headers=headers)
        participants_data = response.json()
    
    # prevents unfinished meetings from being included in dashboard
    if "code" in participants_data.keys():
        if participants_data["code"] == 3001:
            return False

    if len(participants_data["participants"]) == 0:
        return "error"

    new_participants = []
    for participant in participants_data['participants']:
        # Zoom replaces commas in response with # symbol
        if "#" in participant["name"]:
            name = participant['name'].replace("#", ",")
        else:
            name = participant["name"]
        if name in new_participants:
            continue
        id = participant["id"]
        email = participant["user_email"]
        new_participants.append(name)

        # print(name, id, email)

        # searches for existing participant in database with this email
        new_participant = Participant.query.filter_by(email=email).first()

        # print('Participant: ')
        # print(new_participant)

        # retrieves the meeting instance from the database
        meeting_inst = Meeting_Inst.query.filter_by(uuid=uuid).first()

        # print('Meeting: ')
        # print(meeting_inst)

        if new_participant and email != "":
            # if there is an existing Participant entry by this email, use this Participant
            meeting_inst.participants.append(new_participant)
            if new_participant.name != name and name not in [x.alias for x in new_participant.aliases]:
                # if the names do not match up, add the new name as an Alias of the Participant
                new_participant.aliases.append(Alias(name))
        elif Participant.query.filter_by(name=name).first():
            # if there is an existing Participant entry by this name, use this Participant
            meeting_inst.participants.append(Participant.query.filter_by(name=name).first())
            if Participant.query.filter_by(name=name).first().email == "":
                # if the Participant did not have an email but they do in the response data, update their email
                Participant.query.filter_by(name=name).first().email = email
        elif Alias.query.filter_by(alias=name).first():
            # if there is an existing Participant entry with this name as their Alias, use this Participant
            alias = Alias.query.filter_by(alias=name).first()
            a_participant = Participant.query.filter_by(id=alias.participant_id).first()
            meeting_inst.participants.append(a_participant)
        else:
            # otherwise, add a new Participant entry with this information
            # print(id, email, name)
            meeting_inst.participants.append(Participant(id, name, email))
        
    # print("All participants added to database")
    db.session.commit()
    return new_participants

def get_recordings(meeting_id, startdate, enddate):
    """    
    Retrieves from Zoom all meeting instances under the input meeting ID recorded between startdate and enddate.
    Adds meeting and meeting instance entries to database. Executes get_participants on each meeting instance.
    Retrieves transcript files for each meeting instance, executes parse_transcript on each, and adds transcript and transcript blocks to database.
    
    Inputs:
        meeting_id -- string, the ID of a Zoom meeting (from Zoom)
        startdate -- string in ISO format, representing first day to check for recordings
        enddate -- string in ISO format, representing last day to check for recordings (must be within 30 days of startdate)
    """
    # print("Using access token: " + session['a_token'])
    authorization = "Bearer " + session['a_token']

    headers = {"Authorization": authorization}

    # default number of records displayed is 30 -- page_size parameter increases this to the max, 300
    # can only display up to 1 month of meetings    
    url = "https://api.zoom.us/v2/users/me/recordings?from=" + startdate + "&to=" + enddate + "&page_size=" + str(300)
    response = requests.get(url, headers=headers)
    data = response.json()

    # checks if the token needs to be refreshed
    did_refresh = api_refresh_check(data)
    # if the token refreshed, makes the API call again
    if did_refresh:
        authorization = "Bearer " + session['a_token']
        headers = {"Authorization": authorization}
        response = requests.get(url, headers=headers)
        data = response.json()

    meetings = data["meetings"]

    for meeting in meetings:
        # finds all meeting instances matching input meeting ID
        if str(meeting['id']) == meeting_id:
            topic = meeting['topic']

            # adds the meeting assoc. w/ input meeting ID to meetings table in DB if does not exist
            if Meeting.query.filter_by(id=meeting_id).first() == None:
                new_meeting = Meeting(meeting_id, topic)
                db.session.add(new_meeting)
                db.session.commit()

            uuid = meeting['uuid']

            duration = meeting['duration']
            timedate = meeting["start_time"]
            timedate = timedate.replace("T", " ")
            timedate = timedate.replace("Z", " GMT")

            transcripts = []
            transcript_found = False
            for file in meeting['recording_files']:
                # looks for at least one transcript file for this meeting instance
                if file["file_type"] == "TRANSCRIPT":
                    # print("Transcript found")
                    transcript_found = True
                    transcripts.append(file["download_url"])
            if transcript_found == True:
                # add UUIDs/Meeting Insts for meetings w/ transcripts available
                # if no transcripts are found, the meeting instance is not relevant
                if Meeting_Inst.query.filter_by(uuid=uuid).first() == None:
                    # add to the DB if the meeting instance has not been added yet
                    meeting_inst = Meeting_Inst(uuid, meeting_id, duration, timedate)
                    db.session.add(meeting_inst)

                    # retrieve participants and add to DB
                    participants = get_participants(uuid)
                    if participants == 'error':
                        # if the participants list is bugged, remove the meeting instance from the DB to avoid errors
                        Meeting_Inst.query.filter_by(uuid=uuid).delete()
                        db.session.commit()
                        continue
                    else:
                        db.session.commit()

                # Parse and add to DB any new transcripts
                if Transcript.query.filter_by(uuid=uuid).all() == []:
                    # print("no transcripts yet :)")
                    for file in transcripts:
                        # print("Downloading...")

                        # create download URL for the transcript
                        dl_url = file + "?access_token=" + session['a_token']

                        # retrieves the transcript as text/string
                        response = requests.get(dl_url, stream=True)

                        #add transcript to DB
                        transcript = Transcript(uuid, response.text)
                        db.session.add(transcript)
                        db.session.commit()

                        # creates list of Transcript Block objects
                        p_transcript = parse_transcript(transcript.id, response.text)

                        #add parsed transcript to DB
                        db.session.add_all(p_transcript)
                        db.session.commit()

    return 

def host_retrieve():
    """
    Retrieves the meetings for which the current user is the host, and 
    retrieves all respective data from the database to display on the Submit page

    Outputs:
        meetings_dict -- a dictionary; outer keys are meeting IDs each associated to dict; 
        inner dict has a key, "topic", associated w/ meeting topic, and UUID keys each associated w/ dict;
        innermost dicts have three keys - "start_time" and "duration" are associated w/ single values, and 
        "participants" is associated w/ a list of strings
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
    """
    Retrieves all meetings for which the current user is the host, and
    re-runs get_recordings for each to check for new recordings.
    """
    curr_id = current_user.id
    hosted_meetings = Meeting.query.filter_by(host_id=curr_id).all()

    for meeting in hosted_meetings:
        get_recordings(meeting.id)

    return

def instructor_retrieve():
    """
    Retrieves all meetings that the current user has been sent/submitted (instructor or admin role required), and 
    retrieves all respective data from the database to display on the Dashboard page

    Outputs:
        meetings_dict -- a dictionary; outer keys are meeting IDs each associated to dict; 
        inner dict has two keys associated w/ single values, "host" and "topic", and UUID keys each associated w/ dict;
        innermost dicts have three keys - "start_time" and "duration" are associated w/ single values, and 
        "participants" is associated w/ a list of strings
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
    """
    Retrieves a transcript from the database and writes it to a local file.
    Returns the respective filename.

    Inputs:
        transcript_id -- an integer associated with a transcript in the database
    
    Outputs:
        filepath -- a string representing the filepath for the new transcript file
    """
    transcript = Transcript.query.filter_by(id=transcript_id).first()
    uuid = transcript.uuid
    transcript = transcript.transcript
    meeting_inst = Meeting_Inst.query.filter_by(uuid=uuid).first()
    timedate = meeting_inst.start_time

    filepath = "static/client/txt/%s_%d.txt" % (timedate, transcript_id)

    with open(filepath, "w") as file:
        file.write(transcript)

    return filepath

def create_data_csv(uuids):
    """  
    """
    header = ["Meeting Name", "Meeting ID", "Meeting Date", "Speaker", "Start Time", "End Time"]
    data = []
    master_t_list = []
    participants = []
    for uuid in uuids:
        curr_meeting_inst = Meeting_Inst.query.filter_by(uuid=uuid).first()
        curr_meeting = Meeting.query.filter_by(id=curr_meeting_inst.meeting_id).first()

        topic = curr_meeting.topic
        meeting_id = curr_meeting.id

        t_list = Transcript.query.filter_by(uuid=uuid).all()
        p_list = curr_meeting_inst.participants

        for participant in p_list:
            if participant.name not in participants:
                participants.append(participant.name)

        for idx, t in enumerate(t_list):
            p_t_list = Transcript_Block.query.filter_by(transcript_id=t.id).order_by(asc(Transcript_Block.sequence)).all()
            t_list[idx] = p_t_list

        master_t_list.extend(t_list)

        for t in t_list:
            for block in t:
                new_row = []
                new_row.append(topic)
                new_row.append(meeting_id)
                new_row.append(curr_meeting_inst.start_time)
                new_row.append(block.speaker)
                new_row.append(block.starttime)
                new_row.append(block.endtime)
                data.append(new_row)
        
    with open('static/client/csv/speaking_turn_data.csv', 'w', encoding='UTF8', newline='') as f:
        writer = csv.writer(f)

        # write the header
        writer.writerow(header)

        # write multiple rows
        writer.writerows(data)

    # write the second file

    a_dict = {}
    a_dict["speech_instances"] = speech_instances(master_t_list, participants)
    a_dict["silence_breaking"] = silence_breaking(master_t_list)
    a_dict["speech_durations"], a_dict["speech_distribution"] = speech_durations(master_t_list, participants)
    
    header2 = ["Speaker", "Speaking Instances", "Speaking Duration (seconds)", "Proportion of Speaking Time", "Silence Breaks", "Silence Starts", "Average Break", "2.5 to 5s Breaks", "5 to 7.5s Breaks", "7.5 to 10s Breaks", "10s+ Breaks"]
    data2 = []
    for participant in participants:
        new_row = []
        new_row.append(participant)
        new_row.append(a_dict["speech_instances"][participant])
        new_row.append(a_dict["speech_durations"][participant].total_seconds())
        new_row.append(a_dict["speech_distribution"][participant])
        
        try:
            for value in a_dict["silence_breaking"][participant].keys():
                if value == "times":
                    continue
                elif value == "avg-break" and type(a_dict["silence_breaking"][participant][value]) != int:
                    new_row.append(a_dict["silence_breaking"][participant][value].total_seconds())
                else:
                    new_row.append(a_dict["silence_breaking"][participant][value])
        except:
            vals = ["Silence Breaks", "Silence Starts", "Average Break", "2.5 to 5s Breaks", "5 to 7.5s Breaks", "7.5 to 10s Breaks", "10s+ Breaks"]
            for val in vals:
                new_row.append(0)

        data2.append(new_row)

    with open('static/client/csv/speaking_summary_data.csv', 'w', encoding='UTF8', newline='') as f:
        writer = csv.writer(f)

        # write the header
        writer.writerow(header2)

        # write multiple rows
        writer.writerows(data2)
    
    return

# parsing

def parse_transcript(transcript_id, transcript):
    """
    Parses the full transcript into individual Transcript_Block objects and adds them to the database.

    Inputs:
        transcript_id -- an integer associated with a transcript in the database
        transcript -- a string containing the full Zoom transcript
    Outputs:
        p_transcript -- a list containing Transcript_Block objects
    """
    # splits transcript into lines
    split_transcript = transcript.split("\r\n")
    p_transcript = []

    # iterates through each line of the transcript
    for idx, line in enumerate(split_transcript):
        # skips first line
        if idx == 0:
            continue
        elif line == "WEBVTT":
            continue
        # initializes empty block
        block = Transcript_Block(transcript_id)
        if line == "":
            if idx == len(split_transcript) - 1 or idx == len(split_transcript) - 2:
                continue

            block.sequence = int(split_transcript[idx + 1])
            timestamp = split_transcript[idx + 2].split(" --> ")

            # use timedelta values for computations later
            t1 = datetime.strptime(timestamp[0], "%H:%M:%S.%f")
            t2 = datetime.strptime(timestamp[1], "%H:%M:%S.%f")
            block.starttime = timedelta(hours=t1.hour, minutes=t1.minute, seconds=t1.second)
            block.endtime = timedelta(hours=t2.hour, minutes=t2.minute, seconds=t2.second)

            name_text = split_transcript[idx + 3].split(": ")

            # some lines do not contain a name, resulting in len = 1
            if len(name_text) == 1:
                if idx == 1:
                    continue
                text = split_transcript[idx + 3].split(": ")[0]
                
                # start from the current line and traverse backwards to find the speaker
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

# analysis

def speech_instances(transcript_list, participants):
    """
    Counts the number of times each participant spoke in the recording
    
    Inputs: 
        transcript_list -- a list of transcript block objects
        participants -- a list of participants
    Outputs:
        speech_nums -- a dictionary containing the speakers as keys and how many times they spoke as values 
    """
    speech_nums = {}
    # stark by intializing that all participats spoke at least 0 times (helps with aliases)
    for participant in participants:
        speech_nums[participant] = 0
    # look through each speach block 
    for p_transcript in transcript_list:
        for block in p_transcript:
            # add to participant key value each time they speak
            if block.speaker in speech_nums.keys():
                speech_nums[block.speaker] += 1
            else:
                speech_nums[block.speaker] = 1
    # copy speech_nums to modify 
    speech_nums_copy = speech_nums.copy()
    # look for aliases 
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
    Computes values related to durations of silence in the transcript

    Inputs:
        transcript_list -- a list of Transcript Block objects
    Outputs:
        breaks -- a dictionary containing each speaker as a key associated with an inner dict; 
        each inner dict contains the keys "total-breaks", "total-starts", "avg-break", "2.5", "5", "7.5", "10", and "times";    
    """
    breaks = {}

    for p_transcript in transcript_list:
        for idx, block in enumerate(p_transcript):
            # skips the first iteration b/c checking pairs
            if idx == 0:
                continue
            prev_tstamp = p_transcript[idx-1].endtime
            prev_speaker = p_transcript[idx-1].speaker
            curr_tstamp = block.starttime
            curr_speaker = block.speaker
            silence_dur = curr_tstamp - prev_tstamp
            if silence_dur >= timedelta(seconds=2.5):
                # initialize previous and current speaker if new
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

    # copy of dictionary to iterate over while changing original
    breaks_copy = breaks.copy()
    for participant in breaks_copy.keys():
        # find participant by this name
        p = Participant.query.filter_by(name=participant).first()
        if p:
            aliases = [x.alias for x in p.aliases]
            for alias in aliases:
                if alias in breaks.keys():
                    # if this person's alias also appears, combine them under original name & delete alias key
                    for key in breaks[participant].keys():
                        if key == "times":
                            breaks[participant]["times"].extend(breaks[alias]["times"])
                        else:
                            breaks[participant][key] += breaks[alias][key]
                    del breaks[alias]

    # calculate average silence duration before break for each participant
    for participant in breaks:
        times_list = breaks[participant]["times"]
        if len(times_list) == 0:
            average = 0
            breaks[participant]["avg-break"] = average
            continue
        average = sum(times_list, timedelta()) / len(times_list)
        average -= timedelta(microseconds=average.microseconds)
        breaks[participant]["avg-break"] = average

    return breaks
       
def speech_durations(transcript_list, participants):
    """
    Calculates duration each participant spoke and distribution of speaking time

    Inputs:
        transcript_list -- a list of transcript block objects
        participants -- a list of participants' names (strings)
    Outputs:
        durations -- a dictionary containing each participant's name (string) as a key 
        associated with their speaking duration (timedelta)
        distribution -- a dictionary containing each participant's name (string) as a key
        associated with their percentage (float) of the total speaking time
    """
    durations = {}

    # initialize all values to 0 seconds
    for participant in participants:
        durations[participant] = timedelta(0)

    for p_transcript in transcript_list:
        for block in p_transcript:
            tstamp1 = block.starttime
            tstamp2 = block.endtime

            # calculate duration of speaking
            partial_duration = abs(tstamp1 - tstamp2)
            if block.speaker in durations.keys():
                durations[block.speaker] += partial_duration
            else:
                durations[block.speaker] = partial_duration

    # copy of dictionary to iterate over while changing original
    durations_copy = durations.copy()
    for participant in durations_copy.keys():
        # find participant by this name
        p = Participant.query.filter_by(name=participant).first()
        if p:
            aliases = [x.alias for x in p.aliases]
            # if this person's alias also appears in the dict, combine them under original name & delete alias key
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
    """
    Creates multiple graphical representations of meeting transcripts, along with network statistics

    Inputs: 
        transcript_list -- a list of transcript block objects
        participants -- a list of participants' names
    Returns:
        ad_mat -- the graph's adjacency matrix as a dictionary
        ad_list --  graph's adjacency matrix as a list
        g -- an igraph graph object mapping the transcript's interactions
        edge_density -- the total number of edge connections between vertices divided by the total possible number of edges
        centr_degree -- the number of edges connected to each node
    """
    # create adjacency matrix as dict
    ad_mat = {}
    # create adjacency matrix as list
    ad_list = []
    # indexes must be tracked for igraph functions 
    index = 0 
    # for final edge_deg calculation
    edge_tot = 0
    for p_transcript in transcript_list:
        # analize each speach instance
        for idx, block in enumerate(p_transcript):
            # the last speaker ends the meeting, does not speak to anybody else
            if idx == len(p_transcript) - 1:
                continue
            # tracks who(curr_speaker) is speaking to who(next_speaker)
            curr_speaker = block.speaker
            next_speaker = p_transcript[idx+1].speaker
            # adds previously silent speaker to adacency mat
            if curr_speaker not in ad_mat:
                ad_mat[curr_speaker] = {}
                # for ad_list
                ad_mat[curr_speaker]['index'] = index
                index += 1
            # adds previously silent speaker to adacency mat this time if never spoken to before
            if next_speaker not in ad_mat[curr_speaker]:
                # initialize one turn and the edge
                ad_mat[curr_speaker][next_speaker] = 1
            else:
                # add one edge degree
                ad_mat[curr_speaker][next_speaker] += 1
            if next_speaker not in ad_mat:
                # add speaker as a new node 
                ad_mat[next_speaker] = {'index' : index}
                index += 1
    # start ad list construction from ad_mat
    for speaker_1 in ad_mat:
        ad_list.append([])
    for i in range(len(ad_list)):
        for speaker_1 in ad_mat:
            ad_list[i].append(0)
    for speaker_1 in ad_mat:
        # add all adjacent nodes to list as neighbors, skipping index place holders
        for speaker_2 in ad_mat[speaker_1]:
            if speaker_2 == 'index':
                continue
            ad_list[ad_mat[speaker_1]['index']][ad_mat[speaker_2]['index']] = ad_mat[speaker_1][speaker_2]
    #create igraph graph object using ad_list as input
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
    # modify ad_mat for later reference in graph_to_json
    ad_mat_copy = deepcopy(ad_mat)
    # Address aliasing  
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
                        

    centr_degree = 0

    return ad_mat, ad_list, g, centr_degree

def strength(g, ad_mat):
    """
    Finds each participant's node degree

    Inputs: 
        ad_mat -- the graph's adjacency matrix as a dictionary
        g -- an igraph graph object
    Returns: 
        degree_mat -- a dictionary with participants' names as keys and their node degrees as values
    """
    # finds each participant's node degree
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
    """
    Creates a json object for the SigmaJS network graph using computed values from get_graph and
    writes it to the network.json local file. Additionally, calculates edge density from number of edges and nodes.

    Inputs:
        ad_mat -- a dictionary representing the graph's adjacency matrix
        degree_matrix -- a dictionary representing the graph's degree matrix 

    Outputs:
        edge_density -- a float representing the graph's edge density
    """
    nodes = []
    edges = []

    # each key in degree_mat is a node in the graph
    for idx, node in enumerate(degree_mat.keys()):
        node_vals = {"id":node, "label": node, "x": random.random(), "y": random.random(), "size": degree_mat[node]}
        nodes.append(node_vals)
        # just in case node does not also appear in ad_mat (should be fixed?)
        try:
            for idx2, node2 in enumerate(ad_mat[node].keys()):
                if node2 == "index":
                    continue
                edge_name = node + node2
                size = ad_mat[node][node2]
                edge_vals = {"id" : edge_name, "label": size, "source" : node, "target" : node2, "type": "curvedArrow"}
                edges.append(edge_vals)
        except KeyError:
            continue

    edge_total = len(edges)
    edge_density = edge_total / ((len(nodes)*(len(nodes)-1)) + len(nodes))

    # overwrites network.json file each time analysis is done
    fh = open("static/client/json/network.json", "w")
    fh.write(json.dumps({"nodes": nodes, "edges": edges}))
    fh.close()

    return edge_density


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

        return render_template("submit.html", form=form, refreshed=False, new_sub=True, meetings=meetings_dict)

    try:
        auth_code = request.args['code']
        try:
            if session['auth_code'] == auth_code:
                access_token = session['access_token']
                r_token = session['r_token']
            else:
                session['auth_code'] = auth_code
                access_token, r_token = get_access_token(auth_code)
        except:
            session['auth_code'] = auth_code
            access_token, r_token = get_access_token(auth_code)
    except:
        return redirect(OAUTH)

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
        return render_template("submit.html", form=form, refreshed=True, meetings=meetings_dict)

    try:
        auth_code = request.args['code']
        try:
            if session['auth_code'] == auth_code:
                access_token = session['access_token']
                r_token = session['r_token']
            else:
                session['auth_code'] = auth_code
                access_token, r_token = get_access_token(auth_code)
        except:
            session['auth_code'] = auth_code
            access_token, r_token = get_access_token(auth_code)
    except:
        return redirect(OAUTH)

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

        if request.method == 'POST':
            uuids = request.form.getlist('checkbox')
            if len(uuids) == 0:
                return render_template("dashboard.html", meetings=meetings_dict, error="no-meet")
            if 'analyze' in request.form:

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
                        p_t_list = Transcript_Block.query.filter_by(transcript_id=t.id).order_by(asc(Transcript_Block.sequence)).all()
                        # print(p_t_list)
                        t_list[idx] = p_t_list
                    master_t_list.extend(t_list)
                # print(master_t_list)


                a_dict = {}
                a_dict["speech_instances"] = speech_instances(master_t_list, participants)
                a_dict["silence_breaking"] = silence_breaking(master_t_list)
                a_dict["speech_durations"], a_dict["speech_distribution"] = speech_durations(master_t_list, participants)
                a_dict["adjacency_mat"], a_dict["adjacency_lst"], a_dict["network_graph"], a_dict["center_deg"]  = get_graph(master_t_list, participants)

                distribution_labels = a_dict["speech_distribution"].keys()
                distribution_values = a_dict["speech_distribution"].values()
                distribution_values = [round(x * 100, 2) for x in distribution_values]

                distribution = [list(distribution_labels), list(distribution_values)]

                instance_labels = a_dict["speech_instances"].keys()
                instance_values = a_dict["speech_instances"].values()

                instances = [list(instance_labels), list(instance_values)]

                duration_labels = a_dict["speech_durations"].keys()
                duration_values = [x.total_seconds() for x in a_dict["speech_durations"].values()]

                durations = [list(duration_labels), duration_values]

                degree_mat = strength(a_dict["network_graph"], a_dict["adjacency_mat"])
                edge_density = graph_to_json(a_dict["adjacency_mat"], degree_mat)

                return render_template("analysis.html", analysis=a_dict, distribution=distribution, instances=instances, durations=durations, edge_density=edge_density)

            elif 'download' in request.form:
                create_data_csv(uuids)

                with zipfile.ZipFile('static/client/zip/speaking_data.zip','w', zipfile.ZIP_DEFLATED) as zf: 
                    zf.write('static/client/csv/speaking_turn_data.csv', basename('static/client/csv/speaking_turn_data.csv'))
                    zf.write('static/client/csv/speaking_summary_data.csv', basename('static/client/csv/speaking_summary_data.csv'))

                return send_file('static/client/zip/speaking_data.zip', as_attachment=True)


        return render_template("dashboard.html", meetings=meetings_dict)
    else:
        return redirect(url_for('home'))

@app.route('/admin', methods=["GET", "POST"])
@login_required
def admin():
    if current_user.role == "Admin":

        if request.method == 'POST':
            user_ids = request.form.getlist('checkbox')
            if len(user_ids) == 0:
                return render_template("admin.html", users=users, error="no-users")

            if 'instructor' in request.form:
                for user_id in user_ids:
                    user = User.query.filter_by(id=user_id).first()
                    user.role = "Instructor"
                db.session.commit()
            elif 'admin' in request.form:
                for user_id in user_ids:
                    user = User.query.filter_by(id=user_id).first()
                    user.role = "Admin"
                db.session.commit()
            elif 'user' in request.form:
                for user_id in user_ids:
                    user = User.query.filter_by(id=user_id).first()
                    user.role = "User"
                db.session.commit()

            users = User.query.all()

            return render_template("admin.html", users=users)

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
