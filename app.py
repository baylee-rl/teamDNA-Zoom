import os
from dotenv import dotenv_values
import requests
from flask import Flask, render_template, request, session, redirect, url_for, json
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.dialects import postgresql
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Length, Email, EqualTo
from base64 import b64encode
from datetime import date, datetime, timedelta
import urllib.request
import urllib.parse
from collections import defaultdict
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_user, login_required, UserMixin, logout_user, current_user
import igraph
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

    def __init__(self, id, name, email):
        self.id = id
        self.name = name
        self.email = email

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
    speech = db.Column(db.String(100))

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

    new_participants = []
    for participant in participants_data['participants']:
        if participant["name"] in new_participants.keys() and participant["user_email"] == '':
            continue
        id = participant["id"]
        name = participant["name"]
        email = participant["user_email"]
        new_participants.append(name)

        #add participants to meeting inst row in DB
        meeting_inst = Meeting_Inst.query.filter_by(uuid=uuid).first()
        if len(meeting_inst.participants) == 0:
            meeting_inst.participants.append(Participant(id, name, email))
    db.session.commit()
    return new_participants

def get_recordings(meeting_id):
    """
    given a meeting ID, retrieves all information from Zoom and adds information to respective DB tables
    returns a dictionary mapping meeting IDs to UUIDs, host_id, topic, and UUIDs map to start_time, duration, and participants (for display)
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
            m_data[uuid] = {}

            duration = meeting['duration']
            timedate = meeting["start_time"]
            timedate = timedate.replace("T", " ")
            timedate = timedate.replace("Z", " GMT")

            m_data[uuid]['duration'] = duration
            m_data[uuid]['start_time'] = timedate

            # retrieve participants and add to DB
            participants = get_participants(uuid)

            m_data[uuid]['participants'] = participants

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
                    db.session.commit()
                    print("UUID successfully added")
                # Parse and add to DB any new transcripts
                if Transcript.query.filter_by(uuid=uuid).all() == None:
                    for file in transcripts:
                        print("Downloading...")

                        dl_url = file + "?access_token=" + session['a_token']
                        response = requests.get(dl_url, stream=True)

                        #add transcript to DB
                        transcript = Transcript(uuid, response.text)
                        db.session.add(transcript)
                        db.session.commit()

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
            # print(idx)
            block.sequence = int(split_transcript[idx + 1])
            timestamp = split_transcript[idx + 2].split(" --> ")
            t1 = datetime.strptime(timestamp[0], "%H:%M:%S.%f")
            t2 = datetime.strptime(timestamp[1], "%H:%M:%S.%f")
            block.starttime = timedelta(hours=t1.hour, minutes=t1.minute, seconds=t1.second)
            block.endtime = timedelta(hours=t2.hour, minutes=t2.minute, seconds=t2.second)

            name_text = split_transcript[idx + 3].split(": ")
            if len(name_text) == 1:
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

        return render_template("sign-up-success.html")
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
    # app will fail if user has not authenticated OAuth extension
    if form.validate_on_submit():
        # CHANGED TO ACCEPT SINGLE MEETING 
        print("nice")
        meeting_id = form.meetid.data
        recipient_email = form.recipient.data
        recipient = User.query.filter_by(email=recipient_email).first()
        if recipient is None:
            return render_template('submit.html', form=form, msg="no-user")
        elif recipient.role not in ["Instructor", "Admin"]:
            return render_template('submit.html', form=form, msg='not-instructor')

        # removes whitespace if present
        meeting_id = meeting_id.replace(" ", "")
        print("Meeting ID: " + meeting_id)

        # get meetings and info, add to DB
        try:
            get_recordings(meeting_id)
        except:
            print("unable to retrieve info, redirecting")
            return redirect(OAUTH)

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

        ### may change in prod. ###
        # **moving to dashboard/instructor page only
        """
        ### retroactively update metrics if any participant was excluded ###
        for meeting in meeting_dict:
            for meeting_inst in meeting_dict[meeting]:
                if meeting_inst == "topic" or meeting_inst == "host_id":
                    continue
                meeting_vals = meeting_dict[meeting][meeting_inst]
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
        """
        print(meetings_dict)

        return render_template("submit.html", form=form, new_sub=True, meetings=meetings_dict)
        
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
    test_meetings_dict["9876543"] = {"host_id":"08HFJKANmn7asd", "topic":"TeamDNA Bi-Monthly Meetings", "KnmdHFAnsDHA==":{"duration":24, "timedate":"2021-06-07 18:54:25 GMT", "participants":{"Baylee Keevan":"bjk9@rice.edu", "Sophia Rohlfsen":"", "Tina Wen":"", "Margaret Beier":"", "Matthew Wettergreen":"", "Ashu Sabharwal":'', "Matt Barnett":""}}}
    test_meetings_dict["1234567"]["fjHEJmnfmdHf=="] = {"duration":57, "timedate":"2021-05-21 17:44:32 GMT", "participants":{"Baylee Keevan":"bjk9@rice.edu", "Sophia Rohlfsen":"", "Tina Wen":""}}
    test_meetings_dict["9876543"]["hjFDbEUTYZOs=="] = {"duration":46, "timedate":"2021-06-07 18:54:25 GMT", "participants":{"Baylee Keevan":"bjk9@rice.edu", "Sophia Rohlfsen":"", "Tina Wen":"", "Margaret Beier":"", "Matthew Wettergreen":"", "Ashu Sabharwal":'', "Matt Barnett":""}}
    
    return render_template("submit-test.html", meetings = test_meetings_dict)


if __name__ == "__main__":
    app.run(debug=True)