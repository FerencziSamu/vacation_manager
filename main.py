from __future__ import print_function

from flask import Flask, redirect, url_for, session, request, render_template, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_admin.base import MenuLink
from requests_oauthlib import OAuth2Session
from requests.exceptions import HTTPError
from wtforms import Form, DateField
from _datetime import date
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
import os
import json
import pickle
import time


# Postgres and db set up
app = Flask(__name__)
POSTGRES = {
    'user': 'test',
    'pw': 'password',
    'db': 'test_db',
    'host': '0.0.0.0',
    'port': '5432'
}

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://%(user)s:\
%(pw)s@%(host)s:%(port)s/%(db)s' % POSTGRES
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['FLASK_ADMIN_SWATCH'] = 'cerulean'

login_manager = LoginManager()
login_manager.init_app(app)
admin = Admin(app, name='Vacation Manager', template_mode='bootstrap3')

db = SQLAlchemy(app)
db.init_app(app)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    name = db.Column(db.String(100))
    active = db.Column(db.Boolean(), default=False)
    tokens = db.Column(db.Text)
    used_days = db.Column(db.Integer, default=0)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=True)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=True)

    def __repr__(self):
        return '<%r>' % self.name


class Request(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    start_date = db.Column(db.Date())
    finish_date = db.Column(db.Date())
    sum = db.Column(db.Integer)
    status = db.Column(db.String(10))
    employee = db.Column(db.String(50))
    event_id = db.Column(db.String(30))

    def __repr__(self):
        return '<%r>' % self.id


class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20))
    days = db.Column(db.Integer)
    users = db.relationship('User', backref='category', lazy=True)

    def __repr__(self):
        return f"('{self.name}', '{self.days}')"


class Status(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20))

    def __repr__(self):
        return '<%r>' % self.name


class Role(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(50), unique=True)
    users = db.relationship('User', backref='user_roles', lazy=True)

    def __repr__(self):
        return '<%r>' % self.name


class MyModelView(ModelView):
    def is_accessible(self):
        if current_user.is_authenticated and session.get('role') == "Admin":
            return True
    form_excluded_columns = 'tokens', 'used_days', 'users'
    column_exclude_list = 'tokens'


admin.add_menu_item(MenuLink(name='Home Page', url='/'))
admin.add_menu_item(MenuLink(name='Requests', url='/requests'))
admin.add_view(MyModelView(User, db.session))
admin.add_view(MyModelView(Category, db.session))

role0 = Role(name='Unauthorized')
role1 = Role(name='Viewer')
role2 = Role(name='Employee')
role3 = Role(name='Admin')

stat1 = Status(name='Pending')
stat2 = Status(name='Approved')
stat3 = Status(name='Declined')

cat0 = Category(name='Default', days=20)

db.session.add(cat0)
db.session.add(stat1)
db.session.add(stat2)
db.session.add(stat3)
db.session.add(role0)
db.session.add(role1)
db.session.add(role2)
db.session.add(role3)

db.drop_all()
db.create_all()
db.session.commit()

# Google Auth
basedir = os.path.abspath(os.path.dirname(__file__))

# Google Calendar API
SCOPES = ['https://www.googleapis.com/auth/calendar']


@login_manager.user_loader
def get_user(ident):
    return User.query.get(int(ident))


class Auth:
    """Google Project Credentials"""
    CLIENT_ID = '435293161538-4vhaau49erplvbs2pcdv9fsbob2aa726.apps.googleusercontent.com'
    CLIENT_SECRET = 'CY1_FcYf4fbqwpwj3jzUL9bG'
    REDIRECT_URI = 'https://127.0.0.1:5000/gCallback'
    AUTH_URI = 'https://accounts.google.com/o/oauth2/auth'
    TOKEN_URI = 'https://accounts.google.com/o/oauth2/token'
    USER_INFO = 'https://www.googleapis.com/userinfo/v2/me'
    SCOPE = ['profile', 'email']


class Config:
    """Base config"""
    APP_NAME = "Holiday Manager"
    SECRET_KEY = os.environ.get("SECRET_KEY") or "somethingsecret"


@app.route('/gCallback')
def callback():
    google = get_google_auth(state=session['oauth_state'])
    try:
        token = google.fetch_token(
            Auth.TOKEN_URI,
            client_secret=Auth.CLIENT_SECRET,
            authorization_response=request.url)
    except HTTPError:
        return 'HTTPError occurred.'
    google = get_google_auth(token=token)
    resp = google.get(Auth.USER_INFO)
    if resp.status_code == 200:
        user_data = resp.json()
        email = user_data['email']
        user = User.query.filter_by(email=email).first()
        first_user = User.query.filter_by(id=1).first()
        if user is None and first_user is None:
            user = User()
            user.email = email
            user.role_id = role3.id
            user.active = True
        elif user is None:
            user = User()
            user.email = email
            user.role_id = role0.id
        user.name = user_data['name']
        user.tokens = json.dumps(token)
        user.category_id = cat0.id
        db.session.add(user)
        db.session.commit()
        login_user(user)
        session['role'] = Role.query.get(current_user.role_id).name
        print(session['role'])
        print(current_user.role_id)
        days = Category.query.get(current_user.category_id).days
        print(days)
        return redirect(url_for('home'))
    return 'Could not fetch your information.'


def get_google_auth(state=None, token=None):
    if token:
        return OAuth2Session(
            Auth.CLIENT_ID,
            token=token)
    if state:
        return OAuth2Session(
            Auth.CLIENT_ID,
            state=state,
            redirect_uri=Auth.REDIRECT_URI)
    oauth = OAuth2Session(
        Auth.CLIENT_ID,
        redirect_uri=Auth.REDIRECT_URI,
        scope=Auth.SCOPE)
    return oauth


def create_event(date_1, date_2, event_id):
    creds = None
    email = current_user.email

    if os.path.exists('token.pickle'):
        with open('token.pickle', 'rb') as token:
            creds = pickle.load(token)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            get_google_auth()
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', SCOPES)
            creds = flow.run_local_server()
        with open('token.pickle', 'wb') as token:
            pickle.dump(creds, token)

    gcal = build('calendar', 'v3', credentials=creds)
    event = {
        "start": {"date": str(date_1)},
        "end": {"date": str(date_2)},
        "summary": "Holiday",
        "id": event_id,
        "attendees": [{
            "email": email
        }]
    }
    gcal.events().insert(calendarId='invenshure.com_bestbp3r6lvncuqqikfl5ghlno@group.calendar.google.com',
                         sendNotifications=False, body=event).execute()


def delete_event(event_id):
    creds = None

    if os.path.exists('token.pickle'):
        with open('token.pickle', 'rb') as token:
            creds = pickle.load(token)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            get_google_auth()
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', SCOPES)
            creds = flow.run_local_server()
        with open('token.pickle', 'wb') as token:
            pickle.dump(creds, token)
    gcal = build('calendar', 'v3', credentials=creds)
    gcal.events().delete(calendarId='invenshure.com_bestbp3r6lvncuqqikfl5ghlno@group.calendar.google.com',
                            eventId=event_id).execute()


# Request Form Class
class RequestForm(Form):
    start = DateField('Start day of the leave', format='%Y-%m-%d')
    finish = DateField('Last day of the leave', format='%Y-%m-%d')


@app.route('/test', methods=['GET', 'POST'])
def test():
    return render_template('test.html')


# Add Request
@app.route('/add_request', methods=['GET', 'POST'])
@login_required
def add_request():
    if current_user.role_id == 4 or current_user.role_id == 3:
        form = RequestForm(request.form)

        if request.method == 'POST' and form.validate():
            start = form.start.data
            finish = form.finish.data
            date_1 = date(start.year, start.month, start.day)
            date_2 = date(finish.year, finish.month, finish.day)
            sum = (date_2 - date_1).days

            req = Request(sum=sum, start_date=start, finish_date=finish, employee=current_user.name, status=stat1.name)
            db.session.add(req)
            db.session.commit()

            flash('Request created', 'success')
            return redirect(url_for('requests'))

        return render_template('add_request.html', form=form)
    flash('You are not authorized!', 'danger')
    return redirect(url_for('home'))


@app.route('/', methods=['GET', 'POST'])
def home():
    if request.method == 'GET':
        google = get_google_auth()
        auth_url, state = google.authorization_url(Auth.AUTH_URI, access_type='offline')
        session['oauth_state'] = state
        return render_template('home.html', auth_url=auth_url)
    return render_template('home.html')


@app.route('/requests')
@login_required
def requests():
    if current_user.is_authenticated and session.get('role') == "Admin":
        allrequests = Request.query.all()
        return render_template('requests.html', allrequests=allrequests)
    flash('You are not an administrator!', 'danger')
    return redirect(url_for('home'))


# Approve Request
@app.route('/approve_request/<string:id>', methods=['POST'])
@login_required
def approve_request(id):
    if current_user.is_authenticated and session.get('role') == "Admin":
        req = Request.query.get(id)
        event_id = int(time.time())
        date_1 = req.start_date
        date_2 = req.finish_date
        if req.status == stat3.name:
            req.status = stat2.name
            req.event_id = event_id
            db.session.add(req)
            db.session.commit()
            create_event(date_1, date_2, event_id)
            flash('Request approved!', 'success')
            return redirect(url_for('requests'))
        req.status = stat2.name
        req.event_id = event_id
        db.session.add(req)
        db.session.commit()
        create_event(date_1, date_2, event_id)
        flash('Request approved!', 'success')
        return redirect(url_for('requests'))
    flash('You are not an administrator!', 'danger')
    return redirect(url_for('home'))


# Reject Request
@app.route('/reject_request/<string:id>', methods=['POST'])
@login_required
def reject_request(id):
    if current_user.is_authenticated and session.get('role') == "Admin":
        req = Request.query.get(id)
        event_id = req.event_id
        if req.status == stat1.name:
            req.status = stat3.name
            db.session.add(req)
            db.session.commit()
            flash('Request rejected!', 'success')
            return redirect(url_for('requests'))
        req.status = stat3.name
        db.session.add(req)
        db.session.commit()
        delete_event(event_id)
        flash('Request rejected!', 'success')
        return redirect(url_for('requests'))
    flash('You are not an administrator!', 'danger')
    return redirect(url_for('home'))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    return redirect(url_for('home'))


if __name__ == '__main__':
    app.secret_key = b'jz\x8dB\xf3\xeb\n\xe3\x9f\x9c\xf7\x8e\xc3"\x8d\x13\xf2\xb9\xd8QxQ6\xcf'
app.run(host='127.0.0.1', debug=True, port=5000, ssl_context='adhoc')
