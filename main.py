from flask import Flask, redirect, url_for, session, request, render_template
from flask_sqlalchemy import SQLAlchemy
from requests_oauthlib import OAuth2Session
from requests.exceptions import HTTPError
from flask_login import LoginManager, current_user

import os
import json


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


db = SQLAlchemy(app)
db.init_app(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    token = db.Column(db.String(120), nullable=True)

    def __init__(self, username, email):
        self.username = username
        self.email = email

    def __repr__(self):
        return '<User %r>' % self.username


class Request(db.Model):
    id = db.Column(db.Integer, primary_key=True)


db.drop_all()
db.create_all()
Admin = User('Samu', 'samu77@freemail.hu')
db.session.add(Admin)
db.session.commit()


# Google Auth
basedir = os.path.abspath(os.path.dirname(__file__))

login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.session_protection = "strong"
login_manager.init_app(app)


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
    if current_user is not None and current_user.is_authenticated:
        return redirect(url_for('egy'))
    if 'error' in request.args:
        if request.args.get('error') == 'access_denied':
            return 'Access is denied.'
        return 'Error encountered.'
    if 'code' not in request.args and 'state' not in request.args:
        return redirect(url_for('ketto'))
    else:
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
            username = user_data['name']

            # Execute Query
            user = User(username=username, email=email)
            db.session.add(user)
            db.session.commit()

            # flash('You are now registered and can log in!', 'success')
            redirect(url_for('login'))

            if user is None:
                tokens = json.dumps(token)
                name = user_data['name']

                user = User(username=name, email=email, token=tokens)
                db.session.add(user)
                db.session.commit()

            # login_user(user)
            return redirect(url_for('login'))
        return 'Could not fetch your information.'


def get_google_auth(state=None, token=None):
    if token:
        return OAuth2Session(Auth.CLIENT_ID, token=token)
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


@app.route('/')
def index():
    return 'INDEX'


@app.route('/home', methods=['GET'])
def home():
    return render_template('home.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        google = get_google_auth()
        auth_url, state = google.authorization_url(
        Auth.AUTH_URI, access_type='offline')
        session['oauth_state'] = state
        return render_template('login.html', auth_url=auth_url)
    return render_template('home.html')


if __name__ == '__main__':
    app.secret_key = b'jz\x8dB\xf3\xeb\n\xe3\x9f\x9c\xf7\x8e\xc3"\x8d\x13\xf2\xb9\xd8QxQ6\xcf'
    app.run(host='127.0.0.1', debug=True, port=5000, ssl_context='adhoc')
