from flask import Flask, redirect, url_for, session, request, render_template
from flask_sqlalchemy import SQLAlchemy
from requests_oauthlib import OAuth2Session
from requests.exceptions import HTTPError
from flask_login import LoginManager, current_user, UserMixin, login_user, logout_user, login_required
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

login_manager = LoginManager()
login_manager.init_app(app)

db = SQLAlchemy(app)
db.init_app(app)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    active = db.Column(db.Boolean, default=False)
    name = db.Column(db.String(100), nullable=True)
    tokens = db.Column(db.Text)
    role = db.Column(db.String(120), nullable=True, default='unauthorized')

    def __repr__(self):
        return '<User %r>' % self.name


class Request(db.Model):
    id = db.Column(db.Integer, primary_key=True)


db.drop_all()
db.create_all()
Admin = User(email='samu77@freemail.hu', role='admin')
db.session.add(Admin)
db.session.commit()


# Google Auth
basedir = os.path.abspath(os.path.dirname(__file__))


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
            if user is None:
                user = User()
                user.email = email
            user.name = user_data['name']
            user.tokens = json.dumps(token)
            db.session.add(user)
            db.session.commit()
            login_user(user)
            return redirect(url_for('index'))
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


@app.route('/')
def index():
    return 'INDEX'


@app.route('/home', methods=['GET'])
@login_required
def home():
    return render_template('home.html')


@app.route('/success', methods=['GET'])
@login_required
def success():
    return render_template('success.html')


@app.route('/logout', methods=['GET'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        google = get_google_auth()
        auth_url, state = google.authorization_url(Auth.AUTH_URI, access_type='offline')
        session['oauth_state'] = state
        return render_template('login.html', auth_url=auth_url)
    return render_template('home.html')


if __name__ == '__main__':
    app.secret_key = b'jz\x8dB\xf3\xeb\n\xe3\x9f\x9c\xf7\x8e\xc3"\x8d\x13\xf2\xb9\xd8QxQ6\xcf'
    app.run(host='127.0.0.1', debug=True, port=5000, ssl_context='adhoc')