from flask import Flask, redirect, url_for, session, request, render_template, flash
from flask_sqlalchemy import SQLAlchemy
from requests_oauthlib import OAuth2Session
from requests.exceptions import HTTPError
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_admin.base import MenuLink
from wtforms import Form, StringField, DateField, validators, SelectField
from _datetime import date
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
    activated = db.Column(db.String(5), default='no')
    tokens = db.Column(db.Text)
    role = db.Column(db.String(120), nullable=True, default='unauthorized')
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'))
    requests = db.relationship('Request', backref='owner', lazy=True)
    used_days = db.Column(db.Integer, default=0)

    def __repr__(self):
        return '<%r>' % self.name


class Request(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    start_date = db.Column(db.Date())
    finish_date = db.Column(db.Date())
    sum = db.Column(db.Integer)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    status_id = db.Column(db.Integer, db.ForeignKey('status.id'))
    rq_status = db.Column(db.String(10), default='test')
    employee = db.Column(db.String(50))

    def __repr__(self):
        return '<%r>' % self.id


class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20))
    days = db.Column(db.Integer)
    cat_name = db.relationship('User', backref='categories', lazy=True)

    def __repr__(self):
        return '<%r>' % self.name


class Status(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20))
    stat_name = db.relationship('Request', backref='state', lazy=True)

    def __repr__(self):
        return '<%r>' % self.name


class MyModelView(ModelView):
    def is_accessible(self):
        if current_user.is_authenticated and session.get('role') == "admin":
            return True
    column_exclude_list = 'tokens'
    column_display_pk = True


admin.add_view(MyModelView(User, db.session))
admin.add_view(MyModelView(Request, db.session))
admin.add_menu_item(MenuLink(name='Real Home Page', url='/'))
admin.add_menu_item(MenuLink(name='Requests', url='/requests'))


# Adding request for testing purposes
req1 = Request(start_date='2019.01.20', finish_date='2019.01.22', sum=2)
cat0 = Category(name='Default', days= 20)
cat1 = Category(name='Young', days=25)
cat2 = Category(name='Middle age', days=30)
cat3 = Category(name='Old', days=35)

stat1 = Status(name='Pending')
stat2 = Status(name='Approved')
stat3 = Status(name='Declined')

db.session.add(req1)
db.session.add(cat0)
db.session.add(cat1)
db.session.add(cat2)
db.session.add(cat3)
db.session.add(stat1)
db.session.add(stat2)
db.session.add(stat3)

db.drop_all()
db.create_all()
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
        first_user = User.query.filter_by(id=1).first()
        if user is None and first_user is None:
            user = User()
            user.email = email
            user.role = "admin"
            user.activated = "yes"
        elif user is None:
            user = User()
            user.email = email
        user.name = user_data['name']
        user.tokens = json.dumps(token)
        db.session.add(user)
        db.session.commit()
        login_user(user)
        session['role'] = user.role
        session['activated'] = user.activated
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


# Request Form Class
class RequestForm(Form):
    start = DateField('Start day of the leave', format='%Y-%m-%d')
    finish = DateField('Last day of the leave', format='%Y-%m-%d')
    rq_status = SelectField('status', choices=[])


# Add Request
@app.route('/add_request', methods=['GET', 'POST'])
@login_required
def add_request():
    form = RequestForm(request.form)
    form.rq_status.choices = [(Status.id, Status.name) for Status in Status.query.all()]

    if request.method == 'POST':

        start = form.start.data
        finish = form.finish.data
        date_1 = date(start.year, start.month, start.day)
        date_2 = date(finish.year, finish.month, finish.day)

        sum = (date_2 - date_1).days

        req = Request(sum=sum, start_date=start, finish_date=finish, employee=current_user.name, rq_status='Pending')
        db.session.add(req)
        db.session.commit()

        flash('Request created', 'success')
        return redirect(url_for('requests'))

    return render_template('add_request.html', form=form)


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
    allrequests = Request.query.all()
    return render_template('requests.html', allrequests=allrequests)


@app.route('/request/<string:id>', methods=['GET', 'POST'])
@login_required
def modify_request(id):
    req = Request.query.get(id)
    form = RequestForm(request.form)
    form.start.data = req.start_date
    form.finish.data = req.finish_date
    form.rq_status.data = req.rq_status
    status = Status.query.all()

    if request.method == 'POST':
        start_date = request.form['start']
        finish_date = request.form['finish']
        rq_status = request.form['rq_status']
        req.start_date = start_date
        req.finish_date = finish_date
        req.rq_status = rq_status
        db.session.add(req)
        db.session.commit()
        return redirect(url_for('requests'))
    return render_template('request.html', form=form, status=status)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    return redirect(url_for('home'))


if __name__ == '__main__':
    app.secret_key = b'jz\x8dB\xf3\xeb\n\xe3\x9f\x9c\xf7\x8e\xc3"\x8d\x13\xf2\xb9\xd8QxQ6\xcf'
    app.run(host='127.0.0.1', debug=True, port=5000, ssl_context='adhoc')
