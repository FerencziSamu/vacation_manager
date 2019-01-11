from flask import Flask
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
POSTGRES = {
    'user': 'test',
    'pw': 'password',
    'db': 'test_db',
    'host': 'db',
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

    def __init__(self, username, email):
        self.username = username
        self.email = email

    def __repr__(self):
        return '<User %r>' % self.username


db.drop_all()
db.create_all()
Admin = User('Samu', 'samu77@freemail.hu')
Admine = User('Samue', 'esamu77@freemail.hu')
db.session.add(Admin)
db.session.add(Admine)
db.session.commit()


@app.route('/')
def index():
    return 'INDEX'


@app.route('/hello')
def hello():
    return 'Hello, World!'


if __name__ == '__main__':
    app.secret_key = 'password'
    app.run(host='0.0.0.0', debug=True, port=5000)
