import io
from flask import Flask, request, redirect, render_template, session, send_file
from flask_sqlalchemy import SQLAlchemy
import pyotp
import qrcode

app = Flask(__name__)
app.secret_key = 'secret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    otp_secret = db.Column(db.String(16), nullable=False)
with app.app_context():
    db.create_all()

@app.route('/qrcode')
def show_qrcode():
    user = User.query.filter_by(username=session.get('username')).first()
    if not user:
        return redirect('/login')
    otp_uri = pyotp.totp.TOTP(user.otp_secret).provisioning_uri(name=user.username, issuer_name="Sanifarixx")
    img = qrcode.make(otp_uri)
    buf = io.BytesIO()
    img.save(buf)
    buf.seek(0)
    return send_file(buf, mimetype='image/png')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        otp_secret = pyotp.random_base32()
        user = User(username=username, password=password, otp_secret=otp_secret)
        db.session.add(user)
        db.session.commit()
        session['username'] = username
        return redirect('/qrcode')
    return render_template('reg.html')

@app.route('/verify', methods=['GET', 'POST'])
def verify():
    if request.method == 'POST':
        code = request.form['code']
        user = User.query.filter_by(username=session.get('username')).first()
        if user and pyotp.TOTP(user.otp_secret).verify(code):
            return 'authorized :)'
        return 'error'
    return render_template('verify.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username, password=password).first()
        if user:
            session['username'] = username
            return redirect('/verify')
        return 'error'
    return render_template('login.html')



if __name__ == '__main__':
    app.run(debug=True)
