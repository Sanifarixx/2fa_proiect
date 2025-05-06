import io
import smtplib
from email.message import EmailMessage
from random import randint
from flask import Flask, request, redirect, render_template, session, url_for
from flask_sqlalchemy import SQLAlchemy
import pyotp
import qrcode

app = Flask(__name__)
app.secret_key = 'secret_key_for_session'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)

EMAIL_ADDR = "" 
EMAIL_PASSWORD = "" 

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    otp_secret = db.Column(db.String(16), nullable=False)
    is_verified = db.Column(db.Boolean, default=False)
    verification_code = db.Column(db.String(6))

with app.app_context():
    db.create_all()

def send_email(to_email, subject, body, attachment=None):
    msg = EmailMessage()
    msg.set_content(body)
    msg["Subject"] = subject
    msg["From"] = EMAIL_ADDR
    msg["To"] = to_email

    if attachment:
        with open(attachment, "rb") as f:
            img_data = f.read()
        msg.add_attachment(img_data, maintype='image', subtype='png', filename=attachment)

    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(EMAIL_ADDR, EMAIL_PASSWORD)
            server.send_message(msg)
    except Exception as e:
        print("error:", str(e))
        return False
    return True

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        if User.query.filter_by(username=username).first():
            return "Asa nume exista"
        if User.query.filter_by(email=email).first():
            return "Email folosit."

        otp_secret = pyotp.random_base32()
        verification_code = str(randint(100000, 999999))

        user = User(
            username=username,
            email=email,
            password=password,
            otp_secret=otp_secret,
            verification_code=verification_code
        )
        db.session.add(user)
        db.session.commit()

        send_email(email, "Cod de confirmare Sanifarixx", f"Codul tau de confirmare este: {verification_code}")

        session['username'] = username
        return redirect(url_for('verify_email'))

    return render_template('register.html')

@app.route('/verify_email', methods=['GET', 'POST'])
def verify_email():
    if request.method == 'POST':
        code = request.form['code']
        user = User.query.filter_by(username=session.get('username')).first()
        if user and user.verification_code == code:
            user.is_verified = True
            db.session.commit()

            otp_uri = pyotp.TOTP(user.otp_secret).provisioning_uri(name=user.username, issuer_name="Sanifarixx")
            img_path = f"qrcode_{user.id}.png"
            qrcode.make(otp_uri).save(img_path)

            send_email(user.email, "QR Code - Sanifarixx", "Acesta este codul QR", attachment=img_path)

            return redirect(url_for('login'))
        return "cod invalid."
    return render_template('verify_email.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username, password=password).first()
        if user and user.is_verified:
            session['username'] = username
            return redirect(url_for('verify_2fa'))
        return "error - user verify."
    return render_template('login.html')

@app.route('/verify_2fa', methods=['GET', 'POST'])
def verify_2fa():
    if request.method == 'POST':
        code = request.form['code']
        user = User.query.filter_by(username=session.get('username')).first()
        if user and pyotp.TOTP(user.otp_secret).verify(code):
            session['authenticated'] = True
            return redirect(url_for('profile'))
        return "codul gresit"
    return render_template('verify_2fa.html')

@app.route('/profile')
def profile():
    if not session.get('authenticated'):
        return redirect(url_for('login'))
    user = User.query.filter_by(username=session.get('username')).first()
    if not user:
        return redirect(url_for('login'))
    return render_template('profile.html', username=user.username)

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if not session.get('authenticated'):
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_password = request.form['new_password']
        user = User.query.filter_by(username=session.get('username')).first()
        if user:
            user.password = new_password
            db.session.commit()
            return "succes!"
        return "resetarea parolei error."

    return render_template('reset_password.html')

if __name__ == '__main__':
    app.run(debug=True)
