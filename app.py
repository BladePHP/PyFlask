from flask import Flask, request, redirect, url_for, render_template, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, logout_user, login_required, current_user, LoginManager, current_user
from sqlalchemy import func
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "helloworld"

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:''@localhost/crud'
app.config['SQLALCHEMY_TRACK_MODIFICATION'] = False

db = SQLAlchemy(app)

###--------------MODEL-----------------###

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.VARCHAR(20), unique=True)
    username = db.Column(db.VARCHAR(150), unique=True)
    password = db.Column(db.VARCHAR(150))
    date_created = db.Column(db.DateTime(timezone=True), default=func.now())

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.VARCHAR(20), nullable=False)
    deskripsi = db.Column(db.TEXT(450), nullable=False)

    def __init__(self, name, deskripsi):
        self.name = name
        self.deskripsi = deskripsi

###--------------Route-----------------###

@app.route('/')
@login_required
def index():
    tugas = Task.query.all()
    return render_template("index.html", tugas = tugas, user=current_user)

@app.route('/create', methods = ['POST', 'GET'])
def create():
    
    if request.method == 'POST':
        name = request.form['name']
        deskripsi = request.form['deskripsi']
        
        tugas = Task(name, deskripsi)
        db.session.add(tugas)
        db.session.commit()
        return redirect(url_for('index'))
    
    else:
        return render_template("create.html", user=current_user)
    
@app.route('/update/<int:id>', methods = ['GET', 'POST'])
def update(id):
    tugas = Task.query.get(id)

    if request.method == 'POST':
        tugas.name = request.form['name']
        tugas.deskripsi = request.form['deskripsi']

        db.session.commit()
        return redirect(url_for('index'))
    else:
        return render_template("update.html", tugas=tugas, user=current_user)

@app.route('/delete/<int:id>')
def delete(id):

    tugas = Task.query.get(id)
    db.session.delete(tugas)
    db.session.commit()
    return redirect('/')

###--------------Auth Route-----------------###

@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get("email")
        password = request.form.get("password")

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash("Logged in!", category='success')
                login_user(user, remember=True)
                return redirect(url_for('index'))
            else:
                flash('Password is incorrect.', category='error')
        else:
            flash('Email does not exist.', category='error')

    return render_template("login.html", user=current_user)


@app.route("/sign-up", methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get("email")
        username = request.form.get("username")
        password1 = request.form.get("password1")
        password2 = request.form.get("password2")

        email_exists = User.query.filter_by(email=email).first()
        username_exists = User.query.filter_by(username=username).first()

        if email_exists:
            flash('Email is already in use.', category='error')
        elif username_exists:
            flash('Username is already in use.', category='error')
        elif password1 != password2:
            flash('Password don\'t match!', category='error')
        elif len(username) < 2:
            flash('Username is too short.', category='error')
        elif len(password1) < 6:
            flash('Password is too short.', category='error')
        elif len(email) < 4:
            flash("Email is invalid.", category='error')
        else:
            new_user = User(email=email, username=username, password=generate_password_hash(
                password1, method='pbkdf2:sha256'))
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=True)
            flash('User created!')
            return redirect(url_for('index'))

    return render_template("signup.html", user=current_user)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))

###--------------login manajer-----------------###

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))

if __name__ == "__main__":
    app.run(debug=True)