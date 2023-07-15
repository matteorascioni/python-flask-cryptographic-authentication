from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

# App setup 
app = Flask(__name__)
app.debug = True
SECRET_KEY = 'your-secret-key'
# The secret key is needed to keep the client-side sessions secure.
app.config['SECRET_KEY'] = SECRET_KEY

# Database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)
# Create a table in the db (UserMixin necessary to use the flask_login inheritances functinoalities)
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
# Run once db.create _all to create the database
# with app.app_context():
#     db.create_all()

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def home():
    return render_template("index.html")

@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get('email')
        name = request.form.get('name')
        password = request.form.get('password')

        if email and name and password:
            # checking if the user already exist
            if User.query.filter_by(email=email).first():
                flash("You've already signed up with that email, log in instead!")
                return redirect(url_for('register'))
            
            # Encrypting the password and adding the new user into the database
            hash_and_salted_password = generate_password_hash(password, method="pbkdf2:sha256", salt_length=8)
            new_user = User(email=email, name=name, password=hash_and_salted_password)
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('login'))

    return render_template("register.html")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == "POST":
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        # Email doesn't exist
        if not user:
            flash("That email does not exist, please try again.")
            return redirect(url_for('login'))
        # Password incorrect
        elif not check_password_hash(user.password, password):
            flash('Password incorrect, please try again.')
            return redirect(url_for('login'))
        # Email exists and password correct
        else:
            login_user(user)
            return redirect(url_for('secrets'))
    
    return render_template('login.html')

@app.route('/secrets')
@login_required
def secrets():
    return render_template("secrets.html", name=current_user.name)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for("home"))

@app.route('/download')
@login_required
def download():
    try:
        return send_from_directory('./static/files', "cheat_sheet.pdf")
    except FileNotFoundError:
        raise Http404

if __name__ == "__main__":
    app.run()