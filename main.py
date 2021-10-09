from flask import Flask, redirect, flash, render_template, url_for
from pymongo import MongoClient
from flask_login import login_required, login_user, current_user, UserMixin, LoginManager
from werkzeug.security import generate_password_hash, check_password_hash
from forms import *
from datetime import timedelta

app = Flask(__name__)

app.config["SECRET_KEY"] = "86F27F78E9AA221425B98B46F337A"
app.permanent_session_lifetime = timedelta(days=1)

client = MongoClient(
    "mongodb+srv://MindlessDoc:NfhrjdNjg228@cluster0.jlpdf.mongodb.net/myFirstDatabase?retryWrites=true&w=majority"
    "&tlsAllowInvalidCertificates=true")

db_name = "MoreTech"

collections_users = client[db_name]["users"]
collections_datasets = client[db_name]["datasets"]

# collections_users.insert_one({
#     "username": "user",
#     "password": generate_password_hash("user"),
#     "role": "user"
# })

login = LoginManager(app)
login.login_view = 'login'
login.init_app(app)


class User(UserMixin):
    def __init__(self, username, password, role):
        self.password_hash = password
        self.username = username
        self.role = role

    def get_username(self):
        return self.username

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_role(self):
        return self.role

    @login.user_loader
    def load_user(username):
        return User("login", "password", "superuser")


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    form = UserForm()
    if form.is_submitted():
        name = form.username.data
        password = form.password.data
        user_db_count = collections_users.count_documents({"username": name})
        if user_db_count:
            user_db = collections_users.find_one({"username": name})
            user = User(user_db["username"], user_db["password"], 1)

            if user is not None and user.check_password(password):
                login_user(user)
                return redirect("admin/")
        flash('Invalid username or password')
        return redirect(url_for('login'))
    return render_template('admin/login.html', title='Sign In', form=form)


@app.route("/admin", methods=["GET", "POST"])
@login_required
def index():
    return current_user.get_role()


app.run(debug=True)
