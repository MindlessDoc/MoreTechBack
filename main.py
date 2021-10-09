from flask import Flask, redirect, flash, render_template, url_for, jsonify, request
from pymongo import MongoClient
from flask_login import login_required, login_user, current_user, UserMixin, LoginManager
from werkzeug.security import generate_password_hash, check_password_hash
from forms import *
from flask_cors import CORS
from bson.objectid import ObjectId
from datetime import timedelta
import re
import os

app = Flask(__name__)

app.config["SECRET_KEY"] = "86F27F78E9AA221425B98B46F337A"
app.permanent_session_lifetime = timedelta(days=1)

app = Flask(__name__)
cors = CORS(app)
app.secret_key = os.urandom(24)

client = MongoClient(
    "mongodb+srv://MindlessDoc:NfhrjdNjg228@cluster0.jlpdf.mongodb.net/myFirstDatabase?retryWrites=true&w=majority"
    "&tlsAllowInvalidCertificates=true")

db_name = "MoreTech"

collections_admins = client[db_name]["admins"]
collections_users = client[db_name]["users"]
collections_datasets = client[db_name]["datasets"]

# collections_admins.insert_one({
#     "username": "user",
#     "password": generate_password_hash("user"),
#     "role": "user"
# })

login = LoginManager(app)
login.login_view = "login"
login.init_app(app)


class User(UserMixin):
    def __init__(self, id, username, password, name, surname, role):
        self.password_hash = password
        self.username = username
        self.name = name
        self.id = id
        self.surname = surname
        self.role = role

    def get_username(self):
        return self.username

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_role(self):
        return self.role

    def get_id(self):
        return self.username

    @login.user_loader
    def load_user(username):
        loaded_user = collections_admins.find_one({"username": username})
        return User(loaded_user["_id"], loaded_user["username"], loaded_user["password"], loaded_user["name"],
                    loaded_user["surname"], loaded_user["role"])


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    form = UserForm()
    if form.is_submitted():
        name = form.username.data
        password = form.password.data
        user_db_count = collections_admins.count_documents({"username": name})
        if user_db_count:
            user_db = collections_admins.find_one({"username": name})
            user = User(user_db["_id"], user_db["username"], user_db["password"], user_db["name"],
                        user_db["surname"], user_db["role"])

            if user is not None and user.check_password(password):
                login_user(user)
                return redirect("admin/datasets")
        flash('Invalid username or password')
        return redirect(url_for('login'))
    return render_template('admin/login.html', title='Sign In', form=form)


@app.route("/admin", methods=["GET", "POST"])
@login_required
def index():
    return current_user.get_role()


@app.get("/admin/users")
@login_required
def users():
    return render_template("/admin/users.html", users=collections_users.find())


@app.get("/admin/datasets")
@login_required
def datasets():
    return render_template("/admin/datasets.html", datasets=collections_datasets.find())


@app.route('/admin/edit_dataset/<id>', methods=["GET", "POST"])
@login_required
def edit_dataset(id):
    dataset_form = DatasetForm()
    dataset = collections_datasets.find({"_id": ObjectId(id)})[0]
    if dataset_form.validate_on_submit():
        if "delete" in request.form:
            collections_datasets.remove({"_id": ObjectId(id)})
            return redirect("/admin/datasets", code=302)

        dataset_form = request.form

        collections_datasets.update_one({"_id": ObjectId(id)}, {"$set": {
            "name": dataset_form["name"],
            "description": dataset_form["description"],
            "access_role": dataset_form["access_role"]
        }})
        print(dataset_form)

        return redirect("/admin/datasets", code=302)
    return render_template("admin/edit_dataset.html", dataset=dataset, dataset_form=dataset_form)


@app.get("/search_datasets/<name>")
def search_datasets(name):
    my_name = re.compile(f"^{name}.*", re.I)

    datasets = list(collections_datasets.find({"name": {'$regex': my_name}}))
    for dataset in datasets:
        dataset["_id"] = str(dataset["_id"])
    return jsonify(datasets)


@app.route("/users/change_<string:change_username>", methods=["GET", "POST"])
@login_required
def change_user(change_username):
    user_to_change = collections_users.find_one({"username": change_username})

    if user_to_change:
        form = ChangeUserForm(username=user_to_change["username"],
                              name=user_to_change["name"],
                              surname=user_to_change["surname"])

        if form.is_submitted():
            collections_users.update_one({"username": change_username}, {"$set": {"username": form.username.data,
                                                                                  "name": form.name.data,
                                                                                  "surname": form.surname.data}})
            return redirect(url_for('users'))
        return render_template('admin/change_user.html', title='Change_user', form=form)
    return "Несуществующий login пользователя"


@app.get("/")
def api_index():
    return "dataunion api v1.0"

app.run(debug=True)
# app.run(port=5021)
