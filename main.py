from flask import Flask, redirect, flash, render_template, url_for, jsonify, request
from pymongo import MongoClient
from flask_login import login_required, login_user, current_user, UserMixin, LoginManager
from werkzeug.security import generate_password_hash, check_password_hash
from forms import *
from flask_cors import CORS
from bson.objectid import ObjectId
from datetime import timedelta, datetime
import time
import jwt
from random import randint
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
collections_tasks = client[db_name]["tasks"]

categories = ["Изображения", "Финансы", "География", "Персональные данные", "Дети и родители"]
types = ["Агрегация данных", "Необработанный датасет", "Сырые данные"]
access_rights = ["read_dataset", "change_dataset"]

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
    dataset_form.type.choices = types
    dataset_form.type.data = dataset["type"]

    if dataset_form.validate_on_submit():
        if "delete" in request.form:
            collections_datasets.remove({"_id": ObjectId(id)})
            return redirect("/admin/datasets", code=302)

        dataset_form = request.form
        cats = [category for category in categories if category in dataset_form]
        collections_datasets.update_one({"_id": ObjectId(id)}, {"$set": {
            "name": dataset_form["name"],
            "description": dataset_form["description"],
            "access_role": dataset_form["access_role"],
            "categories": cats,
            "type": dataset_form["type"]
        }})

        return redirect("/admin/datasets", code=302)
    return render_template("admin/edit_dataset.html", dataset=dataset, dataset_form=dataset_form, categories=categories)


@app.get("/search_datasets/<name>")
def search_datasets_by_name(name):
    current_time = time.time()
    my_name = re.compile(f"^{name}.*", re.I)

    datasets = list(collections_datasets.find({"name": {'$regex': my_name}}))
    for dataset in datasets:
        dataset["_id"] = str(dataset["_id"])
    return jsonify({"date": round(time.time() - current_time, 3), "datasets": datasets})


@app.get("/search_dataset/<id>")
def search_dataset_by_id(id):
    dataset = collections_datasets.find_one({"_id": ObjectId(id)})
    dataset["_id"] = str(dataset["_id"])
    return jsonify(dataset)


@app.get("/random_dataset")
def random_dataset():
    return jsonify(list(map(lambda x: x["name"], collections_datasets.aggregate([{"$sample": {"size": 5}}]))))


@app.route("/admin/users/change_<string:change_username>", methods=["GET", "POST"])
@login_required
def change_user(change_username):
    user_to_change = collections_users.find_one({"username": change_username})

    if user_to_change:
        form = ChangeUserForm(username=user_to_change["username"],
                              name=user_to_change["name"],
                              surname=user_to_change["surname"])

        access_right_form = request.form

        if form.is_submitted():
            collections_users.update_one({"username": change_username}, {"$set": {"username": form.username.data,
                                                                                  "name": form.name.data,
                                                                                  "surname": form.surname.data,
                                                                                  "role": form.role.data,
                                                                                  "read_dataset": "read_dataset" in access_right_form,
                                                                                  "change_dataset": "change_dataset" in access_right_form}})
            return redirect(url_for('users'))
        return render_template('admin/change_user.html', title='Change_user', form=form, user=user_to_change,
                               access_rights=access_rights)
    return "Несуществующий login пользователя"


@app.get("/get_tasks")
def get_tasks():
    return collections_tasks.find()


@app.get("/")
def api_index():
    return "dataunion api v1.12"


@app.post("/login_jwt")
def login_jwt():
    user_data = request.get_json()
    login = user_data["login"]
    password = user_data["password"]

    if collections_users.count_documents({"username": login}):
        if check_password_hash(collections_users.find_one({"username": login})["password"], password):
            user = collections_users.find_one({"username": login})
            encoded_jwt = jwt.encode({"role": user["role"], "name": user["name"], "surname": user["surname"],
                                      "change_dataset": user["change_dataset"], "read_dataset": user["read_dataset"]},
                                     "secret", algorithm="HS256")
            print(encoded_jwt)
            return encoded_jwt
        return "Wrong password", 400
    return "User not found", 403


app.run(debug=True)
# app.run(port=5021)
