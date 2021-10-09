from flask import Flask
from pymongo import MongoClient

app = Flask(__name__)

client = MongoClient(
    "mongodb+srv://MindlessDoc:NfhrjdNjg228@cluster0.jlpdf.mongodb.net/myFirstDatabase?retryWrites=true&w=majority&tlsAllowInvalidCertificates=true")

db_name = "MoreTech"

collections_users = client[db_name]["users"]
collections_datasets = client[db_name]["datasets"]

@app.route("/", methods = ["GET", "POST"])
def login():
    return "Hello world"

app.run(debug=True)