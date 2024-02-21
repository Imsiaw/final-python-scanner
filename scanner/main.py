from flask import Flask, jsonify, render_template, Response, json
from config.config import bbot_dir_path, diff_dir_path
from flask_cors import CORS
import os
from project import project_route
from diff import diff_route
from utils.general import create_dir_if_not_exist

# ------------------------------------------------------------

sc_path = os.path.abspath(__file__)

project_base_path = os.path.abspath(os.path.join(sc_path, "../../.."))

bbot_dir_path = os.path.join(project_base_path, bbot_dir_path)


create_dir_if_not_exist(bbot_dir_path)

create_dir_if_not_exist(diff_dir_path)

# ------------------------------------------------------------


os.system("clear")
app = Flask(__name__)

app.register_blueprint(project_route)

app.register_blueprint(diff_route)

CORS(app)


@app.route("/")
def index():
    return render_template("index.html")


@app.errorhandler(Exception)
def handle_exception(error):
    print(error)
    response = {"message": str(error), "status": False}
    return jsonify(response)


if __name__ == "__main__":
    app.run(debug=True)
