from config.config import bbot_dir_path, bbot_project_filename
from flask import Blueprint, jsonify, request
from utils.general import list_all_projects
from datetime import datetime
import pandas as pd
import shutil
import os

# ------------------------------------------------------------

project_route = Blueprint("project", __name__)

# ------------------------------------------------------------


# List All The Projects Directory And SubDirectories
@project_route.route("/projects")
def get_projects():
    bbot_files = list_all_projects()

    return jsonify({"status": True, "data": bbot_files})


# Get The asset-inventory.csv Base On Path
@project_route.route("/projects/<path:path>")
def get_project_by_path(path: str):
    try:
        csv_path = os.path.join(bbot_dir_path, path, bbot_project_filename)

        csv_file = pd.read_csv(csv_path, index_col=None)

        dict_file = csv_file.fillna(value="").to_dict("records")

        return jsonify({"status": True, "data": dict_file})

    except FileNotFoundError as err:
        raise Exception("The file is not exist!") from err

    except Exception as err:
        raise Exception("Unknown Error!") from err


# Delete The Project Directory
@project_route.route("/projects/dir/<path:path>", methods=["DELETE"])
def delete_project_dir(path: str):
    try:
        dir_path = os.path.join(bbot_dir_path, path)

        shutil.rmtree(dir_path)

        return jsonify({"status": True, "data": None})

    except FileNotFoundError as err:
        raise Exception("The file is not exist!") from err

    except Exception as err:
        raise Exception("Unknown Error!") from err


# Delete The Project File
@project_route.route("/projects/file/<path:path>", methods=["DELETE"])
def delete_project_file(path: str):
    try:
        dir_path = os.path.join(bbot_dir_path, path)

        shutil.rmtree(dir_path)

        return jsonify({"status": True, "data": None})

    except FileNotFoundError as err:
        raise Exception("The file is not exist!") from err

    except Exception as err:
        raise Exception("Unknown Error!") from err


# Define The Project Directory
@project_route.route("/projects/dir", methods=["POST"])
def define_project_directory():
    try:
        form_data = request.form

        name = form_data["name"]

        dir_path = os.path.join(bbot_dir_path, name)

        os.mkdir(dir_path)

        return jsonify({"status": True, "data": None})

    except FileExistsError as err:
        raise Exception("The Project With The Same Name Exist!") from err

    except FileNotFoundError as err:
        raise Exception("The path is not exist!") from err

    except Exception as err:
        raise Exception("Unknown Error!") from err


# Define The Project File
@project_route.route("/projects/dir/file", methods=["POST"])
def define_project_file():
    try:
        form_data = request.form
        files = request.files

        csv_file = files["csv_file"]

        parent = form_data["parent"]

        timestamp = form_data["datetime"]
        date_time = datetime.fromtimestamp(int(timestamp) / 1000)
        formatted_date_time = date_time.strftime("%Y_%m_%d_%H%M%S")

        sub_dir_path = os.path.join(bbot_dir_path, parent, formatted_date_time)
        os.mkdir(sub_dir_path)

        csv_file.save(os.path.join(sub_dir_path, "asset-inventory.csv"))

        return jsonify({"status": True, "data": None})

    except FileExistsError as err:
        raise Exception("The Project-Dir With The Same Name Exist!") from err

    except FileNotFoundError as err:
        raise Exception("The path is not exist!") from err

    except Exception as err:
        print(err)
        raise Exception("Unknown Error!") from err
