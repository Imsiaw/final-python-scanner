from flask import Blueprint, jsonify, request
from utils.general import list_all_projects, list_projects_by_dir_name
from config.config import diff_dir_path
from utils.diff import diff_two_obj, diff_projects
from datetime import datetime
from uuid import uuid4
import pandas as pd
import shutil
import os

# ------------------------------------------------------------

diff_route = Blueprint("diff", __name__)

# ------------------------------------------------------------


# List All The Diffs Directory And SubDirectories
@diff_route.route("/diffs")
def get_diffs():
    diff_directories = [
        d
        for d in os.listdir(diff_dir_path)
        if os.path.isdir(os.path.join(diff_dir_path, d))
    ]

    diff_files = []

    for dir in diff_directories:
        path = f"{diff_dir_path}/{dir}"
        sub_dirs = [d for d in os.listdir(path) if d.endswith(".csv")]
        diff_files.append(
            {
                "directory": dir,
                "children": [{"label": c, "id": uuid4()} for c in sub_dirs],
                "id": uuid4(),
            }
        )

    return jsonify({"status": True, "data": diff_files})


# Get Diff File
@diff_route.route("/diffs/<path:path>")
def get_diff(path):
    try:
        csv_path = os.path.join(diff_dir_path, path)

        csv_file = pd.read_csv(csv_path, index_col=None)

        dict_file = csv_file.fillna(value="").to_dict("records")

        return jsonify({"status": True, "data": dict_file})

    except FileNotFoundError as err:
        raise Exception("The file is not exist!") from err

    except Exception as err:
        raise Exception("Unknown Error!") from err


# Delete The Diff Directory
@diff_route.route("/diffs/dir/<path:path>", methods=["DELETE"])
def delete_diff_dir(path: str):
    try:
        dir_path = os.path.join(diff_dir_path, path)

        shutil.rmtree(dir_path)

        return jsonify({"status": True, "data": None})

    except FileNotFoundError as err:
        raise Exception("The directory is not exist!") from err

    except Exception as err:
        raise Exception("Unknown Error!") from err


# Delete The Diff File
@diff_route.route("/diffs/file/<path:path>", methods=["DELETE"])
def delete_diff_file(path: str):
    try:
        dir_path = os.path.join(diff_dir_path, path)

        os.unlink(dir_path)

        return jsonify({"status": True, "data": None})

    except FileNotFoundError as err:
        raise Exception("The file is not exist!") from err

    except Exception as err:
        print(err)
        raise Exception("Unknown Error!") from err


# Define The Diff Directory
@diff_route.route("/diffs/dir", methods=["POST"])
def define_diff_directory():
    try:
        form_data = request.form

        name = form_data["name"]

        dir_path = os.path.join(diff_dir_path, name)

        os.mkdir(dir_path)

        return jsonify({"status": True, "data": None})

    except FileExistsError as err:
        raise Exception("The Project With The Same Name Exist!") from err

    except FileNotFoundError as err:
        raise Exception("The path is not exist!") from err

    except Exception as err:
        raise Exception("Unknown Error!") from err


# Define The Diff File
@diff_route.route("/diffs/dir/file", methods=["POST"])
def define_diff_file():
    try:
        form_data = request.form
        files = request.files

        csv_file = files["csv_file"]

        parent = form_data["parent"]

        timestamp = form_data["datetime"]
        date_time = datetime.fromtimestamp(int(timestamp) / 1000)
        formatted_date_time = date_time.strftime("%Y_%m_%d_%H%M%S")

        file_path = os.path.join(diff_dir_path, parent)

        csv_file.save(os.path.join(file_path, f"diff_{formatted_date_time}.csv"))

        return jsonify({"status": True, "data": None})

    except FileExistsError as err:
        raise Exception("The Project-Dir With The Same Name Exist!") from err

    except FileNotFoundError as err:
        raise Exception("The path is not exist!") from err

    except Exception as err:
        print(err)
        raise Exception("Unknown Error!") from err


# Diff The Projects
@diff_route.route("/diff/<path:path>")
def diff_project(path: str):
    try:
        projects = list_projects_by_dir_name(path.split("/")[0])
        print(path, projects)

        diff_projects(projects)

        return jsonify({"status": True, "data": None})

    except FileExistsError as err:
        raise Exception("The Project-Dir With The Same Name Exist!") from err

    except FileNotFoundError as err:
        raise Exception("The path is not exist!") from err

    except Exception as err:
        print(err)
        raise Exception("Unknown Error!") from err


# Diff The All Projects
@diff_route.route("/diff-all", methods=["POST"])
def diff_all_projects():
    try:
        projects = list_all_projects()

        diff_projects(projects)

        return jsonify({"status": True, "data": None})

    except FileExistsError as err:
        raise Exception("The Project-Dir With The Same Name Exist!") from err

    except FileNotFoundError as err:
        raise Exception("The path is not exist!") from err

    except Exception as err:
        print(err)
        raise Exception("Unknown Error!") from err
