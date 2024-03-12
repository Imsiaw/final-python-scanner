from config.config import (
    bbot_dir_path,
    bbot_project_ndjson,
    hostnames_table_filename,
    links_table_filename,
    screenshots_table_filename,
)
from flask import Blueprint, jsonify, request, send_file
from utils.general import list_all_projects
from datetime import datetime
from utils.Links_Parser import Links_Parser
from utils.Hostname_Parser import Hostname_parser
from utils.Screenshot_Parser import Screenshot_Parser
import pandas as pd
import shutil
import os
import json

# ------------------------------------------------------------

project_route = Blueprint("project", __name__)

sc_path = os.path.abspath(__file__)

project_base_path = os.path.abspath(os.path.join(sc_path, "../.."))

bbot_dir_path = os.path.join(project_base_path, bbot_dir_path)


TABLE_TYPE_MAPPER = {
    "hostnames": hostnames_table_filename,
    "links": links_table_filename,
    "screenshots": screenshots_table_filename,
}


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
        queries = request.args
        table_type = queries.get("type", "hostnames")

        ndjson_path = os.path.join(bbot_dir_path, path, bbot_project_ndjson)
        d_path = os.path.join(bbot_dir_path, path, TABLE_TYPE_MAPPER[table_type])

        if os.path.exists(d_path):
            # and table_type != "screenshots":
            with open(d_path, "r") as r:
                data = json.load(r)
                return jsonify({"status": True, "data": data})
        else:
            data = []
            if table_type == "hostnames":
                parser = Hostname_parser()
                data = parser.parse_to_host_names(ndjson_path)

            if table_type == "links":
                parser = Links_Parser()
                data = parser.parse_to_links(ndjson_path)

            if table_type == "screenshots":
                parser = Screenshot_Parser()
                data = parser.parse_to_screenshots(path)

            with open(d_path, "w") as w:
                json.dump(data, w)
            return jsonify({"status": True, "data": data})

    except FileNotFoundError as err:
        raise Exception("The file is not exist!") from err

    except Exception as err:
        print(err)
        raise Exception(err) from err


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


# Update The Project File
@project_route.route("/projects/file", methods=["POST"])
def update_project_file():
    try:

        queries = request.args
        table_type = queries.get("type", "hostnames")

        form_data = request.form

        data = form_data["data"]
        path = form_data["path"]

        file_path = os.path.join(bbot_dir_path, path, TABLE_TYPE_MAPPER[table_type])

        print(file_path)

        with open(file_path, "w") as w:
            json.dump(json.loads(data), w)

        return jsonify({"status": True, "data": None})

    except FileNotFoundError as err:
        raise Exception("The file is not exist!") from err

    except Exception as err:
        raise Exception(err) from err


# Update The Project Marker
@project_route.route("/projects/file/marker", methods=["POST"])
def update_project_maker():
    try:

        queries = request.args
        table_type = queries.get("type", "hostnames")

        form_data = request.form

        data = form_data["data"]
        path = form_data["path"]
        target = json.loads(form_data["target"])

        file_path = os.path.join(bbot_dir_path, path, TABLE_TYPE_MAPPER[table_type])

        links_path = os.path.join(bbot_dir_path, path, links_table_filename)

        hostnames_path = os.path.join(bbot_dir_path, path, hostnames_table_filename)

        if table_type == "screenshots":

            links = []
            hostnames = []

            with open(hostnames_path, "r") as hReader:
                hostnames = json.load(hReader)

            with open(links_path, "r") as lReader:
                links = json.load(lReader)

            for index, hs in enumerate(hostnames):
                for t in target:
                    key = t["UID"]
                    if hs["UID"] == key:
                        print(index, hostnames[index])
                        hostnames[index] = {**hs, "Marker": t["Marker"]}

            for index, hs in enumerate(links):
                for t in target:
                    key = t["UID"]
                    if hs["UID"] == key:
                        links[index] = {**hs, "Marker": t["Marker"]}

            with open(hostnames_path, "w") as hWriter:
                json.dump(hostnames, hWriter)

            with open(links_path, "w") as lWriter:
                json.dump(links, lWriter)

        with open(file_path, "w") as w:
            json.dump(json.loads(data), w)

        return jsonify({"status": True, "data": None})

    except FileNotFoundError as err:
        raise Exception("The file is not exist!") from err

    except Exception as err:
        raise Exception(err) from err


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


# Get The asset-inventory.csv Base On Path
@project_route.route("/project/screenshot/<path:path>")
def get_project_screenshot(path: str):
    try:
        image_path = os.path.join(
            bbot_dir_path,
            path,
        )
        print(image_path)
        print(os.path.exists(image_path))
        return send_file(os.path.abspath(image_path))

    except FileNotFoundError as err:
        raise Exception("The file is not exist!") from err

    except Exception as err:
        raise Exception(err) from err
