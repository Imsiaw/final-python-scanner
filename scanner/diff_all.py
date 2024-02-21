from utils.general import list_all_projects
from utils.diff import diff_projects
from flask import jsonify

# ------------------------------------------------------------


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


diff_all_projects()
