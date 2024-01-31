from config.config import bbot_dir_path
from datetime import datetime
from uuid import uuid4
import os

# ------------------------------------------------------------


def create_dir_if_not_exist(path):
    if not os.path.exists(path):
        os.makedirs(path)


# ------------------------------------------------------------


def list_all_projects():
    bbot_directories = [
        d
        for d in os.listdir(bbot_dir_path)
        if os.path.isdir(os.path.join(bbot_dir_path, d))
    ]

    bbot_files = []

    for dir in bbot_directories:
        path = os.path.join(bbot_dir_path, dir)
        sub_dirs = [
            d
            for d in os.listdir(path)
            if os.path.isdir(os.path.join(path, d))
            and "asset-inventory.csv" in os.listdir(f"{path}/{d}")
        ]
        bbot_files.append(
            {
                "directory": dir,
                "children": [{"label": c, "id": uuid4()} for c in sub_dirs],
                "id": uuid4(),
            }
        )

    for dir in bbot_files:
        date_list = dir["children"]
        date_list = sorted(
            date_list,
            key=lambda x: datetime.strptime(x["label"], "%Y_%m_%d_%H%M%S"),
            reverse=True,
        )
        for file in date_list[:3]:
            path = f"{bbot_dir_path}/{dir['directory']}/{file}/asset-inventory.csv"
    return bbot_files
