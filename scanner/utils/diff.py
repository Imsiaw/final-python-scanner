from config.config import (
    bbot_dir_path,
    bbot_project_data_filename,
)
from datetime import datetime
import json
import os

# ------------------------------------------------------------

sc_path = os.path.abspath(__file__)

project_base_path = os.path.abspath(os.path.join(sc_path, "../../.."))

bbot_dir_path = os.path.join(project_base_path, bbot_dir_path)


def diff_two_obj(obj1, obj2):
    diff_list = []
    diff_obj = {}

    is_diff = False
    for item1 in obj1:
        for item2 in obj2:
            if item1 == item2:
                diff_obj[item1] = obj1[item1]

                if item1 == "Marker" or item1 == "Changes":
                    diff_obj[item1] = obj2[item1]
                    continue

                if item1 == "Technology":
                    ob1 = obj1[item1].replace("\n", " ").split(" ")
                    ob2 = obj2[item1].replace("\n", " ").split(" ")
                    ob1.sort()
                    ob2.sort()
                    ob1 = " ".join(ob1)
                    ob2 = " ".join(ob2)

                    if ob1 != ob2:
                        is_diff = True
                        # diff_obj[item1] = f"{obj1[item1]} => {obj2[item1]}"
                        diff_obj[item1] = obj2[item1]
                        print(
                            f"found diff! {item1} old {obj1[item1]}  new {obj2[item1]}"
                        )
                elif obj1[item1] != obj2[item1] and item1 != "":
                    is_diff = True
                    # diff_obj[item1] = f"{obj1[item1]} => {obj2[item1]}"
                    diff_obj[item1] = obj2[item1]
                    print(f"found diff! {item1} old {obj1[item1]}  new {obj2[item1]}")
    if is_diff:
        diff_obj["Changes"] = "🟡"
        if diff_obj["Hostname"] == "tesla.com":
            print(diff_obj)
        diff_list.append(diff_obj)
    else:
        diff_list.append(diff_obj)
    return diff_list


# ------------------------------------------------------------


def diff_projects(projects):
    for file in projects:
        date_list = file["children"]
        if len(date_list) < 2:
            continue

        date_list = sorted(
            date_list,
            key=lambda x: datetime.strptime(x["label"], "%Y_%m_%d_%H%M%S"),
            reverse=True,
        )

        directory = file["label"]
        base_path = os.path.join(bbot_dir_path, directory)

        # The newest project is df2

        df1_path = os.path.join(
            base_path, date_list[1]["label"], bbot_project_data_filename
        )
        df2_path = os.path.join(
            base_path, date_list[0]["label"], bbot_project_data_filename
        )

        df1 = None
        df2 = None

        with open(df1_path, "r") as df1_reader:
            df1 = json.load(df1_reader)
        with open(df2_path, "r") as df2_reader:
            df2 = json.load(df2_reader)

        new_items = []
        diff_list = []

        print("----------------")
        for new_item in df2:
            new_host = new_item["UID"]
            is_repeated = False
            for old_item in df1:
                old_host = old_item["UID"]
                if new_host == old_host:
                    is_repeated = True
                    diffed = diff_two_obj(old_item, new_item)
                    if len(diffed) != 0:
                        diff_list.append(*diffed)
            if not is_repeated:
                new_items.append(new_item)
            continue

        new_items = [{**i, "Changes": "🔴"} for i in new_items]

        final_diff = diff_list + new_items

        with open(df2_path, "w") as ww:
            json.dump(final_diff, ww)
