from config.config import bbot_dir_path, bbot_project_filename, diff_dir_path
from utils.general import create_dir_if_not_exist
from datetime import datetime
import pandas as pd
import os

# ------------------------------------------------------------


def diff_two_obj(obj1, obj2):
    diff_list = []
    diff_obj = {}
    for item1 in obj1:
        is_diff = False
        for item2 in obj2:
            if item1 == item2:
                diff_obj[item1] = obj1[item1]
                if item1 == "Technologies":
                    ob1 = obj1[item1].replace("\n", " ").split(" ")
                    ob2 = obj2[item1].replace("\n", " ").split(" ")
                    ob1.sort()
                    ob2.sort()
                    ob1 = " ".join(ob1)
                    ob2 = " ".join(ob2)

                    if ob1 != ob2:
                        is_diff = True
                        diff_obj[item1] = f"{obj1[item1]} => {obj2[item1]}"
                        print(
                            f"found diff! {item1} old {obj1[item1]}  new {obj2[item1]}"
                        )
                elif obj1[item1] != obj2[item1] and item1 != "":
                    is_diff = True
                    diff_obj[item1] = f"{obj1[item1]} => {obj2[item1]}"
                    print(f"found diff! {item1} old {obj1[item1]}  new {obj2[item1]}")
        if is_diff:
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
        directory = file["directory"]
        base_path = os.path.join(bbot_dir_path, directory)

        df1_path = os.path.join(base_path, date_list[1]["label"], bbot_project_filename)
        df2_path = os.path.join(base_path, date_list[0]["label"], bbot_project_filename)

        df1 = pd.read_csv(df1_path).fillna(value="").to_dict("records")
        df2 = pd.read_csv(df2_path).fillna(value="").to_dict("records")

        new_items = []
        diff_list = []

        print("----------------")
        for new_item in df2:
            new_host = new_item["Host"]
            is_new = False
            for old_item in df1:
                old_host = old_item["Host"]
                if new_host == old_host:
                    is_new = True
                    diffed = diff_two_obj(old_item, new_item)
                    if len(diffed) != 0:
                        diff_list.append(*diffed)
            if not is_new:
                new_items.append(new_item)
        final_diff = diff_list + new_items
        if len(final_diff) != 0:
            parent_dir = os.path.join(diff_dir_path, directory)
            filename = f'diff_{datetime.now().strftime("%Y-%m-%d_%H-%M-%S")}.csv'
            file_path = os.path.join(parent_dir, filename)
            create_dir_if_not_exist(parent_dir)
            df = pd.DataFrame(final_diff)
            df.to_csv(file_path, index=False)
