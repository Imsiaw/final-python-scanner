from config.config import (
    bbot_dir_path,
    links_table_filename,
)
from datetime import datetime
import json
import os


# ------------------------------------------------------------


class Links_Diff:

    def __init__(self):
        self.old_data = []
        self.new_data = []

    def get_projects(self, projects):
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

            old_data_path = os.path.join(
                base_path, date_list[1]["label"], links_table_filename
            )
            new_data_path = os.path.join(
                base_path, date_list[0]["label"], links_table_filename
            )
            new_base_path = os.path.join(base_path, date_list[0]["label"]).replace(
                bbot_dir_path, ""
            )
            old_base_path = os.path.join(base_path, date_list[1]["label"]).replace(
                bbot_dir_path, ""
            )

            with open(old_data_path, "r") as df1_reader:
                self.old_data = json.load(df1_reader)

            with open(new_data_path, "r") as df2_reader:
                self.new_data = json.load(df2_reader)

            new_items = []

            diff_list = []

            print("\n\n----------------Start Diffing----------------\n\n")
            for new_item in self.new_data:
                new_Url = new_item["PUrl"]
                is_repeated = False
                for old_item in self.old_data:
                    old_Url = old_item["PUrl"]
                    if new_Url == old_Url:
                        is_repeated = True
                        diffed = self.diff_two_obj(
                            old_item, new_item, old_base_path, new_base_path
                        )
                        if len(diffed) != 0:
                            diff_list.append(*diffed)
                if not is_repeated:
                    new_items.append(new_item)
                continue

            new_items = [{**i, "Changes": "🔴"} for i in new_items]

            final_diff = diff_list + new_items

            with open(new_data_path, "w") as ww:
                json.dump(final_diff, ww)
            print("\n\n----------------Ends Diffing----------------\n\n")

    def diff_two_obj(self, old_item, new_item, old_path, new_path):
        diff_list = []
        diff_obj = {}

        is_diff = False
        for item1 in old_item:

            for item2 in new_item:
                if item1 == item2:

                    if item1 == "Diff":
                        if diff_obj.get("Diff", None) is None:
                            diff_obj[item1] = old_item[item1]
                        continue

                    diff_obj[item1] = old_item[item1]

                    if item1 == "Changes" or item1 == "UID":
                        diff_obj[item1] = new_item[item1]
                        continue

                    if item1 == "Marker":
                        if (
                            new_item[item1].strip() != ""
                            and old_item[item1].strip() == ""
                        ):
                            diff_obj[item1] = new_item[item1]
                        elif (
                            new_item[item1].strip() == ""
                            and old_item[item1].strip() != ""
                        ):
                            diff_obj[item1] = old_item[item1]
                        else:
                            diff_obj[item1] = new_item[item1]
                        continue

                    elif old_item[item1] != new_item[item1] and item1 != "":
                        is_diff = True

                        if item1 == "Hash":
                            json_data = json.dumps(
                                {
                                    "old": {"f": old_item["Filename"], "p": old_path},
                                    "new": {"f": new_item["Filename"], "p": new_path},
                                }
                            )
                            diff_obj["Diff"] = json_data
                        diff_obj[item1] = new_item[item1]
                        print(
                            f"found diff! {item1} old {old_item[item1]}  new {new_item[item1]}"
                        )
        if is_diff:
            diff_obj["Changes"] = "🟡"
            diff_list.append(diff_obj)
        else:
            diff_list.append(diff_obj)
        return diff_list

    def diff(self, projects):
        self.get_projects(projects)
