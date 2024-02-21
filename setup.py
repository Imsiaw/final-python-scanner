import os
from setuptools import setup
import subprocess

# setup(name="scanner", packages=["scanner"], include_package_data=True)


project_path = os.path.abspath(os.path.dirname(__file__))

view_path = os.path.join(project_path, "view")

scanner_path = os.path.join(project_path, "scanner")

print(project_path, view_path)


# os.system(
#     f"cd {view_path} && npm run build && mv ./dist/index.html {scanner_path}/templates && mv  ./dist/assets/* {scanner_path}/static/assets && mv ./dist/vite.svg {scanner_path}/static/assets"
# )


os.system(f"python3 {project_path}/scanner/main.py")
