from setuptools import find_packages, setup

setup(
    name='cognito-demo',
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    package_data={"cognito-demo": [
        "static/*/*",
        "templates/*",
    ]},
)
