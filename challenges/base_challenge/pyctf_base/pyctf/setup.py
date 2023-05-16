from setuptools import find_packages, setup

setup(
    name='ctf',
    version='0.0.3',
    packages=["ctf"],
    package_dir={
        "ctf": "ctf"
    },
    package_data={
        "ctf": ["ctf/*.yml"]
    },
    include_package_data=True
)

