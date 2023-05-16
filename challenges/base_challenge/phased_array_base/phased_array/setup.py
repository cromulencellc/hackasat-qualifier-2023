from setuptools import find_packages, setup

setup(
    name='phased_array',
    version='0.0.2',
    packages=["phased_array"],
    package_dir={
        "phased_array": "phased_array"
    },
    package_data={
        "phased_array": ["phased_array/*.yml"]
    },
    include_package_data=True
)

