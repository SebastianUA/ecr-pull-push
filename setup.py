#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os

from setuptools import setup, find_packages

# User-friendly description from README.md
current_directory = os.path.dirname(os.path.abspath(__file__))
try:
    with open(os.path.join(current_directory, 'README.md'), encoding='utf-8') as f:
        long_description = f.read()
except Exception as ex:
    long_description = ''

setup(
    # The current folder name of the project
    name="ecr-pull-push",
    # Description of library
    description="Continuous Delivery and Deployment (in future) for Terraform",
    # Long description of library
    long_description=long_description,
    long_description_content_type='text/markdown',
    url="",
    # Link from which the project can be downloaded
    download_url="",
    # Name
    author="Vitalii Natarov",
    # Email
    author_email="vitaliy.natarov@yahoo.com, solo.metalisebastian@gmail.com",
    version="0.5.7",
    # License
    license="Proprietary License",
    packages=find_packages("."),
    # List of keyword arguments
    keywords=[],
    # List of packages to install with this one
    install_requires=["boto3", "botocore"],
    tests_require=["mock", "pytest"],
    # https://pypi.org/classifiers/
    classifiers=[
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: POSIX",
        "Programming Language :: Python :: 3",
        "Topic :: Software Development :: Version Control",
    ],
    test_suite="nose.collector",
)
