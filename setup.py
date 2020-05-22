#!/usr/bin/env python
import codecs
import os.path
import re
from setuptools import setup, find_packages


HERE = os.path.abspath(os.path.dirname(__file__))


def read(*parts):
    return codecs.open(os.path.join(HERE, *parts), 'r').read()


def find_version(*file_paths):
    version_file = read(*file_paths)
    version_match = re.search(r"^__version__ = ['\"]([^'\"]*)['\"]",
                              version_file, re.M)
    if version_match:
        return version_match.group(1)
    raise RuntimeError("Unable to find version string.")



install_requires = [
    "adal~=1.2.2",
    "boto3"
]

setup(
    name='aws_aad_creds',
    version=find_version('aws_aad_creds', '__init__.py'),
    description='AWS Process Credential Provider for AzureAD.',
    long_description=read('README.md'),
    author='Elliot Segler',
    url='https://github.com/elliotsegler/aws-aad-creds',
    packages=find_packages(exclude=['tests']),
    install_requires=install_requires,
    license='Apache License 2.0',
    keywords='aws credentials',
    entry_points={
        'console_scripts': [
            'aws-aad-creds = aws_aad_creds.cli:run'
        ]
    },
    classifiers=(
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Natural Language :: English',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
    ),
)