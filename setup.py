"""DynamoDB Encryption Client for Python."""
import io
import os
import re

from setuptools import find_packages, setup

VERSION_RE = re.compile(r'''__version__ = ['"]([0-9.]+)['"]''')
HERE = os.path.abspath(os.path.dirname(__file__))


def read(*args):
    """Reads complete file contents."""
    return io.open(os.path.join(HERE, *args), encoding='utf-8').read()


def get_version():
    """Reads the version from this module."""
    init = read('src', 'dynamodb_encryption_sdk', 'identifiers.py')
    return VERSION_RE.search(init).group(1)


def get_requirements():
    """Reads the requirements file."""
    requirements = read('requirements.txt')
    return [r for r in requirements.strip().splitlines()]


setup(
    name='dynamodb-encryption-sdk',
    version=get_version(),
    packages=find_packages('src'),
    package_dir={'': 'src'},
    url='https://github.com/awslabs/aws-dynamodb-encryption-python',
    author='Amazon Web Services',
    author_email='aws-cryptools@amazon.com',
    maintainer='Amazon Web Services',
    description='DynamoDB Encryption Client for Python',
    long_description=read('README.rst'),
    keywords='dynamodb-encryption-sdk aws kms encryption dynamodb',
    data_files=[
        'README.rst',
        'CHANGELOG.rst',
        'LICENSE',
        'requirements.txt'
    ],
    license='Apache License 2.0',
    install_requires=get_requirements(),
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: Implementation :: CPython',
        'Topic :: Security',
        'Topic :: Security :: Cryptography'
    ]
)
