#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""The setup script."""

from setuptools import setup, find_packages

with open('Readme.rst') as readme_file:
    readme = readme_file.read()

requirements = ['numpy>=1.12.0']

setup_requirements = ['pytest-runner']

test_requirements = ['pytest']

setup(
    author="Michael Calvin McCoy",
    author_email='calvin.mccoy@protonmail.com',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
    ],
    description="Kravatte Encryption Authentication Tools",
    install_requires=requirements,
    license="MIT license",
    long_description=readme,
    include_package_data=True,
    keywords='kravatte, farfalle, PRF, AEAD, MAC, crypto, encryption',
    name='kravatte',
    packages=find_packages(include=['kravatte']),
    setup_requires=setup_requirements,
    test_suite='tests',
    tests_require=test_requirements,
    url='https://github.com/inmcm/kravatte',
    download_url='https://github.com/inmcm/kravatte/archive/1.0.0.tar.gz',
    version='1.0.0',
    zip_safe=False,
)
