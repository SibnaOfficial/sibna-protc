#!/usr/bin/env python3
"""
Sibna Protocol v3.0.1 — Pure Python SDK
"""

from setuptools import setup, find_packages
import os

version = "3.0.1"

setup(
    name="sibna",
    version=version,
    author="Sibna Security Team",
    author_email="security@sibna.dev",
    description="Sibna Protocol v3.0.1 — Ultra-Secure Communication Protocol (pure Python)",
    long_description=open("README.md").read() if os.path.exists("README.md") else "",
    long_description_content_type="text/markdown",
    url="https://github.com/SibnaOfficial/sibna-protc",
    packages=find_packages(),
    include_package_data=True,
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Topic :: Security :: Cryptography",
        "Topic :: Communications :: Chat",
        "License :: OSI Approved :: Apache Software License",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.9",
    install_requires=[
        "cryptography>=41.0",
    ],
    extras_require={
        "blake3": ["blake3>=1.0"],
        "dev": [
            "pytest>=7.0",
            "pytest-cov>=4.0",
            "mypy>=1.0",
        ],
    },
    keywords="cryptography encryption signal secure-messaging e2ee",
    project_urls={
        "Bug Reports": "https://github.com/SibnaOfficial/sibna-protc/issues",
        "Source": "https://github.com/SibnaOfficial/sibna-protc",
    },
)
