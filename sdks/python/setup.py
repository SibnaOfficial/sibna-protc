#!/usr/bin/env python3
"""
Sibna Protocol Python SDK - Setup Script
"""

from setuptools import setup, find_packages, Extension
import os
import platform

# Read version from __init__.py
version = "1.0.0"

# Determine library name based on platform
system = platform.system()
if system == "Linux":
    lib_name = "sibna"
    lib_extension = ".so"
elif system == "Darwin":
    lib_name = "sibna"
    lib_extension = ".dylib"
elif system == "Windows":
    lib_name = "sibna"
    lib_extension = ".dll"
else:
    raise OSError(f"Unsupported platform: {system}")

# Check if native library exists
lib_path = os.path.join(os.path.dirname(__file__), "sibna", f"lib{lib_name}{lib_extension}")
has_native_lib = os.path.exists(lib_path)

# Package data
package_data = {}
if has_native_lib:
    package_data["sibna"] = [f"lib{lib_name}{lib_extension}"]

setup(
    name="sibna-protocol",
    version=version,
    author="Sibna Security Team",
    author_email="security@sibna.dev",
    description="Ultra-Secure Communication Protocol - Python SDK",
    long_description=open("README.md").read() if os.path.exists("README.md") else "",
    long_description_content_type="text/markdown",
    url="https://github.com/sibna/protocol",
    packages=find_packages(),
    package_data=package_data,
    include_package_data=True,
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Topic :: Security :: Cryptography",
        "Topic :: Communications :: Chat",
        "License :: OSI Approved :: Apache Software License",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    install_requires=[
        # No external dependencies for core functionality
    ],
    extras_require={
        "dev": [
            "pytest>=7.0",
            "pytest-cov>=4.0",
            "mypy>=1.0",
            "black>=23.0",
            "flake8>=6.0",
        ],
    },
    keywords="cryptography encryption signal secure-messaging e2ee",
    project_urls={
        "Bug Reports": "https://github.com/sibna/protocol/issues",
        "Source": "https://github.com/sibna/protocol",
        "Documentation": "https://docs.sibna.dev",
    },
)
