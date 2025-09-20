#!/usr/bin/env python3
"""
VPEW-AI Setup Script
Vigilancia Proactiva para Endpoints Windows con IA
"""

from setuptools import setup, find_packages
import os

# Read the README file
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

# Read requirements
with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="vpew-ai",
    version="0.1.0",
    author="Equipo SOC",
    author_email="soc@empresa.com",
    description="Vigilancia Proactiva para Endpoints Windows con IA",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/empresa/vpew-ai",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Information Technology",
        "License :: Other/Proprietary License",
        "Operating System :: Microsoft :: Windows",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: System :: Monitoring",
    ],
    python_requires=">=3.10",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=22.0.0",
            "flake8>=5.0.0",
            "mypy>=0.991",
        ],
    },
    entry_points={
        "console_scripts": [
            "vpew-agent=vpew_ai.sensor.agent:main",
            "vpew-backend=vpew_ai.backend.api_server:main",
            "vpew-train=vpew_ai.ml.training.trainer:main",
        ],
    },
    package_data={
        "vpew_ai": [
            "rules/rules/*.yml",
            "config/*.xml",
            "config/*.yaml",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)
