from setuptools import setup, find_packages
import os

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

version = "1.0.0"

setup(
    name="jnxbetasec",
    version=version,
    author="Jnx03(Chawabhon Netisingha)",
    author_email="Jn03official@gmail.com",
    description="A comprehensive security library for encryption, hashing, and secure data handling",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/JNX03/jnxbetasec/",
    project_urls={
        "Bug Tracker": "https://github.com/JNX03/jnxbetasec//issues",
        "Documentation": "https://github.com/JNX03/jnxbetasec/#readme",
        "Source Code": "https://github.com/JNX03/jnxbetasec/",
    },
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: Security :: Cryptography",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    keywords="security, encryption, cryptography, hashing, file encryption",
    python_requires=">=3.8",
    install_requires=[
        "cryptography>=39.0.0",
        "pillow>=9.0.0",
        "click>=8.0.0",
        "tqdm>=4.62.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "isort>=5.0.0",
            "mypy>=1.0.0",
            "flake8>=6.0.0",
        ],
        "docs": [
            "sphinx>=6.0.0",
            "sphinx-rtd-theme>=1.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "jnxbetasec=jnxbetasec.cli:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
    platforms="any",
)