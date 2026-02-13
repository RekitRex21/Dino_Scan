from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="dino-scan",
    version="1.0.0",
    author="Rex Duvall",
    author_email="rex@duvall.io",
    description="DinoScan - Security scanner for OpenClaw skills",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/rexduvall/dino-scan",
    project_urls={
        "Bug Tracker": "https://github.com/rexduvall/dino-scan/issues",
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    packages=find_packages(),
    python_requires=">=3.7",
    entry_points={
        "console_scripts": [
            "dino-scan=skill_scanner:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)
