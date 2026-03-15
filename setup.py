from setuptools import setup, find_packages

setup(
    name="pyaegis",
    version="0.1.0",
    description="Advanced Python Static Application Security Testing (SAST) Engine",
    author="Open Source Community",
    author_email="maintainers@pyaegis.dev",
    packages=find_packages(),
    install_requires=[
        "pyyaml>=6.0.1",
    ],
    entry_points={
        "console_scripts": [
            "pyaegis=pyaegis.cli:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
    ],
    python_requires=">=3.8",
)
