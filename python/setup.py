from setuptools import setup, find_packages

setup(
    name="security_event_logger",
    version="1.1.0",
    description="OWASP Security Event Logger for Python",
    author="security_event_logger",
    license="CC0 1.0 Universal",
    packages=find_packages(),
    include_package_data=True,
    package_data={"security_event_logger": ["security_events.yaml"]},
    install_requires=["PyYAML>=6.0"],
    python_requires=">=3.6",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: CC0 1.0 Universal (CC0 1.0) Public Domain Dedication",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
)
