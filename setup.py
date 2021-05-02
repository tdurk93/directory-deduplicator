from setuptools import setup, find_packages

setup(
    name="directory deduplicator",
    version="0.1",
    packages=find_packages(),
    includ_package_data=True,
    install_requires=[
        "Click",
        "xxhash"
    ],
    entry_points="""
        [console_scripts]
        ddd=directorydeduplicator:run
    """,
)
