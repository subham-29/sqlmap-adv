from setuptools import setup, find_packages

setup(
    name='sqli-scanner',
    version='2.0.0',
    description='Advanced SQL Injection Scanner powered by SQLMap with interactive DB/Table/Column dumping and reporting',
    author='Subham Panigrahi',
    author_email='subhampanigrahi.dev@gmail.com',  # Replace with your real or GitHub email
    url='https://github.com/subham-29/sqlmap-adv',  # Replace after publishing
    packages=find_packages(),
    py_modules=['sqli_scanner'],
    install_requires=[
        'colorama',
        'tqdm',
        'requests'
    ],
    entry_points={
        'console_scripts': [
            'sqli-scanner=sqli_scanner:main',
        ],
    },
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Intended Audience :: Developers',
        'Topic :: Security',
        'Topic :: Utilities'
    ],
    python_requires='>=3.6',
    include_package_data=True,
)