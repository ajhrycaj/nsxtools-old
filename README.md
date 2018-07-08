NSX Tools
---------
Python utility used for quickly executing tasks against an NSX-T Manager

Created By: Andrew Hrycaj

**Files that need to be created:** 

db.ini
------
Configuration file to connect to a mysql database.  This database stores the IP address, login creds, and other information
about the NSX-T Manager you wish to run commands against.  See below for information about creating the file

Place file in 'static' folder

key.enc
-------
Passwords for the NSX-T manager are stored in the database in a encrypted format.  I used the cryptography.fernet library to generate a
key that can be used to decrypt the passwords that are stored.  Included is a python script to generate a key and save it in the 
appropriate location (static folder).


**Files for setup:**

nsxtools.sql
------------

This script will create the mysql database and table needed to store the NSX-T Manager connection information.


**Libraries needed:**

For RedHat/Fedora/CentOS
```
yum install python-devel mysql-devel
```

For Ubuntu:
```
apt-get install libmysqlclient-dev
```

For more recent Ubuntu (2018)
```
apt install default-libmysqlclient-dev
```

**PIP information**

You might need to upgrade come modules to get the NSX-T libraries working for python.  See their setup guide for more information
```
pip install --upgrade pip wheel setuptools
```

**Install NSX-T Python Libraries**

You can get the wheel files from the vmware website.  I used the 2.1 libraries for the code.  Be aware that you must install these in the exact order below!
```
pip install nsx_python_sdk-2.1.0.0.0.7319425-py2.py3-none-any.whl
pip install vapi_runtime-2.7.0-py2.py3-none-any.whl
pip install vapi_common-2.7.0-py2.py3-none-any.whl
pip install vapi_common_client-2.7.0-py2.py3-none-any.whl
```

