NSX Tools
---------
Python utility used for quickly executing tasks against an NSX-T Manager

Created By: Andrew Hrycaj

Files that need to be created: 

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
