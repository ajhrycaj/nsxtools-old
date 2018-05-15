from flask import Flask, render_template, url_for, request, flash, redirect
#from flask_mysqldb import MySQL
from cryptography.fernet import Fernet
from wtforms import Form, BooleanField, StringField, PasswordField, validators, RadioField, SelectField, FileField
from werkzeug.utils import secure_filename
import csv
import MySQLdb
import os
import re
import ipaddress
import configparser

from nsxt import *

app = Flask(__name__)

#For file opening stuff later on
APP_ROOT = os.path.dirname(os.path.abspath(__file__))
APP_STAIC = os.path.join(APP_ROOT, 'static')
APP_UPLOADS = os.path.join(APP_ROOT, 'Uploads')
ALLOWED_EXTENSIONS = set(['csv'])

app.config['UPLOAD_FOLDER'] = APP_UPLOADS

# Create cipher suite for encryption functions
#key = open(os.path.join(APP_STAIC, 'key.enc'), 'rb').read()
#cipher_suite = Fernet(key)

#Function to connect to mysql database
def connectToDatabase():
    #Create DB Connection
    #Open database .ini file
    config = configparser.ConfigParser()
    config.read(os.path.join(APP_STAIC,'db.ini'))

    mysql = MySQLdb.connect(
        config['database']['ipaddr'],
        config['database']['username'],
        config['database']['password'],
        config['database']['dbname']
    )

    return mysql

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def dbGetNsxManagers():

    #Create DB Connection
    mysql = connectToDatabase()

    #SQL query to get all managers
    query = "SELECT * FROM nsxmanagers"

    # Establish connection to database
    cursor = mysql.cursor()

    try:
        #get total number of entries from result of query
        totalentries = cursor.execute(query)
        mysql.commit()

        #Get the results of the call
        entries = cursor.fetchall()

        #Build an object to hold the data
        result = {"length":totalentries,"results":list()}

        for record in entries:
            result["results"].append({
                "id":record[0],
                "type":record[1],
                "ip":record[2],
                "username":record[3],
                "password":record[4],
                "created":record[5],
                "lastmodified":record[6]
                })
    except:
        mysql.rollback()
        result = "Error connecting to database"

    return result

class addFwRuleForm(Form):

    # Get list of managers from database
    result = dbGetNsxManagers()

    #Empty list to store the different choices
    choiceList = []

    #the choices property needs a tuple in the form of (value,label)
    for entry in result['results']:
        choiceList.append((entry['id'],entry['ip']))

    nsxmgr = SelectField('NSX Manager', choices=choiceList)
    srcip = StringField('Source IP', [validators.DataRequired(), validators.IPAddress()])
    dstip = StringField('Destination IP', [validators.DataRequired(), validators.IPAddress()])
    log = BooleanField('Enable Logging', [validators.DataRequired()])
    action = SelectField('Action', choices=[('Permit', 'Permit'), ('Deny', 'Deny')])

def decryptPass(encryptpass):

    try:
        # Create cipher suite for encryption functions
        key = open(os.path.join(APP_STAIC, 'key.enc'), 'rb').read()
        cipher_suite = Fernet(key)

        passwd = cipher_suite.decrypt(encryptpass)
        return passwd
    except:
        return "ERROR: Could not decrypt password"

def getNsxManagerConnectInfoById(nsxId):

    #Connect to Database
    mysql = connectToDatabase()

    #Query
    query = "SELECT * FROM nsxmanagers WHERE id = '{}'".format(nsxId)

    # Create cursor for executing queries
    cursor = mysql.cursor()

    try:
        totalFound = cursor.execute(query)

        #if we got a result
        if totalFound:
            #Get the results
            entry = cursor.fetchone()

            #Get the IP, username, and encrypted password
            ipAddr = entry[2]
            username = entry[3]
            encPasswd = entry[4]

            #decrypt the password
            nsxPasswd = decryptPass(encPasswd)

            #return login info as dictionary
            return {'ipaddr':ipAddr,'username':username,'password':nsxPasswd}

        else:
            return "ERROR: NSX Manager not found in database.  See app developer for more info"
    except:
        mysql.rollback()
        return "ERROR: Query to database failed"

def validateFirewallIpEntry(nsxManager,ipList):

    ###########################################
    # Check for valid IP addresses
    ###########################################

    #There could be multiple, so let's split it
    entries = ipList.split(',')

    #We are going to use this to detect if we ran into something other than an IP address
    notIpList = []

    #Loop through all the entries
    for x in entries:
        try:
            #Valid IP?
            isAddress = ipaddress.ip_address(unicode(x))
        except ValueError:
            #If we got here then it is not a valid IP
            notIpList.append(x)

    ###########################################
    # Check for NSGroups and IPSets
    ###########################################
    if len(notIpList) > 0:
        #print "This IP string has either an IPSet or NSGroup"

        notInNsx = []

        #If we got here, then we have some NSGroups or IPSets
        for x in notIpList:
            #Check to see if this is a NSGroup or IPSet
            if not (nsxManager.getNsGroupIdByName(x) or nsxManager.getIpsetIdByName(x)):
                #If we got here, then it does not exist in NSX
                notInNsx.append(x)

    ###########################################
    # Check for 'any' keyword
    ###########################################
        #If we have anything in this list, then the group does not exist in NSX
        #That is a problem
        if len(notInNsx) > 0:

            notAny = []

            for x in notInNsx:
                if not re.match(r'any',x):
                    #If not keyword 'any', then add to list
                    notAny.append(x)

            if len(notAny) > 0:
                #If we finally got here, then we have no idea what this is.
                return notAny

            #Return False for no errors
            return False

        #Return False for no errors
        return False
    else:
        #print "String contains all IP addresses"
        #return False for no errors
        return False

def validateFirewallPortEntry(nsxManager,portList):

    ###########################################
    # Check for 'tcp/' or '/udp' keywords
    ###########################################

    #First, split by commas
    portSplit = portList.split(',')

    #keep track of non-port entries
    notPort = []

    #Now we check each entry
    for x in portSplit:
        if not (re.match(r'tcp/',x) or re.match(r'udp/',x)):
            notPort.append(x)

    #TODO Check for valid TCP or UDP Port
    #Example: tcp/1000 (valid) vs tcp/1234567 (invalid)
    #TODO Check for valid ranges of TCP or UDP ports
    #Example: tcp/500-1000

    ###########################################
    # Check for NSServices
    ###########################################
    if len(notPort) > 0:
        #print "String contains NSServices"

        # If we got here, we need to check to see if anything in this list is a NSService
        notNsService = []

        #Loop through the list of ports that are not tcp/ or udp/
        for x in notPort:
            if not nsxManager.getServicesIdByName(x):
                # If we got here, it does not exist in the NSX Manager
                notNsService.append(x)

    ###########################################
    # Check for NSServiceGroups
    ###########################################
        if len(notNsService) > 0:

            notNsServiceGroup = []

            for x in notNsService:
                if not nsxManager.getServiceGroupIdByName(x):
                    notNsServiceGroup.append(x)


    ###########################################
    # Check for 'any' keyword
    ###########################################
            # Is there anything in the list
            if len(notNsServiceGroup) > 0:

                notAny = []

                for x in notNsServiceGroup:
                    if not re.match(r'any',x):
                        notAny.append(x)

                if len(notAny) > 0:
                    #If we got here, then we don't know what this is
                    return notAny

                # Return False if there are no errors if notAny = 0
                return False

            # Return False if there are no errors if noNsServiceGroups = 0
            return False

        #Return False if there are no errors if notNsService = 0
        return False
    else:
        #print "String contains all valid TCP or UDP Ports"
        return False

def validateFirewallActionEntry(action):
    #If we don't match 'allow' or 'deny', then error
    #Return True = Error
    #Return False = No Errors
    if not (re.match(r'allow',action) or re.match(r'drop',action)):
        x = []
        x.append(action)
        return x
    else:
        return False

def validateFirewallLoggingEntry(logging):
    #If we don't match 'yes' or 'no', then error
    #Return True = Error
    #Return False = No Errors
    if not (re.match(r'yes',logging) or re.match(r'no',logging)):
        x = []
        x.append(logging)
        return x
    else:
        return False

#Validate the line based from the CSV file to the NSX Manager passed in the function
def validateFirewallCSVLine(nsxManager,line):

    ###############################################
    # Is the section created?
    ###############################################
    sectionName = line[0]
    sectionId = nsxManager.getFirewallSectionIdByName(sectionName)
    sectionError = []

    if sectionId == None:
        #TODO Option to create the section if needed
        sectionError.append(sectionName)
    else:
        sectionError = False

    ###############################################
    # Source IP Validation
    ###############################################
    #Function result will have list of missing IPSets and NSGroups if they are not IPs
    #If all entries are IP addresses, then function will return false
    srcList = validateFirewallIpEntry(nsxManager,line[1])

    ###############################################
    # Destination IP Validation
    ###############################################
    #Function result will have list of missing IPSets and NSGroups if they are not IPs
    #If all entries are IP addresses, then function will return false
    dstList = validateFirewallIpEntry(nsxManager,line[2])

    ###############################################
    # Destination Port Validation
    ###############################################
    dstPortList = validateFirewallPortEntry(nsxManager,line[3])

    ###############################################
    # Action Validation
    ###############################################
    action = validateFirewallActionEntry(line[4])

    ###############################################
    # Logging Validation
    ###############################################
    logging = validateFirewallLoggingEntry(line[5])

    #If either the source or destination ip list have values in them
    if (srcList or dstList):
        #new combined list
        ipList = []

        #if we have sources that were not recognized
        if srcList:
            #iterate through them
            for x in srcList:
                #is this name not already in the iplist?
                if x not in ipList:
                    #if not, then add it
                    ipList.append(x)
                    #print "Adding: " + x + " to missing IP list"
        #repeat above only for destinations
        if dstList:
            for x in dstList:
                if x not in ipList:
                    ipList.append(x)
                    #print "Adding: " + x + " to missing IP list"
    #Else, make it false for no errors
    else:
        ipList = False

    #If there were any errors, the functions above would have returned the name of the entry it did
    #not recognize.  If there were no errors, it will have returned False.
    return {'section':sectionError,
            'iplist':ipList,
            'portlist':dstPortList,
            'action':action,
            'logging':logging}

#Main page
@app.route('/')
def index():
    return render_template('index.html',name='Main Page')

#Contact info page
@app.route('/contact')
def contact():
    return 'Contact info here'

#Page to list all of the NSX Managers currently in the database
@app.route('/listnsxmanager')
def listNsxManagers():

    #Get all NSX Managers
    managerList = dbGetNsxManagers()

    #grab the results from the dictionary
    result = managerList['results']

    return render_template('/listmanager.html', result=result)
app.add_url_rule('/listnsxmanager','listnsxmanager',listNsxManagers)

#Page for inputting required information to add an NSX Manager to the database
@app.route('/addnsxmanager')
def addNsxManagerToDB():
    return render_template('addmanager.html',name='Add NSX Manager')
app.add_url_rule('/addnsxmanager','addnsxmanager',addNsxManagerToDB)

#Action to add the manager
@app.route('/action_addmgr', methods=['POST'])
def action_addmgr():

    # Create cipher suite for encryption functions
    key = open(os.path.join(APP_STAIC, 'key.enc'), 'rb').read()
    cipher_suite = Fernet(key)

    #Create DB Connection
    mysql = connectToDatabase()

    #Get the info about the NSX Manager from the form
    username = request.form['username']
    ipaddr = request.form['ipaddr']
    nsxtype = request.form['type']

    #Create the encrypted password
    encpasswd = cipher_suite.encrypt(bytes(request.form['password']))

    #TODO Validate form input (including password)

    #SQL query to insert entry
    query = "INSERT INTO nsxmanagers(type,ip,username,password) VALUES ('{}','{}','{}','{}')".format(nsxtype,ipaddr,username,encpasswd)

    # Establish connection to database
    cursor = mysql.cursor()

    #Time to insert the record
    try:
        cursor.execute(query)
        mysql.commit()
        result = "NSX Manager Added"
    except:
        mysql.connection.rollback()
        result = "Error adding NSX Manager"

        cursor.close()
        mysql.close()

    return render_template('/action_addmgr.html',result=result)

#Page for inputting required information to add an NSX Manager to the database
@app.route('/addsinglefwrule')
def addSingleFwRule():

    #Create the form object
    form = addFwRuleForm(request.form)

    return render_template('addfwrule.html',form=form)
app.add_url_rule('/addsinglefwrule','addsinglefwrule',addSingleFwRule)

@app.route('/action_addsinglefwrule')
def action_addSingleFwRule():
    return "Test"
app.add_url_rule('/action_addsinglefwrule','action_addsinglefwrule',action_addSingleFwRule)

@app.route('/addbatchfwrule', methods=['GET', 'POST'])
def addBatchFwRule():

    # Get list of managers from database
    result = dbGetNsxManagers()

    #Empty list to store the different choices
    choiceList = []

    #the choices property needs a tuple in the form of (value,label)
    for entry in result['results']:
        choiceList.append((entry['id'],entry['ip']))

    return render_template('addbatchfwrule.html', choices=choiceList)
app.add_url_rule('/addbatchfwrule','addbatchfwrule',addBatchFwRule)

@app.route('/action_addbatchfwrule', methods=['GET','POST'])
def action_addBatchFwRule():

    #Was the file uploaded?
    if 'fwfile' not in request.files:
        return render_template('addbatchfwrule.html')

    #Save the file
    file = request.files['fwfile']

    #Is the file name blank?
    if file.filename == '':
        return render_template('addbatchfwrule.html')

    #If it is an approved file extension, do stuff
    if file and allowed_file(file.filename):
        #Save filename
        filename = secure_filename(file.filename)
        payload = file.read()
        #Create CSV object from the string payload
        reader = csv.reader(payload.splitlines(), delimiter=',')

        #Get the ID of the NSX Manager
        nsxId = request.form['nsxmanager']
        #Get connection info for NSX Manager from database
        connectInfo = getNsxManagerConnectInfoById(nsxId)
        #Init the nsx-t class
        nsxtObj = cNsxt(connectInfo['ipaddr'],connectInfo['username'],connectInfo['password'])

        # Final errors we will pass back to the webpage
        finalErrors = {'section': [], 'iplist': [], 'portlist': [], 'action': [], 'logging': []}
        #This will be the final check to see if we had any errors in our final list
        errorFound = False

        ##########################################
        # Validation of each line
        ##########################################
        #Read the data line by line
        for row in reader:
            #Validate the line
            validationResults = validateFirewallCSVLine(nsxtObj,row)

        ##########################################
        # Create list of missing objects
        ##########################################
            #Loop through all of the keys and values.  If we find a unique value not already in the list
            #then add it to the fianlErrors dictionary for displaying to the end user
            for key,value in validationResults.iteritems():
                print "Looping through " + key + " first with values: "
                print value
                if value:
                    for v in value:
                        if not v in finalErrors[key]:
                            #If we got here, then we didn't have duplicates in this list
                            #We need to add it
                            finalErrors[key].append(v)
                            errorFound = True

        ##########################################
        # Did we have any errors?
        ##########################################
        #If we had an error, then we need to display it to the end user
        if errorFound:
            return render_template('action_addbatchfwrules.html', result=finalErrors, error=errorFound)

        ##########################################
        # Apply new rules to NSX Manager if we got here
        ##########################################
        #Reset file
        file.seek(0)
        payload = file.read()
        #Create CSV object from the string payload
        reader = csv.reader(payload.splitlines(), delimiter=',')

        #ALL CLEAR!!!  We can apply the new rules :)
        for row in reader:
            #Get the sectionId
            sectionId = nsxtObj.getFirewallSectionIdByName(row[0])

            # Let's gather all of the string data
            srcStr = row[1]
            dstStr = row[2]
            svcStr = row[3]
            action = row[4]

            # Separate the data to lists
            srcList = srcStr.split(',')
            dstList = dstStr.split(',')
            svcList = svcStr.split(',')

            result = nsxtObj.createFirewallRule(sectionId, srcList, dstList, svcList, action)

        #Return to the page with errorFound being false
        return render_template('action_addbatchfwrules.html', error=errorFound)
app.add_url_rule('/action_addbatchfwrule','action_addbatchfwrule',action_addBatchFwRule)

@app.route('/addbatchipsets')
def addBatchIpSets():
    # Get list of managers from database
    result = dbGetNsxManagers()

    #Empty list to store the different choices
    choiceList = []

    #the choices property needs a tuple in the form of (value,label)
    for entry in result['results']:
        choiceList.append((entry['id'],entry['ip']))

    return render_template('addbatchipsets.html', choices=choiceList)
app.add_url_rule('/addbatchipsets','addbatchipsets',addBatchIpSets)

@app.route('/action_addbatchipsets', methods=['GET','POST'])
def action_addBatchIPSets():

    #Was the file uploaded?
    if 'fwfile' not in request.files:
        return render_template('addbatchipsets.html')

    #Save the file
    file = request.files['fwfile']

    #Is the file name blank?
    if file.filename == '':
        return render_template('addbatchipsets.html')

    #If it is an approved file extension, do stuff
    if file and allowed_file(file.filename):
        #Save filename
        filename = secure_filename(file.filename)
        payload = file.read()
        #Create CSV object from the string payload
        reader = csv.reader(payload.splitlines(), delimiter=',')

        #Get the ID of the NSX Manager
        nsxId = request.form['nsxmanager']
        #Get connection info for NSX Manager from database
        connectInfo = getNsxManagerConnectInfoById(nsxId)
        #Init the nsx-t class
        nsxtObj = cNsxt(connectInfo['ipaddr'],connectInfo['username'],connectInfo['password'])

        ##########################################
        # Line parsing
        ##########################################
        #Error checking and duplicate tracking for results page
        duplicateIPSet = []
        errorFound = False

        #Read the data line by line
        for row in reader:

            #Get the number of entries in the row
            rowLength = len(row)
            # Create empty list
            ipList = []

            #Does the IPSet already exist in the NSX-T Manager?
            if not nsxtObj.getIpsetIdByName(row[0]):
                #We can have a situation where we just define an IPSet without any addresses
                #If that is so, then we don't need to add any members to this IPSet and we can just
                #create an empty one
                if rowLength == 1:
                    ipList = None
                else:
                    for counter, data in enumerate(row):
                        if counter != 0:
                            ipList.append(data)


                ipsetObj = nsxtObj.createIPSetResourceInventoryMember(row[0],ipList)
                result = nsxtObj.createIPSet(ipsetObj)
                print result
            else:
                #This IPSet already exists in the NSX-T Manager.  Let's not make it again
                duplicateIPSet.append(row[0])
                errorFound = True

        #Return to results page
        return render_template('action_addbatchipsets.html', result=duplicateIPSet, error=errorFound)
app.add_url_rule('/action_addbatchipsets','action_addbatchipsets',action_addBatchIPSets)

if __name__ == '__main__':
    app.run()
