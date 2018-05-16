import requests
import ipaddress

from com.vmware.nsx_client import NsGroups,NsServices,IpSets,NsServiceGroups
from com.vmware.nsx.firewall_client import Sections
from com.vmware.nsx.firewall.sections_client import Rules

from com.vmware.nsx.model_client import NSGroup,FirewallService,FirewallRule,FirewallRuleList,FirewallSection, \
    ResourceReference, NSServiceElement, NSService, L4PortSetNSService, IPSet, NSGroupTagExpression, \
    NSGroupSimpleExpression

from vmware.vapi.lib import connect
from vmware.vapi.security.user_password import create_user_password_security_context
from vmware.vapi.stdlib.client.factories import StubConfigurationFactory

class cNsxt:

    #Later we will change this to be for the specific NSX-T controller we choose from a database
    def __init__(self, ipaddr, username, password):

        session = requests.session()
        session.verify = False

        nsx_url = 'https://%s:%s' % (ipaddr, 443)
        connector = connect.get_requests_connector(session=session, msg_protocol='rest', url=nsx_url)
        self.stub_config = StubConfigurationFactory.new_std_configuration(connector)

        security_context = create_user_password_security_context(username,password)
        connector.set_security_context(security_context)

    #Creates an IPv4 Resource record for firewall rules
    def createIpResourceReference(self,IpString):

        #Create resource Reference
        resource = ResourceReference(
            target_display_name=IpString,
            target_id=IpString,
            target_type='IPv4Address'
        )

        return resource

    #Creates an IPSET Resource record for firewall rules
    def createIpsetResourceReference(self,ipsetId):

        #Create resource Reference
        resource = ResourceReference(
            target_id=ipsetId,
            target_type='IPSet'
        )

        return resource

    #Creates an NSGroup Resource record for firewall rules
    def createNsGroupResourceReference(self,nsGroupId):

        #Create resource Reference
        resource = ResourceReference(
            target_id=nsGroupId,
            target_type='NSGroup'
        )

        return resource

    #Creates an IPSet Resource for the NSX Manager Inventory
    #If ipList = None, then it is an empty IPSet
    def createIPSetResourceInventoryMember(self,ipsetName,ipList):

        resource = IPSet(
            display_name=ipsetName,
            resource_type='IPSet',
            ip_addresses=ipList
        )

        return resource

    #creates the NSGroup object with the membership specified.  This will be used to create
    #a new NSGroup object in the inventory
    def createNsGroupInventoryObject(self,nsGroupName,membershipList, memberList):

        resource = NSGroup(
            display_name=nsGroupName,
            membership_criteria=membershipList,
            members=memberList
        )

        return resource

    #Creates an NSGroup Object to be a member of another NSGroup for dynamic association
    def createMemberListObject(self,resourceType,objId):

        if resourceType == "nsgroup":
            resource = NSGroupSimpleExpression(
                op=NSGroupSimpleExpression.OP_EQUALS,
                target_property='id',
                target_type=NSGroupSimpleExpression.TARGET_TYPE_NSGROUP,
                value=objId,
            )
            return resource

        if resourceType == "ipset":
            resource = NSGroupSimpleExpression(
                op=NSGroupSimpleExpression.OP_EQUALS,
                target_property='id',
                target_type=NSGroupSimpleExpression.TARGET_TYPE_IPSET,
                value=objId,
            )
            return resource

    #function to create a tag expression with the name sepecified when the function is called
    #right now this function only uses allows EQUALS as an operator for a VirtualMachine target type
    def createNsGroupTagListObject(self,tagName):

        resource = NSGroupTagExpression(
            scope_op=NSGroupTagExpression.TAG_OP_EQUALS,
            tag=tagName,
            tag_op=NSGroupTagExpression.TAG_OP_EQUALS,
            target_type=NSGroupTagExpression.TARGET_TYPE_VIRTUALMACHINE
        )

        return resource

    def getAllNsGroups(self):

        #First create an object using the authentication and connection information we made in init phase
        nsObj = NsGroups(self.stub_config)
        #This returns the data in JSON from already
        x = nsObj.list()

        sObjects = []
        for sObj in x.results:
            sObjects.append(sObj.display_name)

        return sObjects

    def getNsGroupIdByName(self,displayName):

        nsObj = NsGroups(self.stub_config)
        data = nsObj.list()

        for x in data.results:
            if x.display_name == displayName:
                return x.id
        return None

    def getAllIpsets(self):

        ipsObj = IpSets(self.stub_config)
        data = ipsObj.list()

        return data

    def getIpsetIdByName(self,displayName):

        ipsObj = IpSets(self.stub_config)
        data = ipsObj.list()

        for x in data.results:
            if x.display_name == displayName:
                return x.id
        return None

    def getAllFirewallSections(self):

        fwObj = Sections(self.stub_config)
        x = fwObj.list()

        fObjects = []
        for fObj in x.results:
            fObjects.append(fObj.display_name)
        return fObjects

    #Success = Section ID
    #Failure = None
    def getFirewallSectionIdByName(self, displayName):

        fwObj = Sections(self.stub_config)
        data = fwObj.list()

        for x in data.results:
            if x.display_name == displayName:
                return x.id
        return None

    #Returns information about the specified section.
    #NO rules are printed from this command
    def getFirewallSectionInfoById(self,sectionId):

        fwObj = Sections(self.stub_config)
        result = fwObj.get(sectionId)

        return result

    #Returns information about the specified section.
    #Rules ARE printed from this command
    def getFirewallSectionRulesById(self,sectionId):

        fwObj = Sections(self.stub_config)
        result = fwObj.listwithrules(sectionId)

        return result

    #Searches for service by display name
    #Success = Services ID
    #Failure = None
    def getServicesIdByName(self,displayName):

        nsObj = NsServices(self.stub_config)
        group = nsObj.list()

        for x in group.results:
            if x.display_name == displayName:
                return x.id
        return None

    def getServiceGroupIdByName(self,displayName):

        nsObj = NsServiceGroups(self.stub_config)
        group = nsObj.list()

        for x in group.results:
            if x.display_name == displayName:
                return x.id
        return None

    #Protocol can be TCP or UDP
    def createL4FirewallService(self,protocol,portList):

        L4ServiceSet = L4PortSetNSService(
            destination_ports=portList,
            l4_protocol=protocol
        )

        nsService = FirewallService(
            service=L4ServiceSet
        )

        return nsService

    #Creates a FirewallService object using the ID of a pre-made Service found in the NSX-Manager
    def createFirewallServiceObj(self,objId):

        fwService = FirewallService(
            target_id=objId,
            target_type="NSService"
        )

        return fwService

    def createFirewallSeriveGroupObj(self,objId):

        fwService = FirewallService(
            target_id=objId,
            target_type="NSServiceGroup"
        )

        return fwService

    def createFirewallSection(self,displayName,sectionType,stateful):

        """

        :type  displayName: :class:'str'
        :param displayName:
            Can be any string you want.  This will be the friendly name it goes by in the NSX Manager

        :type  sectionType: :class:'str'
        :param sectionType:
            :attr:'LAYER3'
            :attr:'LAYER2'

        :type  stateful: :class:'bool"
        :param stateful:
            :attr:'True'
            :attr:'False'

        """
        fwSection = FirewallSection(
            display_name=displayName,
            section_type=sectionType,
            stateful=stateful
        )

        fwObj = Sections(self.stub_config)
        result = fwObj.create(fwSection)

        if result.id:
            return result.id
        else:
            return None

    #This is expecting the following:
    #srcString = List of source addresses
    #dstString = List of destination addresses
    #dstPortString = List of destination ports
    def createFirewallRule(self,sectionId,srcString,dstString,dstPortString,action):

        #Create a new list that we will use to hold the source and destination resource records
        sArray = []
        dArray = []

        #TODO Check for 'any' keyword or empty entry for source or destination
        #This will mean ANY for src or dst IP

        #First make sure the type is a list so it will work below
        if type(srcString) is not list:
            tmp = srcString
            srcString = []
            srcString.append(tmp)

        #First make sure the type is a list so it will work below
        if type(dstString) is not list:
            tmp = dstString
            dstString = []
            dstString.append(tmp)

        #TODO Write a validation script to parse through the IP address strings
        for x in srcString:
            try:
                network = ipaddress.ip_address(unicode(x))
                sArray.append(self.createIpResourceReference(x))
            except ValueError:
                ipsetId = self.getIpsetIdByName(x)
                nsgroupid = self.getNsGroupIdByName(x)
                if ipsetId:
                    sArray.append(self.createIpsetResourceReference(ipsetId))
                elif nsgroupid:
                    sArray.append(self.createNsGroupResourceReference(nsgroupid))
                else:
                    print "ERROR: Cannot find source object " + x + " in manager....skipping"

        for y in dstString:
            try:
                network = ipaddress.ip_address(unicode(y))
                dArray.append(self.createIpResourceReference(y))
            except ValueError:
                ipsetId = self.getIpsetIdByName(y)
                nsgroupid = self.getNsGroupIdByName(y)

                if ipsetId:
                    dArray.append(self.createIpsetResourceReference(ipsetId))
                elif nsgroupid:
                    dArray.append(self.createNsGroupResourceReference(nsgroupid))
                else:
                    print "ERROR: Cannot find destination object " + y + " in manager....skipping"


        #Final array with all TCP and UDP ports
        l4Array = []

        #Port List for TCP and UDP
        tcpArray = []
        udpArray = []

        #Get what protocol and port it is
        for x in dstPortString:
            #Split the portocol from the port number
            z = x.split('/')

            if (z[0] == 'TCP' or z[0] == 'tcp'):
                tcpArray.append(z[1])
            elif (z[0] == 'UDP' or z[0] == 'udp'):
                udpArray.append(z[1])
            else:
                #If splitting didn't see what protocol it was, then see if while name is in the NSX-Manager
                result = self.getServicesIdByName(x)
                nsservicegroup = self.getServiceGroupIdByName(x)

                #If we found got something back, it is the ID of the pre-created group
                #Else, it means it could be just an error
                if result:
                    fwService = self.createFirewallServiceObj(result)
                    l4Array.append(fwService)
                elif nsservicegroup:
                    fwService = self.createFirewallSeriveGroupObj(nsservicegroup)
                    l4Array.append(fwService)
                else:
                    print "ERROR: Unknown protocol " + x + "....skipping"

        #Now let's put the TCP and UDP rules into the final list as long as they are not empty
        if len(tcpArray) != 0:
            l4Array.append(self.createL4FirewallService('TCP',tcpArray))
        if len(udpArray) != 0:
            l4Array.append(self.createL4FirewallService('UDP',udpArray))
        #If we had no ports, then set final l4 array to None
        if len(l4Array) == 0:
            l4Array = None

        #action MUST be capitalized
        finalAction = action.upper()

        #Create the firewall rule with our options
        rule = FirewallRule(
            sources=sArray,
            destinations=dArray,
            services=l4Array,
            action=finalAction
        )

        print rule

        ruleObj = Rules(self.stub_config)
        result = ruleObj.create(
            section_id=sectionId,
            firewall_rule=rule,
            operation="insert_bottom"
        )

        return result

    def createIPSet(self,ipset):

        #Create the IPSet object
        ipsObj = IpSets(self.stub_config)

        #Create the IPSet in the NSX Manager
        result = ipsObj.create(ipset)

        #Return the result
        return result

    def createNsGroup(self,nsgroup):

        #Create the NSGroup Object
        nsGroupObj = NsGroups(self.stub_config)

        #Create the NSGroup in the manager
        result = nsGroupObj.create(nsgroup)

        #Return the result
        return result



