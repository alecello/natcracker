#!/usr/bin/env python
import upnpy, sys, getopt, re

# Define version of the script
__version__ = '0.1.0'

# Display help
def printUsageAndExit():
    print('Usage: python natcracker.py [SWITCHES] VERB [[NOUN] [ADDRESS] [SERVICE] [ACTION]]')
    print('SWITCHES:')
    print('    --service <service name>')
    print('        Sets the name of the service used to interact with port forwardings.')
    print('    --add-action <action name>')
    print('        Sets the name of the action used to add a port forwarding.')
    print('    --remove-action <action name>')
    print('        Sets the name of the action used to remove a port forwarding.')
    print('    --get-action <action name>')
    print('        Sets the name of the action used to list all port forwardings.\n')

    print('    -l --local <local port>')
    print('        Sets the local port for the port forwarding.')
    print('    -r --remote <remote port>')
    print('        Sets the remote port for the port forwarding.')
    print('    -i --ip <address>')
    print('        Sets the local IP address to forward traffic to.')
    print('    -h --host <address>')
    print('        Sets the IP address of the remote host allowed to access this port forwarding (defaults to all hosts).')
    print('    -p --protocol (TCP|UDP|BOTH)')
    print('        Sets the protocol to forward (defaults to both).')
    print('    -d --duration <seconds>')
    print('        Sets the duration of the mapping in seconds (defaults to one day).')
    print('    -n --name <mapping name>')
    print('        Sets the name of the mapping (defaults to "NATCracker").')
    print('    --help')
    print('        Displays this screen.')
    print('    --debug')
    print('        Enables debug mode (verbose output).\n')

    print('VERBS')
    print('    add')
    print('        Adds a port forwarding.')
    print('    remove')
    print('        Removes a port forwarding.')
    print('    list')
    print('        Lists an entity type (defined in NOUN).\n')

    print('NOUNS (only for verb "LIST")')
    print('    devices')
    print('        Prints a list of UPnP capable devices currently present on the network.')
    print('    igds')
    print('        Like devices, but restricted to Internet Gateway Devices.')
    print('    services')
    print('        Lists services for a device.')
    print('        After the noun, an IP address must be specified.')
    print('    actions')
    print('        Lists actions for a service on a device.')
    print('        After the noun, an IP address and service ID must be specified.')
    print('    parameters')
    print('        Lists parameters for a specific action.')
    print('        After the noun, an IP address, a service ID and an action name must be specified.')
    print('    mappings')
    print('        Lists UPnP port mappings from the IGD.')
    print('        Optionally an IP address can be provided to limit the output to mappings that resolve to that IP.')
    print('        This is the default choice if no noun is provided.')
    
    exit(1)

# Prints an error message when a service is not found and exits
def printServiceNotFoundAndExit(deviceIP, serviceName):
    print('\nERROR: Service', serviceName, 'not found on device', deviceIP)
    print('If you defined a custom service name, check your input')
    print('If you did not do so, maybe your device uses a non-standard service: try to list its services')
    exit(1)

# Prints an error message when an action is not found and exits
def printActionNotFoundAndExit(deviceIP, serviceName, actionName):
    print('\nERROR: Action', actionName, 'not found in service', serviceName, 'on device', deviceIP)
    print('If you defined a custom action name, check your input')
    print('If you did not do so, maybe your device uses a non-standard action: try to list its actions for that service')
    exit(1)

# Checks wether the provided IP string is valid
def isValidIP(ip):
    # If the parameter is None we skip all the checks
    if ip is None:
        return False

    # The first step is to check the format of the string
    match = re.search('^[0-9]{1,3}([.][0-9]{1,3}){3}$', ip)

    # If the format is not valid we can return right away
    if match is None:
        return False

    # Then we get the individual segments for further analysis
    segments = ip.split('.')

    # We perform two checks:
    #   1) We check that each segment is less than 256
    #   2) That the segment does not start with zero unless it is a literal zero
    for segment in segments:
        # We don't need to check that a segment is a positive integer since we already know by
        # the regular expression that it's only made of digits.
        if int(segment) > 255 or (segment.startswith('0') and len(segment) > 1):
            return False
    
    # We have no reason to doubt the IP is not valid
    return True

# Checks wether the input is a positive integer number
def isPositiveInteger(input, strictlyPositive=False):
    try:
        value = int(input)
        if value > 0 or (not strictlyPositive and value >= 0):
            return True
        else:
            return False
    except ValueError:
        return False

# Get a service with the provided name from the device
# WARNING: Can rise upnpy.exceptions.ServiceNotFoundError
def getServiceByName(device, serviceName):
    return device[serviceName]

# Get an action with the provided name from the service
# WARNING: Can rise upnpy.exceptions.ActionNotFoundError
def getActionByName(service, actionName):
    return getattr(service, actionName)

# Gets the UPnP type of the device using the type string
def getType(device):
    return device.type_.split(':')[3]

# Checks wether the device is an IGP using the type string
def isIGD(device):
    return True if getType(device) == 'InternetGatewayDevice' else False

# Gets the device by IP
# Returns at the first match even though there might be multiple entries for the same IP due to quirky devices
# In my observation this behaviour did not cause any problem
def getDeviceByIP(IP, devices):
    for device in devices:
        if device.host == IP:
            return device
    return None

# MAIN FUNCTION
def main():
    # Greet the user and disable debug by default
    print('NATCracker version', __version__)
    debug = False

    # DEFAULT VARIABLE INITIALIZATION
    portmapService = 'WANIPConn1'                   # UPnP service to be used to interact with portmaps
    portmapAddAction = 'AddPortMapping'             # UPnP action to be used to add a portmap
    portmapGetAction = 'GetGenericPortMappingEntry' # UPnP action to be used to list portmaps
    portmapRemAction = 'DeletePortMapping'          # UPnP action to be used to remove a portmap

    localPort = 0                                   # Local port for the port forwarding
    remotePort = 0                                  # Remote port for the port forwarding
    internalIP = ''                                 # Internal IP to forwarad traffic to
    host = ''                                       # Remote host that is allowed to use the forwarding
    protocol = 'BOTH'                               # Protocol to forward (TCP, UDP or BOTH)
    duration = 86400                                # Portmap duration in seconds. Defaults to one day
    name = 'NATCracker'                             # Name for the mapping

    # PARSING THE COMMAND LINE ARGUMENTS
    # Check the --help to see what switch does what
    try:
        options, commands = getopt.getopt(sys.argv[1:],'l:r:i:h:p:d:n:',['service=','add-action=','remove-action=','get-action=','local=','remote=','ip=','host=','protocol=','duration=','name=','help','debug'])
    except getopt.GetoptError:
        printUsageAndExit()

    # Parse the switches and assign them
    for opt, arg in options:
        if opt == '--service':
            portmapService = arg
        elif opt == '--add-action':
            portmapAddAction = arg
        elif opt == '--remove-action':
            portmapRemAction = arg
        elif opt == '--get-action':
            portmapGetAction = arg
        elif opt == '--help':
            printUsageAndExit()
        elif opt == '--debug':
            debug = True
        elif opt in ('-l', '--local'):
            localPort = arg
        elif opt in ('-r', '--remote'):
            remotePort = arg
        elif opt in ('-i', '--ip'):
            internalIP = arg
        elif opt in ('-h', '--host'):
            host = arg
        elif opt in ('-p', '--protocol'):
            # Check wether the protocol is valid
            if arg.upper() in ('TCP', 'UDP', 'BOTH'):
                protocol = arg.upper()
            else:
                print('\nERROR: Invalid protocol', arg.upper())
                exit(1)
        elif opt in ('-d', '--duration'):
            # Check wether the duration is a positive integer
            if isPositiveInteger(arg):
                duration = int(arg)
            else:
                print('\nERROR: Invalid value for duration: must be a positive integer.')
                exit(1)
        elif opt in ('-n', '--name'):
            name = arg

    # Debug print of all parameters
    if debug:
        print('\nDEBUG - VARIABLES STATE:')
        print('\tService:', portmapService)
        print('\tAdd Action:', portmapAddAction)
        print('\tRemove Action:', portmapRemAction)
        print('\tGet Action:', portmapGetAction)
        print('\tLocal Port:', localPort)
        print('\tRemote Port:', remotePort)
        print('\tInternal IP:', internalIP)
        print('\tRemote Host:', host if host != '' else '0.0.0.0')
        print('\tProtocol:', protocol)
        print('\tDuration:', duration)
        print('\tName:', name)

    # Initialize dictionary with None
    commandList = {'VERB':None,'NOUN':None,'ADDR':None,'SERV':None,'ACTN':None}

    # Parse commands. If we exceed the bundary ignore all further assignements and proceed
    try:
        commandList['VERB'] = commands[0].upper()
        commandList['NOUN'] = commands[1].upper()
        commandList['ADDR'] = commands[2]
        commandList['SERV'] = commands[3]
        commandList['ACTN'] = commands[4]
    except IndexError:
        pass

    # If we don't have a verb quit with an error
    if commandList['VERB'] == None:
        print('\nERROR: Missing verb (either list, add or remove)')
        exit(1)

    # INITIALIZE THE UPnP CLIENT
    # Construct the client and scan for UPnP devices on the network
    client = upnpy.UPnP()
    devices = client.discover()

    # Initialize gateway variable
    gateway = None

    # Find an IGD - but only if we need it
    if commandList['VERB'] in ('ADD', 'REMOVE') or (commandList['VERB'] == 'LIST' and (commandList['NOUN'] == 'MAPPINGS' or commandList['NOUN'] is None)):
        igds = []
        addr = []

        for device in devices:
            if isIGD(device):
                igds.append(device)
                addr.append(device.host)

        if len(igds) == 0:
            print('\nERROR: No IGD (Internet Gateway Device) found on this network')
            print('Your device might be offline or have UPnP disabled')
            print('Please also check that your firewall rules are not blocking UPnP')
            print('Cannot proceed further. Aborting...')
            exit(1)
        elif len(igds) > 1:
            print('\nWARNING: There are multiple IGDs (Internet Gateway Device) on this network')
            print('You must manually choose your gateway (or device you intend to operate) from the following list')
            print('If your device does not appear on this list it might be offline or have UPnP disabled')
            print('Please also check that your firewall rules are not blocking UPnP')

            for igd in igds:
                print('    ', igd.host, '\t(', igd.friendly_name, ')', sep='')

            while True:
                try:
                    choice = input('Please type the IP address of the device you intend to interact with: ')
                except EOFError:
                    print('\n\nAborting...')
                    exit(0)

                if not isValidIP(choice) or choice not in addr:
                    print('\nERROR: Your input is not a valid address from the above list. Try again or press CTRL-D to abort')
                    continue

                gateway = getDeviceByIP(choice, devices)
                break
        else:
            gateway = igds[0]

    # HANDLE LIST REQUEST
    if commandList['VERB'] == 'LIST':
        if commandList['NOUN'] is None or commandList['NOUN'] == 'MAPPINGS':
            try:
                service = getServiceByName(gateway, portmapService)
                action = getActionByName(service, portmapGetAction)
            except upnpy.exceptions.ServiceNotFoundError:
                printServiceNotFoundAndExit(gateway.host, portmapService)
            except upnpy.exceptions.ActionNotFoundError:
                printActionNotFoundAndExit(gateway.host, portmapService, portmapGetAction)

            # Retrieve the entries one at a time using an incremental index
            index = 0

            while True:
                try:
                    # Optionally take an IP address as argument - only show mappings towards that IP
                    Mapping = action(NewPortMappingIndex=index)
                    if not isValidIP(commandList['ADDR']) or commandList['ADDR'] == Mapping['NewInternalClient']:
                        print('[', Mapping['NewRemoteHost'] if Mapping['NewRemoteHost'] != '' else '0.0.0.0', ':', Mapping['NewExternalPort'], '] -> [', Mapping['NewInternalClient'], ':', Mapping['NewInternalPort'], '] protocol ', Mapping['NewProtocol'], ' for ', Mapping['NewLeaseDuration'], ' seconds (', Mapping['NewPortMappingDescription'], ')', sep='')

                    index += 1
                except upnpy.exceptions.SOAPError as exception:
                    # Error 713 is Index Out Of Bounds - we have reached the end of the list
                    if exception.error == 713:
                        if index == 0:
                            print('\nNo mapping found on the IGD.')
                        break
                    elif exception.error == 501:
                        print('\nERROR: An error occurred on the remote device while it attempted to execute the requested action.')
                        exit(1)
                    else:
                        print('\nERROR: An unspecified error occurred while retrivering mappings from the IGD:', exception.description)
                        exit(1)

        elif commandList['NOUN'] in ('DEVICES','IGDS'):
            if commandList['NOUN'] == 'IGDS':
                targets = []

                for device in devices:
                    if isIGD(device):
                        targets.append(device)

            else:
                targets = devices

            if len(targets) == 0:
                print('\nThere are no UPnP', 'devices' if commandList['NOUN'] == 'DEVICES' else 'IGDs', 'on this network')
                exit(0)

            print('\nListing ', len(targets), ' UPnP ', 'device' if commandList['NOUN'] == 'DEVICES' else 'IGD', 's' if len(targets) > 1 else '', ' on the network:', sep='')
            if commandList['NOUN'] == 'DEVICES':
                print('NOTE: Entries preceeded by a star are IGDs')

            for device in targets:
                    print('  * ' if isIGD(device) and commandList['NOUN'] == 'DEVICES' else '    ', '[', device.host, ']\t', device.friendly_name, ' (', getType(device), ')', sep='')

        elif commandList['NOUN'] == 'SERVICES':
            if not isValidIP(commandList['ADDR']):
                print('\nERROR: Invalid usage: you must specify a valid IP address')
                exit(1)

            device = getDeviceByIP(commandList['ADDR'], devices)

            if device is None:
                print('\nERROR: No UPnP device found at address', commandList['ADDR'])
                exit(1)

            services = device.get_services()

            # No need to check wether len(services) == 0 as it is assumed that an UPnP device will expose at least one
            print('\nListing', len(services), 'services' if len(services) > 1 else 'service', 'on device', device.host)
            for s in services:
                serviceName, serviceVersion = s.service.split(':')[-2:]
                print('    ', serviceName, ' (Version ', serviceVersion, ', ID ', s.id.split(':')[-1], ')', sep='')

        elif commandList['NOUN'] == 'ACTIONS':
            if not (isValidIP(commandList['ADDR']) and commandList['SERV'] is not None):
                print('\nERROR: Invalid usage: you must specify a valid IP address and service ID in this order')
                exit(1)

            device = getDeviceByIP(commandList['ADDR'], devices)

            if device is None:
                print('\nERROR: No UPnP device found at address', commandList['ADDR'])
                exit(1)

            try:
                service = getServiceByName(device, commandList['SERV'])
            except upnpy.exceptions.ServiceNotFoundError:
                printServiceNotFoundAndExit(device.host, commandList['SERV'])

            actions = service.get_actions()
            print('\nListing', len(actions), 'actions' if len(actions) > 1 else 'action', 'in service', service.id.split(':')[-1], 'on device', device.host)
            for action in service.get_actions():
                print('   ', action.name)

        elif commandList['NOUN'] == 'PARAMETERS':
            if not (isValidIP(commandList['ADDR']) and commandList['SERV'] is not None and commandList['ACTN'] is not None):
                print('\nERROR: Invalid usage: you must specify a valid IP address, service ID and action name in this order')
                exit(1)

            device = getDeviceByIP(commandList['ADDR'], devices)

            if device is None:
                print('\nERROR: No UPnP device found at address', commandList['ADDR'])
                exit(1)

            try:
                service = getServiceByName(device, commandList['SERV'])
                action = getActionByName(service, commandList['ACTN'])
            except upnpy.exceptions.ServiceNotFoundError:
                printServiceNotFoundAndExit(device.host, commandList['SERV'])
            except upnpy.exceptions.ActionNotFoundError:
                printActionNotFoundAndExit(device.host, commandList['SERV'], commandList['ACTN'])

            if len(action.arguments) > 0:
                print('\nListing', len(action.arguments), 'parameters' if len(action.arguments) > 1 else 'parameter', 'for action', action.name, 'in service', service.id.split(':')[-1], 'on device', device.host)

                for argument in action.arguments:
                    print('   ', argument.name, '(Input)' if argument.direction == 'in' else '(Output)')
            else:
                print('\nThere are no parameters for action', action.name, 'in service', service.id.split(':')[-1], 'on device', device.host)

        else:
            print('\nERROR: Unknown action', commandList['NOUN'])
            exit(1)


    elif commandList['VERB'] == 'ADD':
        # Check that local and remote ports have been defined
        if not (isPositiveInteger(localPort, strictlyPositive=True) and isPositiveInteger(remotePort, strictlyPositive=True)):
            print('\nERROR: Invalid port definition')
            exit(1)

        # Then, validate the Host and internal IP
        if not ((isValidIP(host) or host == '') and isValidIP(internalIP)):
            print('\nERROR: Invalid host or internal IP')
            exit(1)

        try:
            service = getServiceByName(gateway, portmapService)
            action = getActionByName(service, portmapAddAction)
        except upnpy.exceptions.ServiceNotFoundError:
            printServiceNotFoundAndExit(gateway.host, portmapService)
        except upnpy.exceptions.ActionNotFoundError:
            printActionNotFoundAndExit(gateway.host, portmapService, portmapAddAction)

        # Warn the user if they try to add a permanent mapping
        if duration == 0:
            print('\nWARNING: You are about to add a permanent mapping')
            print('This mapping might not be discarded unless you manually remove it later')
            print('Adding a permament mapping and forgetting to later remove it may expose your network devices to malicious actors')

            try:
                response = input('Please confirm that you know what you are doing by typing uppercase yes: ')
                if response != 'YES':
                    print('\nAborting...')
                    exit(0)
            except EOFError:
                print('\n\nAborting...')
                exit(0)

        print('\nAdding mapping [', host if host != '' else '0.0.0.0', ':', remotePort, '] -> [', internalIP, ':', localPort, '] protocol ', protocol if protocol != 'BOTH' else 'TCP and UPD', ' for ', duration, ' seconds', sep='')

        try:
            if protocol == 'BOTH':
                action(NewRemoteHost=host,NewExternalPort=remotePort, NewProtocol='TCP', NewInternalPort=localPort, NewInternalClient=internalIP, NewEnabled=1, NewPortMappingDescription=name, NewLeaseDuration=duration)
                action(NewRemoteHost=host,NewExternalPort=remotePort, NewProtocol='UDP', NewInternalPort=localPort, NewInternalClient=internalIP, NewEnabled=1, NewPortMappingDescription=name, NewLeaseDuration=duration)
            else:
                action(NewRemoteHost=host,NewExternalPort=remotePort, NewProtocol=protocol, NewInternalPort=localPort, NewInternalClient=internalIP, NewEnabled=1, NewPortMappingDescription=name, NewLeaseDuration=duration)
        except upnpy.exceptions.SOAPError as exception:
            if exception.error == 501:
                print('\nERROR: An error occurred on the remote device while it attempted to execute the requested action.')
                exit(1)
            else:
                print('\nERROR: An unspecified error occurred while adding', 'mappings' if protocol == 'BOTH' else 'a mapping', 'for host [', host if host != '' else '0.0.0.0', ':', remotePort, '] protocol TCP: ', exception.description, sep='')
                exit(1)

    elif commandList['VERB'] == 'REMOVE':
        if host != '' and not isValidIP(host):
            print('\nERROR: Invalid remote IP', host)
            exit(1)

        if not isPositiveInteger(remotePort, strictlyPositive=True):
            print('\nERROR: Remote port must be a positive integer')
            exit(1)

        try:
            service = getServiceByName(gateway, portmapService)
            action = getActionByName(service, portmapRemAction)
        except upnpy.exceptions.ServiceNotFoundError:
            printServiceNotFoundAndExit(gateway.host, portmapService)
        except upnpy.exceptions.ActionNotFoundError:
            printActionNotFoundAndExit(gateway.host, portmapService, portmapRemAction)

        print('\nRemoving all mappings for host [', host if host != '' else '0.0.0.0', ':', remotePort, '] protocol ', protocol if protocol != 'BOTH' else 'TCP and UDP', sep='')

        if protocol == 'BOTH':
            while True:
                try:
                    action(NewRemoteHost=host, NewExternalPort=remotePort, NewProtocol='TCP')
                except upnpy.exceptions.SOAPError as exception:
                    if exception.error == 714:
                        break
                    elif exception.error == 501:
                        print('\nERROR: An error occurred on the remote device while it attempted to execute the requested action.')
                        exit(1)
                    else:
                        print('\nERROR: An unspecified error occurred while removing mappings for host [', host if host != '' else '0.0.0.0', ':', remotePort, '] protocol TCP: ', exception.description, sep='')
                        exit(1)
            while True:
                try:
                    action(NewRemoteHost=host, NewExternalPort=remotePort, NewProtocol='UDP')
                except upnpy.exceptions.SOAPError as exception:
                    if exception.error == 714:
                        break
                    elif exception.error == 501:
                        print('\nERROR: An error occurred on the remote device while it attempted to execute the requested action.')
                        exit(1)
                    else:
                        print('\nERROR: An unspecified error occurred while removing mappings for host [', host if host != '' else '0.0.0.0', ':', remotePort, '] protocol UDP: ', exception.description, sep='')
                        exit(1)
        else:
            while True:
                try:
                    action(NewRemoteHost=host, NewExternalPort=remotePort, NewProtocol=protocol)
                except upnpy.exceptions.SOAPError as exception:
                    if exception.error == 714:
                        break
                    elif exception.error == 501:
                        print('\nERROR: An error occurred on the remote device while it attempted to execute the requested action.')
                        exit(1)
                    else:
                        print('\nERROR: An unspecified error occurred while removing mappings for host [', host if host != '' else '0.0.0.0', ':', remotePort, '] protocol ', protocol, ': ', exception.description, sep='')
                        exit(1)

    else:
        print('\nERROR: Unknown action', commandList['VERB'])
        exit(1)

# This script is meant to be run as a standalone
if __name__ == "__main__":
    main()
else:
    raise ImportWarning('This program is not meant to be imported by another script but rather to be run directly.')
