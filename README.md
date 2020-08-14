# NATCracker

NATCracker is a simple python script that can help you open ports on your router using the UPnP protocol without ever touching the router configuration page. Although this is its primary intended purpose, it can also help you interact in other ways with UPnP devices on the network, for example listing them along with their services and actions and parameters and finding the IGDs ([Internet Gateway Devices](https://en.wikipedia.org/wiki/Internet_Gateway_Device_Protocol) - usually your router) on the network.

## Why?

Sometimes you just want to open ports on your gateway but don't have access to its configuration page or don't want to mess around with it, maybe you manage a fleet of these devices all with different configurations and layouts, or maybe you want to let your computer do the hard work for you without building a scraper for the web interface. UPnP can also create temporary port mappings that are limited to a specific remote host, increasing the security of a port mapping in certain scenarios like temporarily hosting a service. In all these cases, if UPnP is available and viable, this script can help you!

## Installation and usage

NATCracker has an unique dependency on [UPnPy](https://github.com/5kyc0d3r/upnpy).

NATCracker does not require installation: to use it, just clone the repository and run `pipenv install` in the local folder. You may then use `pipenv shell` or `pipenv run` to run the script directly from the command line.

The script accepts a number of command-line switches and works around a basic concept of **verbs** and **nouns**:

#### Verbs

* **ADD:** Adds a port mapping to the selected IGD
* **REMOVE:** Removes all port mappings that match a remote host, port and protocol from the IGD
* **LIST:** Lists certain properties and objects

#### Nouns
Nouns are used together with the verb **list** and specify what kind of object to enumerate:

* **DEVICES:** Enumerates all UPnP devices found on the network
* **IGDS:** Enumerates all UPnP IGDs found on the network
* **MAPPINGS:** Enumerates all mappings found on the IGD
* **SERVICES:** Enumerates all UPnP services for a specific device
* **ACTIONS:** Enumerates all actions for a specific service
* **PARAMETERS:** Enumerates all parameters (arguments) for a specific action

For specific help and syntax, please refer to the extensive usage information provided by `natcracker.py --help`.

Note that some actions (namely **add**, **remove** and **list mappings**) require a valid IGD to be present on the network to complete successfully. In case no IGD is found an error will be printed and the script will terminate. If multiple IGDs are found, the user will be prompted to enter the address of the device they intend to interact with.

#### Error handling
In case a handled error occurs during operation, an error message will be presented to the user explaining the reason of failure. As for automatic operation, the script will return an exit code appropriate for the outcome of the action:

* **0** If the action completed successfully
* **1** If an error occurred that prevented the correct execution of the action

At present there are no facilities for an external script to retrieve detailed information about what went wrong in a structured way, other than parsing of the output of the script.
> NOTE: The output message format of the script is not considered to be stable and might change over time.
> Also, even though the program does handle possible exceptions due to wrong usage or input it does not necessarily cover exceptions due to the remote devices not complying to the UPnP specification or returning unspecified internal errors while processing the request, therefore some quirky devices **can** crash the script.

## A few words on security
UPnP is often regarded as an inherently unsafe protocol as it allows any device on the local network to create arbitrary port mappings and puncture holes in the NAT without any authentication whatsoever. While this is true, I feel an attacker that has gained code execution on a local machine would rather implant a reverse shell, which is going to work almost every time and everywhere and also bypass most firewalls, than to mess about with a service that may or may not exist on the local network and that is going to do nothing against firewalling. That being said, there might be edge cases where UPnP would allow for an attack to complete that would otherwise fail, and there are many actions and services that devices like routers provide via this protocol besides port mapping: feel free to use this tool to take a look at the capabilities advertised by your devices to get an idea. Of course these are my two cents - the end user must balance security and convenience for their own network.
> This script is provided as-is and with no warranty. This is just a tool you can use to interact with the devices you own using protocols they advertise. How you use this tool is entirely up to you and I am in no way liable for any action.

## FAQs
#### I am passing command-line switches but the script is ignoring them. Why?
For how the script is structured, **command-line switches have to be specified BEFORE the verb**.
Any switch provided after the verb will be ignored. Typically, you want to specify all your switches as the first thing after the name of the script, and then proceed with the other options that are not provided as switches:

```
python natcracker.py -a -b value -c --switch value -d -e VERB [NOUN [ADDRESS [SERVICE [ACTION]]]]
```


#### I have UPnP-enabled devices on the network but the script does not see them!
Check your firewall rules and make sure that the firewall is not blocking UPnP requests. Also, check that UPnP is enabled on your device (sometimes UPnP is disabled by default).
If the problem persist and you're sure that UPnP is enabled and that the firewall is not blocking the requests, open an issue with as much information as possible and I'll look into it!
