# Wifi Killer
### Wifi deauthentication attack script

###### Another old script found in the maze of my hard disk, created to experiment with the Scapy library. It has been adapted to use Python 3 instead of Python 2.7. Command-line options and a simple ui have been added

## Installation

```pip install -r requirements.txt```

## Usage

First of all you need to identify the wireless interface you want to use.
In my case i used the command ```iw dev```.

After that run the script with the parameter ``` --interface <iface_name> ```.
The script will use system commands to set the interface to monitor mode automatically.

You can run ```python wifikiller.py --help``` to retrieve a list of all available options.

```
required arguments:
  --interface INTERFACE
                        Select wireless interface

optional arguments:

  --count COUNT         Set the number of beacons to probe. Set count to -1
                        for a loop (Default: -1)

  --sniff_timeout SNIFF_TIMEOUT
                        Set time to use (in seconds) during sniffing
                        operations (Default: 0.1)

  --ignore_aps IGNORE_APS
                        Set a list of of Access point Mac address list ignored
                        by deauthing attack divided by a comma (,)

  --monitor_creation MONITOR_CREATION
                        Select the method used to create the monitor mode
                        interface. It can be <new> or <old> (Default: new)

                        Using the old method this script will use ifconfig and iwconfig
                        utils. Using the new method this script will use ip and iw
                        utils.

  --silent              Suppress console logging


```
