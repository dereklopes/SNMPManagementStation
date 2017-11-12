# SNMP Management Station
An SNMP-enabled device management station written in C utilizing the net-snmp library.

Class project for CS158B, taught by Alberto Prieto in Fall 2017 at San Jose State University.

## Features:
- Displays device interfaces
- Displays device IP neighbors
- Displays traffic on each interface

## Requirements:
- Must have an snmp agent running (and community name known)
- net-snmp library installed (Debian/Ubuntu: `apt-get install libsnmp-dev`)

## TODO:
[X] Get input (time interval between samples, number of samples, agent IP, community name)

[X] Decide on MIB-II objects to use to find the required information (see features)

[X] Use libsnmp to get device interfaces

[X] Use libsnmp to get device IP neighbors

[X] Use libsnmp to get traffic on each interface

[X] Compute traffic from traffic data

[X] Format output to be user-friendly
