"""
DNS Proxy with Deep Packet Inspection (DPI) capabilities.
This module intercepts and handles DNS queries/responses.
"""
import socket
import threading
import time
#from dnslib import DNSRecord, QTYPE, RR, A
import ipaddress
import sys
import logging
from logger import Logger