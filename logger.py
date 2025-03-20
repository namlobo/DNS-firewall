"""
Logging module for DNS proxy with DPI capabilities.
This module logs events and triggers alerts for suspicious activities.
"""

import os
import json
import time
import logging
import threading
import smtplib
from email.mime.text import M