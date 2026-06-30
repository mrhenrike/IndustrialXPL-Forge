#!/usr/bin/env python3

import sys
import time
from pymodbus.client.sync import ModbusTcpClient as ModbusClient
from pymodbus.exceptions import ConnectionException

ip = sys.argv[1]
registry = int(sys.argv[2])
value = int(sys.argv[3])
client = ModbusClient(ip, port=502)
client.connect()
client.write_register(registry, value)
