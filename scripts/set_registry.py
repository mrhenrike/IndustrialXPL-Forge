#!/usr/bin/env python3

import sys

from pymodbus.client.sync import ModbusTcpClient as ModbusClient

ip = sys.argv[1]
registry = int(sys.argv[2])
value = int(sys.argv[3])
client = ModbusClient(ip, port=502)
client.connect()
client.write_register(registry, value)
