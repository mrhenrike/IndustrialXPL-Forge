"""industrialxpl AutoPwn — modbus segment. # authorized use only"""
from .base import SegmentAutoPwn
class ModbusAutoPwn(SegmentAutoPwn):
    def __init__(self, targets, **kw): super().__init__("modbus", targets, **kw)
