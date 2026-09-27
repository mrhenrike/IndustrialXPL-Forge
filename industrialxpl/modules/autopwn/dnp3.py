"""industrialxpl AutoPwn — dnp3 segment. # authorized use only"""
from .base import SegmentAutoPwn
class Dnp3AutoPwn(SegmentAutoPwn):
    def __init__(self, targets, **kw): super().__init__("dnp3", targets, **kw)
