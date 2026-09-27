"""industrialxpl AutoPwn — ics segment. # authorized use only"""
from .base import SegmentAutoPwn
class IcsAutoPwn(SegmentAutoPwn):
    def __init__(self, targets, **kw): super().__init__("ics", targets, **kw)
