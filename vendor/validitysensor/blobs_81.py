# Blobs for Synaptics/Validity 06cb:0081 (Lenovo Yoga 920).
# This sensor has the same ROM as 138a:0090 (6.7 build 164) and runs the same fwext
# (6_07f_Lenovo.xpfwext, 6.07.0164), so it uses the 0090 blob set unchanged.
# init_hardcoded and reset_blob were independently verified byte-identical against the Windows
# driver (synaTEE.signed.dll 5.5.2811.1050). That newer driver's clean_slate/db_write_enable
# candidates do NOT work with this ROM+fwext (clean_slate rebooted a stale session; its
# write-enable crashed the sensor on the first fwext block).
from .blobs_90 import init_hardcoded, init_hardcoded_clean_slate, reset_blob, db_write_enable
