import sys

def unicode_from(in_str):
    if sys.version_info[0] >= 3:
        return in_str
    else:
        return in_str.decode('utf-8')
