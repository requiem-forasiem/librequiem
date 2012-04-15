from _requiem import *

class RequiemError(Exception):
    def __init__(self, errno, strerror=None):
        self.errno = errno
        self._strerror = strerror

    def __str__(self):
        if self._strerror:
            return self._strerror
        return requiem_strerror(self.errno)
