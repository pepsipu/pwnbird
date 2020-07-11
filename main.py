import angr
from arch import arch

binary = arch.Binary64(angr.Project('./tests/coffer-overflow-2/coffer-overflow-2'))
