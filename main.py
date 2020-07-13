import angr
import sys
from arch import arch

binary = arch.Binary64(angr.Project(sys.argv[1]))
binary.pp_vulnerabilities()