// This module's sole purpose is to import scan modules for their side
// effect, i.e. registering via spyre.RegisterSystemScanner or
// spyre.RegisterFileScanner. Those modules are then called via
package config

import (
  _ "github.com/spyre-project/spyre/scanner/yara"
  _ "github.com/spyre-project/spyre/scanner/command"
)
