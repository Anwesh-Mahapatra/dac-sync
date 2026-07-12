module dac-sync

go 1.22

// The ONLY external dependency. The stdlib has no YAML parser; everything
// else is net/http + encoding/json per the design constraint.
require gopkg.in/yaml.v3 v3.0.1
