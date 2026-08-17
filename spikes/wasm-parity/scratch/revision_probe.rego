# SPIKE SCRATCH FILE - not part of the AIL policy source tree.
# Standalone probe used only to test whether data.system.bundles resolves
# identically between an OPA server instance and a compiled WASM module.
# Mirrors the exact reference shape described in the spike spec
# (data.system.bundles[input.bundle_name].manifest.revision), reduced to a
# fixed bundle name matching interceptor/middleware.py's "ail-policies".

package ail.probe

revision := data.system.bundles["ail-policies"].manifest.revision

bundles_present if {
    data.system.bundles
}

bundles_keys := object.keys(data.system.bundles) if {
    data.system.bundles
} else := []
