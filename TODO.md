### Phase 2 Backlog: Native Container Health Checks
When migrating to enterprise Kubernetes/production Docker Swarm, re-implement native health checks using the internal binaries:

**OPA:**
`test: ["CMD", "/opa", "eval", "--data", "/policy/cloud_policy.rego", "true"]`

**ImmuDB:**
`test: ["CMD", "immuadmin", "status"]`
