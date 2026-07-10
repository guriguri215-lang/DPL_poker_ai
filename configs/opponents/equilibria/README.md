# Frozen equilibrium registry

Each `*.equilibrium.json` file binds a stable equilibrium version to a complete
river game specification, solver provenance, and strategy profile. The declared
content SHA-256 excludes only the digest field itself. Opponent configs pin that
digest, so changing a game or profile requires a new config identity.
