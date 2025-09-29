# ZTVO – Zero Trust Vault Operator

```text
╔═══════════════════════════════════════════════════════════════════════╗
║                                                                       ║
║     ███████╗████████╗██╗   ██╗ ██████╗ ██████╗ ███████╗████████╗     ║
║     ╚══███╔╝╚══██╔══╝██║   ██║██╔═══██╗██╔══██╗██╔════╝╚══██╔══╝     ║
║       ███╔╝    ██║   ██║   ██║██║   ██║██████╔╝█████╗     ██║        ║
║      ███╔╝     ██║   ╚██╗ ██╔╝██║   ██║██╔══██╗██╔══╝     ██║        ║
║     ███████╗   ██║    ╚████╔╝ ╚██████╔╝██║  ██║███████╗   ██║        ║
║     ╚══════╝   ╚═╝     ╚═══╝   ╚═════╝ ╚═╝  ╚═╝╚══════╝   ╚═╝        ║
║                                                                       ║
║                   ZTVO – Zero Trust Vault Operator                   ║
║                             v1.0.0                                    ║
║                                                                       ║
║   Secure Azure Key Vault access with automatic firewall, lock, and   ║
║   role management. Zero trust principles with full state restoration. ║
║                                                                       ║
╚═══════════════════════════════════════════════════════════════════════╝
```

A robust, idempotent helper around Azure Key Vault to temporarily grant the current machine access (via IP firewall and optional role assignment), safely handle resource locks, retrieve secrets, and then restore the previous state.

## Highlights
- Idempotent role assignment: assigns "Key Vault Secrets Officer" only if missing; removes only if this session created it
- Lock-safe firewall changes: detects existing CanNotDelete locks, infers scope from lock name (resource/rg/sub), removes, then restores
- Non-interactive friendly: no prompts for lock handling; status and errors are printed clearly
- Propagation polling with progress bars:
  - Firewall propagation: polls `secret list` until reachable
  - Secret retrieval: polls `secret show` for a specific secret
- Automatic cleanup on exit: restores locks (when removed) and removes temporary role assignment

## Requirements
- Azure CLI (`az`) logged into the correct subscription
- `jq` for JSON parsing
- Bash (script uses `set -e` and process substitution)

## Usage (Typical)
```bash
# Show help (inline comments in script)
# Make executable: chmod +x vault.sh

# Set target vault name
export VAULT_NAME="my-key-vault"

# Run
./vault.sh
```

The script:
1) Verifies Azure CLI availability
2) Determines current public IP
3) Checks Key Vault firewall status
4) If firewall is enabled, checks and removes necessary locks, adds your IP to the firewall, and waits for propagation
5) Assigns "Key Vault Secrets Officer" only if you don���t already have it
6) Provides robust secret listing/retrieval with polling and clear progress
7) Restores previously-removed locks and removes role assignment only if this session created it

## Key Behaviors
- Role Assignment
  - Checks whether the current principal already has the "Key Vault Secrets Officer" role at the vault scope
  - `ROLE_ASSIGNED_NEW=true` only if this run created it ��� Only then removed on exit

- Lock Handling (Inference by Name)
  - Lists locks at the resource scope only
  - Infers scope from lock name prefix:
    - `rg-...` ��� resource group scope
    - `sub-...` ��� subscription scope
    - otherwise ��� resource scope
  - Deletes lock(s) before firewall change; records metadata for restoration

- Firewall IP Allow
  - Adds current public IP to vault firewall
  - Replaces fixed sleep with polling every 5 seconds (up to 5 minutes) to detect when the firewall is effective

- Secret Retrieval
  - When retrieving a specific secret, polls every 5 seconds (up to 5 minutes) with a progress bar
  - Avoids "failed to retrieve" chatter; returns cleanly when available

## Environment Variables
- `VAULT_NAME` (required): target Key Vault name
- Optional tuning variables (edit in script if needed):
  - Poll intervals and timeouts (defaults: 5s x 5m)

## Example ��� Retrieve a Secret
```bash
export VAULT_NAME="corp-secrets"
./vault.sh
# Follow the on-screen prompt to choose a secret; retrieval uses polling for reliability
```

## Safety & Restoration
- If the script removed locks, it restores the exact locks (same names and scopes) on exit
- If the script assigned the role, it removes it on exit

## Notes
- Designed for CI and terminals; favors clear logs over interactive prompts
- Make sure your account has permissions to manage locks and role assignments if you expect those flows to work

## Roadmap Ideas
- Support explicit `--secret <name>` for fully non-interactive retrieval
- Add `--only-firewall`/`--only-role` switches for surgical use
- Exportable JSON summary of actions performed for auditing
