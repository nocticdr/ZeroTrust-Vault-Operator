#!/bin/bash

# Zero Trust Vault Operator (ZTVO) - Azure Key Vault Access Orchestrator
# Requirements: Azure CLI installed and configured

set -e

# ASCII Banner
cat_banner() {
    cat <<'BANNER'
╔═══════════════════════════════════════════════════════════════════════╗
║                                                                       ║
║                    ███████╗████████╗██╗   ██╗ ██████╗                 ║
║                    ╚══███╔╝╚══██╔══╝██║   ██║██╔═══██╗                ║
║                      ███╔╝    ██║   ██║   ██║██║   ██║                ║
║                     ███╔╝     ██║   ╚██╗ ██╔╝██║   ██║                ║
║                    ███████╗   ██║    ╚████╔╝ ╚██████╔╝                ║
║                    ╚══════╝   ╚═╝     ╚═══╝   ╚═════╝                 ║
║                                                                       ║
║                     ZTVO - Zero Trust Vault Operator                  ║
║                             v1.0.0                                    ║
║                                                                       ║
║   Secure Azure Key Vault access with automatic firewall, lock, and    ║
║   role management. Zero trust principles with full state restoration. ║
║                                                                       ║
╚═══════════════════════════════════════════════════════════════════════╝
BANNER
}

# Global variables
VAULT_NAME=""
CURRENT_USER=""
SUBSCRIPTION_NAME=""
ROLE_ASSIGNED=false
ROLE_ASSIGNED_NEW=false
IP_ADDED_TO_FIREWALL=false
CURRENT_IP=""
RESOURCE_LOCK_REMOVED=false
ORIGINAL_LOCK_INFO=""

# Configuration
CONFIG_FILE="$HOME/.azure_keyvault_config"
CACHE_FILE="$HOME/.azure_keyvault_cache"
CACHE_DURATION=2592000  # 30 days in seconds
SECRETS_OFFICER_ROLE="Key Vault Secrets Officer"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Function to check if Azure CLI is installed
check_azure_cli() {
    if ! command -v az &> /dev/null; then
        print_error "Azure CLI is not installed. Please install it first."
        print_info "Visit: https://docs.microsoft.com/en-us/cli/azure/install-azure-cli"
        exit 1
    fi
}

# Function to get current public IP
get_current_ip() {
    print_info "Getting current public IP address..."
    CURRENT_IP=$(curl -s https://icanhazip.com | tr -d '\n\r')
    
    if [[ -z "$CURRENT_IP" ]]; then
        print_error "Failed to get current IP address."
        return 1
    fi
    
    print_success "Current IP address: $CURRENT_IP"
    return 0
}

# Function to check if Key Vault has firewall enabled
check_vault_firewall() {
    print_info "Checking Key Vault firewall settings for: $VAULT_NAME"
    
    local network_acls=$(az keyvault show --name "$VAULT_NAME" --query "properties.networkAcls" -o json 2>/dev/null)
    
    if [[ $? -ne 0 ]] || [[ -z "$network_acls" ]] || [[ "$network_acls" == "null" ]]; then
        print_info "No firewall restrictions detected."
        return 1  # No firewall
    fi
    
    local default_action=$(echo "$network_acls" | jq -r '.defaultAction // "Allow"')
    
    if [[ "$default_action" == "Deny" ]]; then
        print_warning "Key Vault firewall is enabled (default action: Deny)."
        return 0  # Firewall enabled
    else
        print_info "Key Vault firewall allows all access (default action: Allow)."
        return 1  # No effective firewall
    fi
}

# Function to check for resource locks on Key Vault at all levels
check_resource_locks() {
    print_info "Checking for resource locks on vault: $VAULT_NAME"
    local vault_resource_id=$(az keyvault show --name "$VAULT_NAME" --query id -o tsv 2>/dev/null)
    if [[ -z "$vault_resource_id" ]]; then
        print_error "Failed to get vault resource ID."
        return 1
    fi
    local resource_group=$(echo "$vault_resource_id" | cut -d'/' -f5)
    local subscription_id=$(az account show --query id -o tsv 2>/dev/null)
    
    local resource_locks=$(az lock list --resource "$vault_resource_id" -o json 2>/dev/null)
    if [[ -z "$resource_locks" || "$resource_locks" == "[]" ]]; then
        print_info "No locks impacting this resource."
        return 1
    fi
    
    local combined_locks=$(echo "$resource_locks" | jq -c --arg rg "$resource_group" --arg sub "/subscriptions/$subscription_id" --arg rid "$vault_resource_id" '[ .[] | select(.level == "CanNotDelete") as $l | ((if ($l.name|test("^rg-")) then {scope:"resource-group", scope_id:$rg} elif ($l.name|test("^sub-")) then {scope:"subscription", scope_id:$sub} else {scope:"resource", scope_id:$rid} end) + $l) ]')
    if [[ -z "$combined_locks" || "$combined_locks" == "[]" ]]; then
        print_info "No CanNotDelete locks found."
        return 1
    fi
    ORIGINAL_LOCK_INFO=$(echo "$combined_locks" | jq -c '.[]')
    echo "$combined_locks" | jq -r '.[] | "- \(.name) (\(.scope) level)"' | while read -r lock_summary; do
        print_warning "$lock_summary"
    done
    return 0
}

# Function to remove resource locks at all levels
remove_resource_locks() {
    print_info "Removing CanNotDelete resource locks to allow firewall modifications..."
    
    if [[ -z "$ORIGINAL_LOCK_INFO" ]]; then
        print_info "No locks to remove."
        return 0
    fi
    
    local lock_removed=false
    
    # Process each lock with its scope information
    while IFS= read -r lock_info; do
        if [[ -n "$lock_info" ]] && [[ "$lock_info" != "null" ]]; then
            local lock_name=$(echo "$lock_info" | jq -r '.name')
            local lock_scope=$(echo "$lock_info" | jq -r '.scope')
            local scope_id=$(echo "$lock_info" | jq -r '.scope_id')
            
            print_info "Removing lock: $lock_name ($lock_scope level) for scope: $scope_id and id: $lock_info"
            
            local delete_cmd=""
            case "$lock_scope" in
                "resource")
                    delete_cmd="az lock delete --name \"$lock_name\" --resource \"$scope_id\""
                    ;;
                "resource-group")
                    delete_cmd="az lock delete --name \"$lock_name\" --resource-group \"$scope_id\""
                    ;;
                "subscription")
                    delete_cmd="az lock delete --name \"$lock_name\""
                    ;;
                *)
                    print_warning "Unknown lock scope: $lock_scope"
                    continue
                    ;;
            esac
            
            if eval "$delete_cmd" 2>/dev/null; then
                print_success "Removed lock: $lock_name ($lock_scope level)"
                lock_removed=true
            else
                print_warning "Failed to remove lock: $lock_name ($lock_scope level)"
            fi
        fi
    done < <(echo "$ORIGINAL_LOCK_INFO" | jq -c '.')
    
    if [[ "$lock_removed" == "true" ]]; then
        RESOURCE_LOCK_REMOVED=true
        print_success "Resource locks removed successfully."
        sleep 3  # Wait for lock removal to propagate
        return 0
    else
        print_warning "No locks were removed."
        return 1
    fi
}

# Function to restore resource locks to their original scopes
restore_resource_locks() {
    if [[ "$RESOURCE_LOCK_REMOVED" == "true" ]] && [[ -n "$ORIGINAL_LOCK_INFO" ]] && [[ -n "$VAULT_NAME" ]]; then
        print_info "Restoring original resource locks..."
        
        # Restore each lock to its original scope
        while IFS= read -r lock_info; do
            if [[ -n "$lock_info" ]] && [[ "$lock_info" != "null" ]]; then
                local lock_name=$(echo "$lock_info" | jq -r '.name')
                local lock_notes=$(echo "$lock_info" | jq -r '.notes // empty')
                local lock_scope=$(echo "$lock_info" | jq -r '.scope')
                local scope_id=$(echo "$lock_info" | jq -r '.scope_id')
                
                print_info "Restoring lock: $lock_name ($lock_scope level)"
                
                local create_cmd=""
                case "$lock_scope" in
                    "resource")
                        create_cmd="az lock create --name \"$lock_name\" --lock-type CanNotDelete --resource \"$scope_id\""
                        ;;
                    "resource-group")
                        create_cmd="az lock create --name \"$lock_name\" --lock-type CanNotDelete --resource-group \"$scope_id\""
                        ;;
                    "subscription")
                        create_cmd="az lock create --name \"$lock_name\" --lock-type CanNotDelete"
                        ;;
                    *)
                        print_warning "Unknown lock scope for restoration: $lock_scope"
                        continue
                        ;;
                esac
                
                # Add notes if they exist
                if [[ -n "$lock_notes" ]]; then
                    create_cmd="$create_cmd --notes \"$lock_notes\""
                fi
                
                if eval "$create_cmd" &>/dev/null; then
                    print_success "Restored lock: $lock_name ($lock_scope level)"
                else
                    print_warning "Failed to restore lock: $lock_name ($lock_scope level)"
                fi
            fi
        done < <(echo "$ORIGINAL_LOCK_INFO" | jq -c '.')
        
        RESOURCE_LOCK_REMOVED=false
    fi
}

# Function to add current IP to Key Vault firewall
add_ip_to_firewall() {
    if ! get_current_ip; then
        return 1
    fi
    
    # Check and handle resource locks (non-interactive)
    if check_resource_locks; then
        print_warning "Resource locks detected. Temporarily removing to modify firewall (non-interactive)."
        if ! remove_resource_locks; then
            print_error "Failed to remove resource locks. Cannot modify firewall."
            return 1
        fi
    fi
    
    print_info "Adding IP $CURRENT_IP to Key Vault firewall..."
    
    if az keyvault network-rule add \
        --name "$VAULT_NAME" \
        --ip-address "$CURRENT_IP" \
        --output none 2>/dev/null; then
        print_success "IP address $CURRENT_IP added to firewall rules."
        IP_ADDED_TO_FIREWALL=true
        
        # Poll until access is granted or timeout
        wait_for_firewall_propagation
        return 0
    else
        print_warning "Failed to add IP to firewall or IP already exists."
        # Continue anyway as IP might already be whitelisted
        return 0
    fi
}

# Function to remove IP from Key Vault firewall
remove_ip_from_firewall() {
    if [[ "$IP_ADDED_TO_FIREWALL" == "true" ]] && [[ -n "$CURRENT_IP" ]] && [[ -n "$VAULT_NAME" ]]; then
        print_info "Removing IP $CURRENT_IP from Key Vault firewall..."
        
        if az keyvault network-rule remove \
            --name "$VAULT_NAME" \
            --ip-address "$CURRENT_IP" \
            --output none 2>/dev/null; then
            print_success "IP address $CURRENT_IP removed from firewall rules."
        else
            print_warning "Failed to remove IP from firewall."
        fi
        IP_ADDED_TO_FIREWALL=false
    fi
}

# Function to get or set subscription name
get_subscription_name() {
    if [[ -f "$CONFIG_FILE" ]]; then
        SUBSCRIPTION_NAME=$(cat "$CONFIG_FILE")
        if [[ -n "$SUBSCRIPTION_NAME" ]]; then
            print_info "Using configured subscription: $SUBSCRIPTION_NAME"
            echo -n "Is this correct? (Y/n): "
            read -r confirm
            if [[ "$confirm" =~ ^[Nn]$ ]]; then
                set_subscription_name
            fi
        else
            set_subscription_name
        fi
    else
        set_subscription_name
    fi
}

# Function to set and save subscription name
set_subscription_name() {
    print_info "Available subscriptions:"
    
    # Get subscriptions as JSON for numbered selection
    local subscriptions_json=$(az account list --query "[].{Name:name, SubscriptionId:id, State:state}" -o json)
    
    if [[ "$subscriptions_json" == "[]" ]]; then
        print_error "No subscriptions found."
        exit 1
    fi
    
    # Display numbered list
    echo "$subscriptions_json" | jq -r 'to_entries[] | "\(.key + 1). \(.value.Name) (ID: \(.value.SubscriptionId), State: \(.value.State))"'
    
    echo
    local sub_count=$(echo "$subscriptions_json" | jq length)
    
    while true; do
        echo -n "Enter the number of the subscription you want to use (1-$sub_count): "
        read -r sub_number
        
        # Validate input
        if ! [[ "$sub_number" =~ ^[0-9]+$ ]] || [[ "$sub_number" -lt 1 ]] || [[ "$sub_number" -gt "$sub_count" ]]; then
            print_error "Invalid selection. Please enter a number between 1 and $sub_count."
            echo -n "Do you want to try again? (y/N): "
            read -r retry
            if [[ "$retry" =~ ^[Yy]$ ]]; then
                continue
            else
                exit 1
            fi
        fi
        
        # Get subscription name from JSON (arrays are 0-indexed, so subtract 1)
        SUBSCRIPTION_NAME=$(echo "$subscriptions_json" | jq -r ".[$(($sub_number - 1))].Name")
        
        if [[ -z "$SUBSCRIPTION_NAME" ]] || [[ "$SUBSCRIPTION_NAME" == "null" ]]; then
            print_error "Failed to get subscription name from selection."
            echo -n "Do you want to try again? (y/N): "
            read -r retry
            if [[ "$retry" =~ ^[Yy]$ ]]; then
                continue
            else
                exit 1
            fi
        fi
        
        # Save to config file
        echo "$SUBSCRIPTION_NAME" > "$CONFIG_FILE"
        print_success "Subscription '$SUBSCRIPTION_NAME' saved to configuration."
        break
    done
}

# Function to check authentication and subscription
check_authentication() {
    print_info "Checking Azure authentication..."
    
    # Check if logged in
    if ! az account show &> /dev/null; then
        print_warning "Not logged in to Azure. Please log in."
        az login
    fi
    
    # Get subscription name from config
    get_subscription_name
    
    # Check current subscription
    current_subscription=$(az account show --query name -o tsv 2>/dev/null || echo "")
    
    if [[ "$current_subscription" != "$SUBSCRIPTION_NAME" ]]; then
        print_warning "Current subscription: '$current_subscription'"
        print_info "Required subscription: '$SUBSCRIPTION_NAME'"
        
        # Try to set the correct subscription
        if az account set --subscription "$SUBSCRIPTION_NAME" 2>/dev/null; then
            print_success "Switched to subscription: $SUBSCRIPTION_NAME"
        else
            print_error "Failed to switch to subscription '$SUBSCRIPTION_NAME'"
            print_info "Let's reconfigure the subscription..."
            set_subscription_name
            
            if az account set --subscription "$SUBSCRIPTION_NAME"; then
                print_success "Switched to subscription: $SUBSCRIPTION_NAME"
            else
                print_error "Failed to switch subscription. Exiting."
                exit 1
            fi
        fi
    else
        print_success "Already connected to correct subscription: $SUBSCRIPTION_NAME"
    fi
    
    # Get current user info
    CURRENT_USER=$(az ad signed-in-user show --query userPrincipalName -o tsv 2>/dev/null || az account show --query user.name -o tsv)
    print_info "Logged in as: $CURRENT_USER"
}

# Function to check cache validity
is_cache_valid() {
    if [[ ! -f "$CACHE_FILE" ]]; then
        return 1
    fi
    
    local cache_timestamp=$(stat -c %Y "$CACHE_FILE" 2>/dev/null || stat -f %m "$CACHE_FILE" 2>/dev/null || echo 0)
    local current_timestamp=$(date +%s)
    local cache_age=$((current_timestamp - cache_timestamp))
    
    if [[ $cache_age -gt $CACHE_DURATION ]]; then
        return 1
    fi
    
    return 0
}

# Function to get cache age in human readable format
get_cache_age() {
    local cache_timestamp=$(stat -c %Y "$CACHE_FILE" 2>/dev/null || stat -f %m "$CACHE_FILE" 2>/dev/null || echo 0)
    local cache_date=$(date -r "$cache_timestamp" "+%Y-%m-%d %H:%M:%S" 2>/dev/null || date -d "@$cache_timestamp" "+%Y-%m-%d %H:%M:%S" 2>/dev/null)
    echo "$cache_date"
}

# Function to refresh vault cache
refresh_vault_cache() {
    print_info "Refreshing Key Vault cache..."
    
    # Get all key vaults in the subscription
    az keyvault list --query "[].{Name:name, ResourceGroup:resourceGroup, Location:location}" -o json > "$CACHE_FILE"
    
    if [[ $? -eq 0 ]]; then
        local vault_count=$(jq length "$CACHE_FILE")
        print_success "Cache updated with $vault_count vaults"
    else
        print_error "Failed to refresh cache"
        exit 1
    fi
}

# Function to display cached vaults
display_cached_vaults() {
    if [[ -f "$CACHE_FILE" ]] && [[ -s "$CACHE_FILE" ]]; then
        print_info "Cached Key Vaults:"
        jq -r 'to_entries[] | "\(.key + 1). \(.value.Name) (RG: \(.value.ResourceGroup), Location: \(.value.Location))"' "$CACHE_FILE"
        return 0
    else
        return 1
    fi
}

# Function to list vaults with caching logic
list_vaults() {
    local force_refresh=${1:-false}
    
    if [[ "$force_refresh" == "true" ]] || ! is_cache_valid; then
        if [[ "$force_refresh" != "true" ]] && [[ -f "$CACHE_FILE" ]]; then
            print_warning "Cache is older than 30 days, refreshing..."
        fi
        refresh_vault_cache
    elif [[ -f "$CACHE_FILE" ]]; then
        local cache_age=$(get_cache_age)
        print_info "Using cached data from: $cache_age"
        
        echo -n "Do you want to refresh the cache? (y/N): "
        read -r refresh_choice
        if [[ "$refresh_choice" =~ ^[Yy]$ ]]; then
            refresh_vault_cache
        fi
    else
        refresh_vault_cache
    fi
    
}

# Function to select vault from numbered list
select_vault_from_list() {
    if ! display_cached_vaults; then
        print_error "No vaults found in cache."
        return 1
    fi
    
    echo
    local vault_count=$(jq length "$CACHE_FILE")
    
    while true; do
        echo -n "Enter the number of the vault you want to select (1-$vault_count): "
        read -r vault_number
        
        # Validate input
        if ! [[ "$vault_number" =~ ^[0-9]+$ ]] || [[ "$vault_number" -lt 1 ]] || [[ "$vault_number" -gt "$vault_count" ]]; then
            print_error "Invalid selection. Please enter a number between 1 and $vault_count."
            echo -n "Do you want to try again? (y/N): "
            read -r retry
            if [[ "$retry" =~ ^[Yy]$ ]]; then
                continue
            else
                return 1
            fi
        fi
        
        # Get vault name from JSON (arrays are 0-indexed, so subtract 1)
        VAULT_NAME=$(jq -r ".[$(($vault_number - 1))].Name" "$CACHE_FILE")
        
        if [[ -z "$VAULT_NAME" ]] || [[ "$VAULT_NAME" == "null" ]]; then
            print_error "Failed to get vault name from selection."
            echo -n "Do you want to try again? (y/N): "
            read -r retry
            if [[ "$retry" =~ ^[Yy]$ ]]; then
                continue
            else
                return 1
            fi
        fi
        
        # Verify vault exists
        if az keyvault show --name "$VAULT_NAME" &> /dev/null; then
            print_success "Selected vault: $VAULT_NAME"
            return 0
        else
            print_error "Key Vault '$VAULT_NAME' not found or not accessible."
            echo -n "Do you want to try again? (y/N): "
            read -r retry
            if [[ "$retry" =~ ^[Yy]$ ]]; then
                echo
                continue
            else
                return 1
            fi
        fi
    done
}

# Function to select vault
select_vault() {
    echo
    print_info "Available options:"
    echo "1. List all Key Vaults (with caching)"
    echo "2. Enter vault name directly"
    echo "3. Reconfigure subscription"
    echo "4. Exit"
    
    echo -n "Choose an option (1-4): "
    read -r choice
    
    case $choice in
        1)
            echo
            list_vaults
            echo
            select_vault_from_list
            ;;
        2)
            while true; do
                echo -n "Enter the Key Vault name: "
                read -r VAULT_NAME
                
                if [[ -z "$VAULT_NAME" ]]; then
                    print_error "Vault name cannot be empty."
                    continue
                fi
                
                # Verify vault exists
                if az keyvault show --name "$VAULT_NAME" &> /dev/null; then
                    print_success "Selected vault: $VAULT_NAME"
                    break
                else
                    print_error "Key Vault '$VAULT_NAME' not found or not accessible."
                    echo -n "Do you want to try again? (y/N): "
                    read -r retry
                    if [[ "$retry" =~ ^[Yy]$ ]]; then
                        continue
                    else
                        exit 1
                    fi
                fi
            done
            ;;
        3)
            set_subscription_name
            # Refresh authentication after changing subscription
            check_authentication
            select_vault
            return
            ;;
        4)
            print_info "Exiting..."
            exit 0
            ;;
        *)
            print_error "Invalid choice. Please try again."
            select_vault
            return
            ;;
    esac
}

# Function to assign secrets officer role
assign_secrets_officer_role() {
    print_info "Assigning Key Vault Secrets Officer role for vault: $VAULT_NAME"
    
    local vault_resource_id=$(az keyvault show --name "$VAULT_NAME" --query id -o tsv)
    # Check if role assignment already exists
    if az role assignment list --assignee "$CURRENT_USER" --scope "$vault_resource_id" --role "$SECRETS_OFFICER_ROLE" -o tsv --query "[0].roleDefinitionName" 2>/dev/null | grep -q "."; then
        print_info "Secrets Officer role already assigned to $CURRENT_USER at this scope."
        ROLE_ASSIGNED=true
        ROLE_ASSIGNED_NEW=false
        return 0
    fi

    if az role assignment create \
        --role "$SECRETS_OFFICER_ROLE" \
        --assignee "$CURRENT_USER" \
        --scope "$vault_resource_id" &> /dev/null; then
        print_success "Secrets Officer role assigned successfully"
        ROLE_ASSIGNED=true
        ROLE_ASSIGNED_NEW=true
        return 0
    else
        print_warning "Failed to create role assignment (it may already exist or there was an error). Proceeding."
        ROLE_ASSIGNED=true
        ROLE_ASSIGNED_NEW=false
        return 0
    fi
}

# Function to remove secrets officer role
remove_secrets_officer_role() {
    # if [[ "$ROLE_ASSIGNED" == "true" ]] && [[ "$ROLE_ASSIGNED_NEW" == "true" ]] && [[ -n "$VAULT_NAME" ]]; then
    if [[ "$ROLE_ASSIGNED" == "true" ]] && [[ -n "$VAULT_NAME" ]]; then
        print_info "Removing Key Vault Secrets Officer role for vault: $VAULT_NAME"
        
        local vault_resource_id=$(az keyvault show --name "$VAULT_NAME" --query id -o tsv 2>/dev/null)
        
        if [[ -n "$vault_resource_id" ]]; then
            if az role assignment delete \
                --role "$SECRETS_OFFICER_ROLE" \
                --assignee "$CURRENT_USER" \
                --scope "$vault_resource_id" &> /dev/null; then
                print_success "Secrets Officer role removed successfully"
            else
                print_warning "Failed to remove role or role didn't exist"
            fi
        else
            print_warning "Could not get vault resource ID for role removal"
        fi
        ROLE_ASSIGNED=false
    fi
}

# Function to handle firewall and list secrets
handle_firewall_and_list_secrets() {
    # Check if firewall is enabled
    if check_vault_firewall; then
        print_warning "Key Vault has firewall enabled. Automatically adding current IP (non-interactive)."
        if ! add_ip_to_firewall; then
            print_error "Failed to add IP to firewall. Cannot proceed with secret retrieval."
            return 1
        fi
    fi
    
    # Now try to list secrets
    if list_and_select_secrets; then
        return 0
    else
        # If no secrets found, that's OK - don't treat as error
        print_info "No secrets to retrieve from this vault."
        return 0
    fi
}

# Function to list and select secrets
list_and_select_secrets() {
    print_info "Listing secrets in vault: $VAULT_NAME"
    
    # Get secrets list with properties
    local secrets_json=$(az keyvault secret list --vault-name "$VAULT_NAME" --query "[].{Name:name, Enabled:attributes.enabled, Created:attributes.created, Updated:attributes.updated}" -o json 2>/dev/null)
    
    if [[ $? -ne 0 ]]; then
        print_error "Failed to list secrets. This might be a firewall or permission issue."
        return 1
    fi
    
    # Check if secrets_json is valid and not empty
    if [[ -z "$secrets_json" ]] || [[ "$secrets_json" == "null" ]] || [[ "$secrets_json" == "[]" ]]; then
        print_info "No secrets found in vault '$VAULT_NAME'. This is normal for empty vaults."
        return 0  # Not an error - vault is just empty
    fi
    
    # Validate JSON and get count
    local secret_count=$(echo "$secrets_json" | jq length 2>/dev/null)
    if [[ -z "$secret_count" ]] || [[ "$secret_count" == "null" ]] || [[ "$secret_count" -eq 0 ]]; then
        print_info "No secrets found in vault '$VAULT_NAME'."
        return 0  # Not an error
    fi
    
    while true; do
        print_info "Available secrets:"
        echo "$secrets_json" | jq -r 'to_entries[] | "\(.key + 1). \(.value.Name) (Enabled: \(.value.Enabled), Updated: \(.value.Updated))"'
        
        echo
        echo -n "Enter the number of the secret you want to retrieve (1-$secret_count): "
        read -r secret_number
        
        # Validate input
        if ! [[ "$secret_number" =~ ^[0-9]+$ ]] || [[ "$secret_number" -lt 1 ]] || [[ "$secret_number" -gt "$secret_count" ]]; then
            print_error "Invalid selection. Please enter a number between 1 and $secret_count."
            echo -n "Do you want to try again? (y/N): "
            read -r retry
            if [[ "$retry" =~ ^[Yy]$ ]]; then
                continue
            else
                return 0  # User chose not to retry - not an error
            fi
        fi
        
        # Get secret name from JSON (arrays are 0-indexed, so subtract 1)
        local SECRET_NAME=$(echo "$secrets_json" | jq -r ".[$(($secret_number - 1))].Name" 2>/dev/null)
        
        if [[ -z "$SECRET_NAME" ]] || [[ "$SECRET_NAME" == "null" ]]; then
            print_error "Failed to get secret name from selection."
            echo -n "Do you want to try again? (y/N): "
            read -r retry
            if [[ "$retry" =~ ^[Yy]$ ]]; then
                continue
            else
                return 0  # User chose not to retry
            fi
        fi
        
        # Retrieve secret value
        if wait_for_secret_retrieval "$SECRET_NAME"; then
            echo
            echo -n "Do you want to retrieve another secret? (y/N): "
            read -r another
            if [[ "$another" =~ ^[Yy]$ ]]; then
                echo
                continue  # Show the list again
            else
                break  # Exit the function
            fi
        else
            # On timeout, do not show immediate failure spam; just return to menu
            return 0
        fi
    done
    
    return 0
}

# Function to wait for firewall propagation by polling secret list
wait_for_firewall_propagation() {
    local max_seconds=300
    local interval=5
    local elapsed=0

    print_info "Waiting for firewall access (polling every ${interval}s, timeout ${max_seconds}s)..."

    while [[ $elapsed -lt $max_seconds ]]; do
        # Try a lightweight list to verify access
        if az keyvault secret list --vault-name "$VAULT_NAME" >/dev/null 2>&1; then
            echo
            print_success "Firewall rule propagated and access confirmed."
            return 0
        fi

        # Progress bar (50 chars width)
        local percent=$(( (elapsed * 100) / max_seconds ))
        local done=$(( percent / 2 ))
        local left=$(( 50 - done ))
        local bar_done=""
        local bar_left=""
        for _ in $(seq 1 $done); do bar_done+="#"; done
        for _ in $(seq 1 $left); do bar_left+=" "; done
        printf "\r[%s%s] %3d%% | next check in %2ds" "$bar_done" "$bar_left" "$percent" "$interval"

        sleep $interval
        elapsed=$((elapsed + interval))
    done

    echo
    print_warning "Timeout waiting for firewall access after $max_seconds seconds. Continuing anyway."
    return 1
}

# Function to poll for secret retrieval with progress bar
wait_for_secret_retrieval() {
    local secret_name="$1"
    local max_seconds=300
    local interval=5
    local elapsed=0

    print_info "Retrieving secret '$secret_name' (polling every ${interval}s, timeout ${max_seconds}s)..."

    while [[ $elapsed -lt $max_seconds ]]; do
        local secret_value=$(az keyvault secret show --vault-name "$VAULT_NAME" --name "$secret_name" --query value -o tsv 2>/dev/null || true)
        if [[ -n "$secret_value" ]]; then
            echo
            print_success "Secret value for '$secret_name':"
            echo "----------------------------------------"
            echo "$secret_value"
            echo "----------------------------------------"
            return 0
        fi

        # Progress bar (50 chars width)
        local percent=$(( (elapsed * 100) / max_seconds ))
        local done=$(( percent / 2 ))
        local left=$(( 50 - done ))
        local bar_done=""
        local bar_left=""
        for _ in $(seq 1 $done); do bar_done+="#"; done
        for _ in $(seq 1 $left); do bar_left+=" "; done
        printf "\r[%s%s] %3d%% | next check in %2ds" "$bar_done" "$bar_left" "$percent" "$interval"

        sleep $interval
        elapsed=$((elapsed + interval))
    done

    echo
    print_warning "Timeout retrieving secret '$secret_name' after $max_seconds seconds."
    return 1
}

# Cleanup function - ALWAYS runs on exit
cleanup() {
    echo
    print_info "Performing cleanup..."
    remove_ip_from_firewall
    remove_secrets_officer_role
    restore_resource_locks
}

# Enhanced trap to handle all exit scenarios
cleanup_on_exit() {
    local exit_code=$?
    trap - EXIT INT TERM  # Remove traps to avoid recursion
    
    if [[ $exit_code -ne 0 ]]; then
        echo
        print_error "Script exited with error (code: $exit_code)"
    fi
    
    cleanup
    exit $exit_code
}

# Trap to ensure cleanup on any exit scenario
trap cleanup_on_exit EXIT INT TERM

# Main execution
main() {
    cat_banner
    
    # Check prerequisites
    check_azure_cli
    check_authentication
    
    # Select vault
    select_vault
    
    # Assign role and process secrets
    assign_secrets_officer_role
    
    # Wait a moment for role assignment to propagate
    print_info "Waiting for role assignment to propagate (5 seconds)..."
    sleep 5
    
    # Handle firewall and retrieve secrets
    if handle_firewall_and_list_secrets; then
        print_success "Operation completed successfully!"
    else
        print_warning "Could not complete secret retrieval."
        exit 1
    fi
}

# Run main function
main "$@"