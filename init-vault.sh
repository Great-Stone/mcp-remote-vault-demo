#!/bin/bash

set -e

echo "Initializing Vault..."

# Wait for Vault to be ready
echo "Waiting for Vault to be ready..."
until docker exec -e VAULT_TOKEN=root-token vault vault status > /dev/null 2>&1; do
  sleep 2
done

echo "Vault is ready!"

# Wait for Keycloak to be ready (from host)
echo "Waiting for Keycloak to be ready..."
MAX_WAIT=60
WAIT_COUNT=0
until curl -f http://localhost:8080/realms/master > /dev/null 2>&1; do
  if [ $WAIT_COUNT -ge $MAX_WAIT ]; then
    echo "Error: Keycloak did not become ready within ${MAX_WAIT} seconds"
    exit 1
  fi
  echo "Waiting for Keycloak to start... ($WAIT_COUNT/$MAX_WAIT)"
  sleep 2
  WAIT_COUNT=$((WAIT_COUNT + 2))
done

echo "Keycloak is ready!"

# Wait for Keycloak realm to be ready
echo "Waiting for Keycloak realm to be ready..."
WAIT_COUNT=0
until curl -f http://localhost:8080/realms/mcp-demo/.well-known/openid-configuration > /dev/null 2>&1; do
  if [ $WAIT_COUNT -ge $MAX_WAIT ]; then
    echo "Error: Keycloak realm did not become ready within ${MAX_WAIT} seconds"
    echo "Please make sure init-keycloak.sh has been run"
    exit 1
  fi
  echo "Waiting for Keycloak realm... ($WAIT_COUNT/$MAX_WAIT)"
  sleep 2
  WAIT_COUNT=$((WAIT_COUNT + 2))
done

echo "Keycloak realm is ready!"

# Enable JWT auth
echo "Enabling JWT auth method..."
docker exec -e VAULT_TOKEN=root-token vault vault auth enable jwt 2>/dev/null || echo "JWT auth already enabled"

# Delete existing JWT config if it exists (to avoid conflicts)
echo "Clearing existing JWT config (if any)..."
docker exec -e VAULT_TOKEN=root-token vault vault delete auth/jwt/config 2>/dev/null || echo "No existing JWT config to clear"

# Configure JWT auth with Keycloak using jwks_url directly
echo "Configuring JWT auth with Keycloak..."
# Use jwks_url directly instead of oidc_discovery_url to avoid discovery URL issues
# The issuer in Keycloak's discovery doc is http://localhost:8080, but we access via keycloak:8080
# So we use jwks_url directly and set bound_issuer to match the actual issuer in tokens
docker exec -e VAULT_TOKEN=root-token vault vault write auth/jwt/config \
  jwks_url="http://keycloak:8080/realms/mcp-demo/protocol/openid-connect/certs" \
  bound_issuer="http://localhost:8080/realms/mcp-demo"

if [ $? -eq 0 ]; then
  echo "JWT auth configured successfully!"
else
  echo "Error: Failed to configure JWT auth"
  exit 1
fi

# Enable KV secrets engine
echo "Enabling KV secrets engine..."
docker exec -e VAULT_TOKEN=root-token vault vault secrets enable -version=2 -path=secret kv 2>/dev/null || echo "KV secrets engine already enabled"

# Enable Database secrets engine
echo "Enabling Database secrets engine..."
docker exec -e VAULT_TOKEN=root-token vault vault secrets enable database 2>/dev/null || echo "Database secrets engine already enabled"

# Create policy
echo "Creating user-secrets policy..."
# Using Entity name based templating
# Entity name is set to username (alice, bob) for easier management
# Entity alias name is set to Keycloak user ID (JWT 'sub' claim value)
# This allows using entity.name directly in the path for easier management
cat > /tmp/user-secrets-policy.hcl <<POLICY_EOF
path "secret/data/users/{{identity.entity.name}}/*" {
  capabilities = ["read", "list"]
}

path "secret/metadata/users/{{identity.entity.name}}/*" {
  capabilities = ["list"]
}

# Allow users to read their own entity information
path "identity/entity/name/{{identity.entity.name}}" {
  capabilities = ["read"]
}

# Allow users to get database credentials for their own role
path "database/creds/{{identity.entity.name}}" {
  capabilities = ["read"]
}

# Allow users to read their own database role definition (for verification)
path "database/roles/{{identity.entity.name}}" {
  capabilities = ["read"]
}
POLICY_EOF

# Copy policy file to vault container and apply
docker cp /tmp/user-secrets-policy.hcl vault:/tmp/user-secrets-policy.hcl
docker exec -e VAULT_TOKEN=root-token vault vault policy write user-secrets /tmp/user-secrets-policy.hcl
rm -f /tmp/user-secrets-policy.hcl

# Get JWT mount accessor for entity alias creation
echo "Getting JWT mount accessor..."
JWT_ACCESSOR=$(docker exec -e VAULT_TOKEN=root-token vault vault read -field=accessor sys/auth/jwt 2>/dev/null || echo "")
if [ -z "$JWT_ACCESSOR" ]; then
  echo "Error: Could not get JWT accessor"
  exit 1
fi
echo "JWT accessor: $JWT_ACCESSOR"

# Create entities for Keycloak users
echo "Creating Vault entities for Keycloak users..."

# Get Keycloak admin token
echo "Getting Keycloak admin token..."
KC_TOKEN=""
RETRY_COUNT=0
MAX_RETRIES=5

while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
  KC_TOKEN=$(curl -s -X POST "http://localhost:8080/realms/master/protocol/openid-connect/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=admin" \
    -d "password=admin" \
    -d "grant_type=password" \
    -d "client_id=admin-cli" 2>/dev/null | python3 -c "import sys, json; data = json.load(sys.stdin); print(data.get('access_token', ''))" 2>/dev/null || echo "")
  
  if [ -n "$KC_TOKEN" ] && [ "$KC_TOKEN" != "None" ] && [ "$KC_TOKEN" != "" ]; then
    break
  fi
  
  RETRY_COUNT=$((RETRY_COUNT + 1))
  if [ $RETRY_COUNT -lt $MAX_RETRIES ]; then
    echo "Retrying to get Keycloak token... ($RETRY_COUNT/$MAX_RETRIES)"
    sleep 3
  fi
done

if [ -z "$KC_TOKEN" ] || [ "$KC_TOKEN" == "None" ] || [ "$KC_TOKEN" == "" ]; then
  echo "Warning: Could not get Keycloak token after $MAX_RETRIES attempts, skipping entity creation"
  echo "This is not critical - entities will be created automatically on first login"
else
  # Get users from Keycloak
  echo "Fetching users from Keycloak..."
  USERS_JSON=$(curl -s -X GET "http://localhost:8080/admin/realms/mcp-demo/users" \
    -H "Authorization: Bearer ${KC_TOKEN}")
  
  # Create entity for each user
  echo "$USERS_JSON" | python3 <<PYTHON_SCRIPT | while IFS='|' read -r user_id username; do
import sys
import json

try:
    users = json.load(sys.stdin)
    for user in users:
        user_id = user.get('id', '')
        username = user.get('username', '')
        if user_id and username:
            # Create entity with name = username (for easier management)
            print(f"Creating entity for user: {username} (ID: {user_id})")
            # Entity creation will be done via docker exec
            print(f"{user_id}|{username}")
except Exception as e:
    print(f"Error: {e}", file=sys.stderr)
    sys.exit(1)
PYTHON_SCRIPT
    if [ -n "$user_id" ] && [ -n "$username" ]; then
      echo "Creating entity for user: $username (ID: $user_id)"
      
      # Delete existing entity if it exists (by name)
      echo "Deleting existing entity if exists (by name: $username)..."
      docker exec -e VAULT_TOKEN=root-token vault vault delete identity/entity/name/$username 2>/dev/null || true
      
      # Create entity with name = username (for easier management)
      ENTITY_RESPONSE=$(docker exec -e VAULT_TOKEN=root-token vault vault write -format=json identity/entity \
        name="$username" \
        metadata=user_id="$user_id" \
        metadata=source="keycloak" 2>&1)
      
      # Get entity ID
      ENTITY_ID=$(echo "$ENTITY_RESPONSE" | python3 -c "import sys, json; data = json.load(sys.stdin); print(data.get('data', {}).get('id', ''))" 2>/dev/null || echo "")
      
      if [ -z "$ENTITY_ID" ]; then
        # Entity may already exist, try to read it
        ENTITY_READ=$(docker exec -e VAULT_TOKEN=root-token vault vault read -format=json identity/entity/name/$username 2>/dev/null || echo "")
        if [ -n "$ENTITY_READ" ]; then
          ENTITY_ID=$(echo "$ENTITY_READ" | python3 -c "import sys, json; data = json.load(sys.stdin); print(data.get('data', {}).get('id', ''))" 2>/dev/null || echo "")
        fi
      fi
      
      if [ -n "$ENTITY_ID" ]; then
        echo "Entity created/updated: $ENTITY_ID"
        
        # Delete existing alias if it exists (by canonical_id)
        echo "Deleting existing alias if exists for entity: $ENTITY_ID..."
        docker exec -e VAULT_TOKEN=root-token vault vault list -format=json identity/entity-alias/id 2>/dev/null | python3 <<PYTHON_SCRIPT | while IFS='|' read -r alias_id alias_canonical_id; do
import sys
import json

try:
    alias_ids = json.load(sys.stdin)
    for alias_id in alias_ids:
        # We'll check canonical_id in bash, not here
        print(f"{alias_id}")
except Exception as e:
    pass
PYTHON_SCRIPT
          if [ -n "$alias_id" ]; then
            ALIAS_CANONICAL_ID=$(docker exec -e VAULT_TOKEN=root-token vault vault read -format=json identity/entity-alias/id/$alias_id 2>/dev/null | python3 -c "import sys, json; print(json.load(sys.stdin).get('data', {}).get('canonical_id', ''))" 2>/dev/null || echo "")
            if [ "$ALIAS_CANONICAL_ID" = "$ENTITY_ID" ]; then
              docker exec -e VAULT_TOKEN=root-token vault vault delete identity/entity-alias/id/$alias_id 2>/dev/null || true
            fi
          fi
        done
        
        # Create entity alias (name = Keycloak user ID, which matches JWT 'sub' claim)
        echo "Creating entity alias for user: $username (alias name: $user_id)"
        ALIAS_RESPONSE=$(docker exec -e VAULT_TOKEN=root-token vault vault write -format=json identity/entity-alias \
          name="$user_id" \
          canonical_id="$ENTITY_ID" \
          mount_accessor="$JWT_ACCESSOR" 2>&1)
        
        if echo "$ALIAS_RESPONSE" | grep -q "error"; then
          echo "Warning: Failed to create alias for user $username"
        else
          echo "Entity alias created for user: $username"
        fi
      else
        echo "Warning: Could not create or find entity for user: $username"
      fi
    fi
  done
fi

# Create JWT role
echo "Creating JWT role..."
# user_claim="sub" sets the Entity alias name to JWT's 'sub' claim value
# Vault will automatically find existing entities with matching alias name and use them
docker exec -e VAULT_TOKEN=root-token vault vault write auth/jwt/role/user \
  role_type="jwt" \
  bound_audiences="mcp-client,account" \
  user_claim="sub" \
  groups_claim="groups" \
  policies="user-secrets" \
  ttl=1h \
  max_ttl=24h

# Create Jira secrets for alice user only (for comparison with bob)
echo "Creating Jira secrets for alice user only..."

# Entity name is now username, so use "alice" directly
# Note: vault kv put automatically adds "data/" prefix for KV v2, so use "secret/users/..." not "secret/data/users/..."
echo "Creating Jira secret for alice (entity name: alice)..."
docker exec -e VAULT_TOKEN=root-token vault vault kv put secret/users/alice/jira \
  username="alice-jira" \
  password="alice-jira-password" \
  api_token="alice-jira-token-12345" 2>&1
if [ $? -eq 0 ]; then
  echo "Jira secret created for alice at path: secret/data/users/alice/jira"
else
  echo "Warning: Failed to create Jira secret for alice"
fi

echo "Bob user will not have Jira secret (for comparison)"

echo "Creating GitHub secrets for alice and bob users..."

# Create GitHub secret for alice
echo "Creating GitHub secret for alice (entity name: alice)..."
docker exec -e VAULT_TOKEN=root-token vault vault kv put secret/users/alice/github \
  token="alice-github-token-12345" \
  username="alice-github" 2>&1
if [ $? -eq 0 ]; then
  echo "GitHub secret created for alice at path: secret/data/users/alice/github"
else
  echo "Warning: Failed to create GitHub secret for alice"
fi

# Create GitHub secret for bob
echo "Creating GitHub secret for bob (entity name: bob)..."
docker exec -e VAULT_TOKEN=root-token vault vault kv put secret/users/bob/github \
  token="bob-github-token-67890" \
  username="bob-github" 2>&1
if [ $? -eq 0 ]; then
  echo "GitHub secret created for bob at path: secret/data/users/bob/github"
else
  echo "Warning: Failed to create GitHub secret for bob"
fi

# Configure PostgreSQL connection in Database secrets engine
echo "Configuring PostgreSQL connection in Database secrets engine..."

# Wait for PostgreSQL to be ready
echo "Waiting for PostgreSQL to be ready..."
MAX_WAIT=60
WAIT_COUNT=0
until docker exec postgresql pg_isready -U postgres > /dev/null 2>&1; do
  if [ $WAIT_COUNT -ge $MAX_WAIT ]; then
    echo "Error: PostgreSQL did not become ready within ${MAX_WAIT} seconds"
    exit 1
  fi
  echo "Waiting for PostgreSQL to start... ($WAIT_COUNT/$MAX_WAIT)"
  sleep 2
  WAIT_COUNT=$((WAIT_COUNT + 2))
done

echo "PostgreSQL is ready!"

# Configure PostgreSQL plugin connection
echo "Configuring PostgreSQL plugin connection..."
docker exec -e VAULT_TOKEN=root-token vault vault write database/config/postgresql \
  plugin_name=postgresql-database-plugin \
  allowed_roles="*" \
  connection_url="postgresql://{{username}}:{{password}}@postgresql:5432/mcp_demo?sslmode=disable" \
  username="vault_admin" \
  password="vault-admin-password-12345" \
  verify_connection=false 2>&1

if [ $? -eq 0 ]; then
  echo "PostgreSQL connection configured successfully!"
else
  echo "Warning: Failed to configure PostgreSQL connection"
fi

# Create dynamic roles for alice and bob
echo "Creating PostgreSQL dynamic roles for alice and bob users..."

# Create role for alice
echo "Creating PostgreSQL role for alice (entity name: alice)..."
ROLE_CREATE_OUTPUT=$(docker exec -e VAULT_TOKEN=root-token vault vault write database/roles/alice \
  db_name=postgresql \
  creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT USAGE ON SCHEMA public TO \"{{name}}\"; GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO \"{{name}}\"; GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO \"{{name}}\"; ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO \"{{name}}\"; ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO \"{{name}}\";" \
  revocation_statements="REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM \"{{name}}\"; REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM \"{{name}}\"; REVOKE USAGE ON SCHEMA public FROM \"{{name}}\"; DROP ROLE IF EXISTS \"{{name}}\";" \
  default_ttl="1h" \
  max_ttl="24h" 2>&1)

if [ $? -eq 0 ]; then
  echo "PostgreSQL role created for alice"
  # Verify role was created
  ROLE_VERIFY=$(docker exec -e VAULT_TOKEN=root-token vault vault read database/roles/alice 2>&1)
  if echo "$ROLE_VERIFY" | grep -q "db_name"; then
    echo "✓ Verified: PostgreSQL role 'alice' exists in Vault"
  else
    echo "⚠ Warning: PostgreSQL role 'alice' may not have been created correctly"
  fi
else
  echo "Error: Failed to create PostgreSQL role for alice"
  echo "Output: $ROLE_CREATE_OUTPUT"
fi

# Create role for bob
echo "Creating PostgreSQL role for bob (entity name: bob)..."
ROLE_CREATE_OUTPUT=$(docker exec -e VAULT_TOKEN=root-token vault vault write database/roles/bob \
  db_name=postgresql \
  creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT USAGE ON SCHEMA public TO \"{{name}}\"; GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO \"{{name}}\"; GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO \"{{name}}\"; ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO \"{{name}}\"; ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO \"{{name}}\";" \
  revocation_statements="REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM \"{{name}}\"; REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM \"{{name}}\"; REVOKE USAGE ON SCHEMA public FROM \"{{name}}\"; DROP ROLE IF EXISTS \"{{name}}\";" \
  default_ttl="1h" \
  max_ttl="24h" 2>&1)

if [ $? -eq 0 ]; then
  echo "PostgreSQL role created for bob"
  # Verify role was created
  ROLE_VERIFY=$(docker exec -e VAULT_TOKEN=root-token vault vault read database/roles/bob 2>&1)
  if echo "$ROLE_VERIFY" | grep -q "db_name"; then
    echo "✓ Verified: PostgreSQL role 'bob' exists in Vault"
  else
    echo "⚠ Warning: PostgreSQL role 'bob' may not have been created correctly"
  fi
else
  echo "Error: Failed to create PostgreSQL role for bob"
  echo "Output: $ROLE_CREATE_OUTPUT"
fi

# List all database roles for verification
echo "Listing all database roles for verification..."
docker exec -e VAULT_TOKEN=root-token vault vault list database/roles 2>&1

echo "Vault initialization completed!"

