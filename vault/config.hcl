storage "file" {
  path = "/vault/data"
}

# Note: In dev mode, listener is configured via VAULT_DEV_LISTEN_ADDRESS
# Uncomment below for production mode
# listener "tcp" {
#   address     = "0.0.0.0:8200"
#   tls_disable = 1
# }

# api_addr = "http://0.0.0.0:8200"
ui = true

