# This is an example that is part of Nomad's internal default configuration for Consul integration.
consul {
  # The address to the Consul agent.
  address = "127.0.0.1:8500"
  token   = "abcd1234"
  grpc_address = "127.0.0.1:8502"

  # TLS encryption
  ssl = true
  ca_file = "/etc/consul.d/tls/consul-agent-ca.pem"
  cert_file = "/etc/consul.d/tls/consul-server-consul-0.pem"
  key_file = "/etc/consul.d/tls/consul-server-consul-0-key.pem"
  verify_ssl = true

  # The service name to register the server and client with Consul.
  server_service_name = "nomad"
  client_service_name = "nomad-client"

  # Enables automatically registering the services.
  auto_advertise = true

  # Enabling the server and client to bootstrap using Consul.
  server_auto_join = true
  client_auto_join = true
}

