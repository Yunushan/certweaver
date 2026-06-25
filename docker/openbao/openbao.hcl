ui = true
disable_mlock = false
listener "tcp" {
  address = "0.0.0.0:8200"
  tls_disable = true # Development example only; production must use TLS.
}
storage "raft" {
  path = "/openbao/data"
  node_id = "openbao-1"
}
