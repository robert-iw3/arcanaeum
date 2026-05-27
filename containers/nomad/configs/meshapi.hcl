group "api" {
    network {
      mode = "bridge"
    }

    # ...

    service {
      name = "count-api"
      port = "9001"

    # ...

      connect {
        sidecar_service {}
      }
    }

    # ...

  }