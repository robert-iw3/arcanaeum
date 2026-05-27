group "dashboard" {
  network {
    mode = "bridge"

    port "http" {
      static = 9002
      to     = 9002
    }
  }

  # ...

}