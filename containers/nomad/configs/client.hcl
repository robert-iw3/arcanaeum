client {
  enabled = true
  servers = ["myserver:port"]

  host_volume "letsencrypt" {
    path = "/etc/letsencrypt"
    read_only = false
  }

  host_volume "osticket_db" {
    path = "/opt/osticket/db"
    read_only = false
  }

  host_volume "borg_config" {
    path = "/opt/borg/config"
    read_only = false
  }

  host_volume "borg_repo" {
    path = "/opt/borg/repo"
    read_only = false
  }
}

# Docker Configuration
plugin "docker" {

  volumes {
    enabled      = true
    selinuxlabel = "z"
  }

  allow_privileged = false
  allow_caps       = ["chown", "net_raw"]

}