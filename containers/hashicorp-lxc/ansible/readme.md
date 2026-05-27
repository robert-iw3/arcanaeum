## Hashicorp stack via ansible

The cluster contains the following nodes:

- 3 Consul nodes
- 3 Vault nodes
- 3 Nomad server nodes
- 5 Nomad client nodes (3 "apps" node, 2 "infra" node)
- 1 NFS server node
- 1 Load balancer node

Consul is used to bootstrap the Nomad cluster, for service discovery and for the
service mesh.

The Nomad client infra nodes are the entrypoints of the cluster. They will run Traefik
and use Consul service catalog to expose the applications.

Load balancer node will map ports 80 and 443 into the host, which will also have the ip
`10.99.0.1`, that is part of the cluster.

The proxy configuration exposes the services at `{{ service name }}.apps.10.99.0.1.nip.io`,
so when you deploy the service [hello.nomad](hello.nomad), it will be exposed at
`hello-world.apps.10.99.0.1.nip.io`

Consul, Vault and Nomad ui can be accessed in `https://consul.10.99.0.1.nip.io`,
`https://vault.10.99.0.1.nip.io` and `https://nomad.10.99.0.1.nip.io`, respectivelly.

Root tokens can be found in the `.tmp` directory.

## NFS and CSI Plugin

For storage with the NFS node, a CSI plugin will be configured using the [RocketDuck CSI plugin](https://gitlab.com/rocketduck/csi-plugin-nfs).


The are also examples of [other CSI plugins](csi_plugins).

## Examples

There are 3 example jobs:

- [hello.nomad](examples/hello.nomad), a simples hello world
- [countdash.nomad](examples/countdash.nomad), shows the usage of consul connect
- [nfs](examples/nfs/), show how to setup volumes using the nfs csi plugin


## Linux Containers

https://linuxcontainers.org/

almalinux/9:

```zsh
sudo dnf install -y lxc lxc-templates lxc-extra
sudo snap install lxd
sudo systemctl unmask snapd.service
sudo systemctl enable snapd.service
sudo systemctl start snapd.service


# upgrade to 6.x
snap refresh lxd --channel=6/stable
sudo snap start --enable lxd.daemon

sudo chown root:lxd /var/snap/lxd/common/lxd/unix.socket
sudo chmod 660 /var/snap/lxd/common/lxd/unix.socket
sudo chmod u+s /var/snap/lxd/common/lxd/unix.socket

/var/lib/snapd/snap/bin/lxd init

sudo usermod -a -G lxd $(whoami)
newgrp lxd

sudo touch /etc/environment
echo -ne PATH="/var/lib/snapd/snap/bin:$PATH" | sudo tee -a /etc/environment
```