# Create a Kind cluster without default CNI

## Pre-requisites

- [Docker Desktop](https://www.docker.com/products/docker-desktop) installed (or any other container platform line [Orbstack](https://orbstack.dev/)).
- [Kind](https://kind.sigs.k8s.io/docs/user/quick-start/#installation) installed.

> If you are running Docker Desktop on a Windows machine/laptop, Cilium will probably not work as expected, and you will need to compile your own WSL2 kernel for Cilium to work properly. More info [here](https://wsl.dev/wslcilium/).

## Create Kind Cluster

From the root folder of this repository, go to folder `kubernetes/kind` and create a `Kind` cluster with the following command:

```bash
kind create cluster --config ./kind-config.yaml --kubeconfig ../cilium-inject-mtls-demo.config
```

It uses the Kind configuration file `kind-config.yaml` to create a `Kind` cluster without a default CNI (we will install Cilium CNI next). The kubeconfig file is saved to `../cilium-inject-mtls-demo.config`.

Check the cluster is running with:

```bash
kubectl --kubeconfig ../cilium-inject-mtls-demo.config get nodes
```

You should see the Kind nodes `NotReady`, as we haven't installed a CNI yet.

## Install Cilium

Follow [these instructions](../cilium/README.md) to install Cilium on the Kind cluster.
