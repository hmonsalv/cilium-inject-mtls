# Install Cilium

## Pre-requisites

- [Helm](https://helm.sh/docs/intro/install/#from-script) installed.

## Configure Cilium Repository

Add the Cilium Helm repository:

```bash
helm repo add cilium https://helm.cilium.io/
helm repo update
```

## Generate Cilium Installation Manifests

From the root folder of this repository, go to folder `kubernetes/cilium` and use Helm template to generate the Cilium installation manifest:

```bash
helm template cilium cilium/cilium --version 1.15.0 --namespace kube-system --kubeconfig ../cilium-inject-mtls-demo.config -f ./cilium-values.yaml > ./cilium-install.yaml
```

It will generate `cilium-install.yaml` file with all k8s manifests to install Cilium.

> **Note:** `cilium-values.yaml` file has been configured to enable the Cilium features that we will use in this lab: Cilium Service Mesh (CiliumEnvoyConfig), and Hubble Relay, that will allow us to visualize the network traffic.

## Install Cilium Manifests

Install Cilium using the generated installation manifests:

```bash
kubectl --kubeconfig ../cilium-inject-mtls-demo.config apply -f ./cilium-install.yaml
```

## Verify Cilium Installation

Check that Cilium pods are running:

```bash
kubectl --kubeconfig ../cilium-inject-mtls-demo.config get pods -n kube-system -l k8s-app=cilium
```

## Let's Get Started

Now you are ready run this lab. Follow instructions described in the [README.md](../../README.md#lets-get-started) file.
