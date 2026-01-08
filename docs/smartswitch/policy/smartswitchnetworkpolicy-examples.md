# SmartSwitchNetworkPolicy Examples

This document provides example SmartSwitchNetworkPolicy configurations for common use cases. For detailed documentation on policy structure and behavior, see the [SmartSwitchNetworkPolicy Guide](./smartswitchnetworkpolicy-guide.md).

## Table of Contents

- [Basic Examples](#basic-examples)
  - [Allow HTTP Traffic](#allow-http-traffic)
  - [Deny SSH Access](#deny-ssh-access)
- [VRF-Based Policies](#vrf-based-policies)
  - [Allow DNS Within a VRF](#allow-dns-within-a-vrf)
  - [Allow Database Access Within a VRF](#allow-database-access-within-a-vrf)
- [VLAN-Based Policies](#vlan-based-policies)
  - [Allow Web Traffic on VLAN](#allow-web-traffic-on-vlan)
- [Port Ranges](#port-ranges)
  - [Allow Ephemeral Ports](#allow-ephemeral-ports)
  - [Allow RTP Media Ports](#allow-rtp-media-ports)
- [Multiple Protocols](#multiple-protocols)
  - [Allow DNS (TCP and UDP)](#allow-dns-tcp-and-udp)
  - [Allow Multiple Services](#allow-multiple-services)
- [Multiple Sources and Destinations](#multiple-sources-and-destinations)
  - [Multi-Subnet to Multi-Server Policy](#multi-subnet-to-multi-server-policy)
- [IPv6 Policies](#ipv6-policies)
  - [Allow IPv6 HTTP Traffic](#allow-ipv6-http-traffic)
- [Deny Rules](#deny-rules)
  - [Network Segmentation with Deny Rules](#network-segmentation-with-deny-rules)
- [Mixed Protocol Services](#mixed-protocol-services)
  - [Kubernetes Services Policy](#kubernetes-services-policy)
- [Multiple Policies in One File](#multiple-policies-in-one-file)
- [Complete Application Stack Example](#complete-application-stack-example)

---

## Basic Examples

### Allow HTTP Traffic

A simple policy allowing HTTP and HTTPS traffic from a source subnet to a web server.

```yaml
apiVersion: isovalent.com/v1alpha1
kind: SmartSwitchNetworkPolicy
metadata:
  name: allow-web-traffic
  namespace: default
spec:
  description: "Allow HTTP and HTTPS traffic from internal network to web server"
  rules:
    - description: "Allow HTTP and HTTPS to web server"
      action: allow
      source:
        ipBlock:
          - cidr: "10.0.0.0/16"
      destination:
        ipBlock:
          - cidr: "192.168.1.100/32"
        protoPorts:
          - protocol: "TCP"
            port: 80
          - protocol: "TCP"
            port: 443
```

**Expansion:** 1 source × 1 destination = **1 rule** (with 2 ports attached)

---

### Deny SSH Access

Block SSH access from untrusted networks to sensitive servers.

```yaml
apiVersion: isovalent.com/v1alpha1
kind: SmartSwitchNetworkPolicy
metadata:
  name: deny-ssh-from-untrusted
  namespace: security
spec:
  description: "Block SSH access from untrusted guest network to sensitive servers"
  rules:
    - description: "Block SSH from guest network"
      action: deny
      source:
        ipBlock:
          - cidr: "172.16.0.0/12"
      destination:
        ipBlock:
          - cidr: "10.10.0.0/16"
        protoPorts:
          - protocol: "TCP"
            port: 22
```

---

## VRF-Based Policies

### Allow DNS Within a VRF

Allow DNS queries within the production VRF.

```yaml
apiVersion: isovalent.com/v1alpha1
kind: SmartSwitchNetworkPolicy
metadata:
  name: allow-dns-production
  namespace: network
spec:
  description: "Allow DNS queries within the production VRF"
  rules:
    - description: "Allow DNS queries to internal DNS servers"
      action: allow
      source:
        ipBlock:
          - cidr: "10.0.0.0/8"
            vrf: "production"
      destination:
        ipBlock:
          - cidr: "10.255.255.53/32"
            vrf: "production"
          - cidr: "10.255.255.54/32"
            vrf: "production"
        protoPorts:
          - protocol: "UDP"
            port: 53
          - protocol: "TCP"
            port: 53
```

**Expansion:** 1 source × 2 destinations = **2 rules**

---

### Allow Database Access Within a VRF

Allow application servers to access database servers within the same VRF.

```yaml
apiVersion: isovalent.com/v1alpha1
kind: SmartSwitchNetworkPolicy
metadata:
  name: allow-database-access
  namespace: backend
spec:
  description: "Allow application servers to access database servers within the backend VRF"
  rules:
    - description: "Allow PostgreSQL access from app tier"
      action: allow
      source:
        ipBlock:
          - cidr: "10.10.1.0/24"
            vrf: "backend"
          - cidr: "10.10.2.0/24"
            vrf: "backend"
      destination:
        ipBlock:
          - cidr: "10.20.1.10/32"
            vrf: "backend"
          - cidr: "10.20.1.11/32"
            vrf: "backend"
        protoPorts:
          - protocol: "TCP"
            port: 5432
    - description: "Allow Redis access from app tier"
      action: allow
      source:
        ipBlock:
          - cidr: "10.10.1.0/24"
            vrf: "backend"
          - cidr: "10.10.2.0/24"
            vrf: "backend"
      destination:
        ipBlock:
          - cidr: "10.20.2.10/32"
            vrf: "backend"
        protoPorts:
          - protocol: "TCP"
            port: 6379
```

**Expansion:**
- Rule 1: 2 sources × 2 destinations = **4 rules**
- Rule 2: 2 sources × 1 destination = **2 rules**
- **Total: 6 rules**

---

## VLAN-Based Policies

### Allow Web Traffic on VLAN

Allow traffic within a specific VLAN.

```yaml
apiVersion: isovalent.com/v1alpha1
kind: SmartSwitchNetworkPolicy
metadata:
  name: allow-vlan100-web
  namespace: network
spec:
  description: "Allow web traffic within VLAN 100"
  rules:
    - description: "Allow HTTP within VLAN 100"
      action: allow
      source:
        ipBlock:
          - cidr: "192.168.100.0/24"
            vlan: 100
      destination:
        ipBlock:
          - cidr: "192.168.100.50/32"
            vlan: 100
        protoPorts:
          - protocol: "TCP"
            port: 80
          - protocol: "TCP"
            port: 443
```

---

## Port Ranges

### Allow Ephemeral Ports

Allow responses on ephemeral port ranges.

```yaml
apiVersion: isovalent.com/v1alpha1
kind: SmartSwitchNetworkPolicy
metadata:
  name: allow-ephemeral-ports
  namespace: default
spec:
  description: "Allow responses on ephemeral port ranges"
  rules:
    - description: "Allow ephemeral port responses"
      action: allow
      source:
        ipBlock:
          - cidr: "0.0.0.0/0"
      destination:
        ipBlock:
          - cidr: "10.0.0.0/8"
        protoPorts:
          - protocol: "TCP"
            port: 32768
            endPort: 65535
          - protocol: "UDP"
            port: 32768
            endPort: 65535
```

---

### Allow RTP Media Ports

Allow RTP media traffic for VoIP applications.

```yaml
apiVersion: isovalent.com/v1alpha1
kind: SmartSwitchNetworkPolicy
metadata:
  name: allow-rtp-media
  namespace: voip
spec:
  description: "Allow RTP media traffic for VoIP applications"
  rules:
    - description: "Allow RTP media streams"
      action: allow
      source:
        ipBlock:
          - cidr: "10.50.0.0/16"
            vrf: "voice"
      destination:
        ipBlock:
          - cidr: "10.60.0.0/16"
            vrf: "voice"
        protoPorts:
          - protocol: "UDP"
            port: 16384
            endPort: 32767
```

---

## Multiple Protocols

### Allow DNS (TCP and UDP)

DNS uses both UDP (standard queries) and TCP (zone transfers, large responses).

```yaml
apiVersion: isovalent.com/v1alpha1
kind: SmartSwitchNetworkPolicy
metadata:
  name: allow-dns-both-protocols
  namespace: default
spec:
  description: "Allow DNS queries over both UDP and TCP protocols"
  rules:
    - description: "Allow DNS over UDP and TCP"
      action: allow
      source:
        ipBlock:
          - cidr: "10.0.0.0/8"
      destination:
        ipBlock:
          - cidr: "8.8.8.8/32"
          - cidr: "8.8.4.4/32"
        protoPorts:
          - protocol: "UDP"
            port: 53
          - protocol: "TCP"
            port: 53
```

**Expansion:** 1 source × 2 destinations = **2 rules** (each with UDP and TCP port 53)

**Note:** In the DPU JSON output, ports with the same range but different protocols are merged. Each rule will have a single port entry with `"protocol": ["udp", "tcp"]`.

---

### Allow Multiple Services

Allow access to multiple services on a server.

```yaml
apiVersion: isovalent.com/v1alpha1
kind: SmartSwitchNetworkPolicy
metadata:
  name: allow-multi-service
  namespace: default
spec:
  description: "Allow access to multiple services on a server"
  rules:
    - description: "Allow HTTP, HTTPS, and SSH"
      action: allow
      source:
        ipBlock:
          - cidr: "10.0.0.0/8"
      destination:
        ipBlock:
          - cidr: "192.168.1.10/32"
        protoPorts:
          - protocol: "TCP"
            port: 22
          - protocol: "TCP"
            port: 80
          - protocol: "TCP"
            port: 443
```

---

## Multiple Sources and Destinations

### Multi-Subnet to Multi-Server Policy

A policy demonstrating cartesian expansion with multiple sources and destinations.

```yaml
apiVersion: isovalent.com/v1alpha1
kind: SmartSwitchNetworkPolicy
metadata:
  name: multi-subnet-access
  namespace: production
spec:
  description: "Allow API access from multiple subnets to API servers"
  rules:
    - description: "Allow API access from multiple subnets to API servers"
      action: allow
      source:
        ipBlock:
          - cidr: "10.1.0.0/24"
            vrf: "production"
          - cidr: "10.2.0.0/24"
            vrf: "production"
          - cidr: "10.3.0.0/24"
            vrf: "production"
      destination:
        ipBlock:
          - cidr: "192.168.10.1/32"
            vrf: "production"
          - cidr: "192.168.10.2/32"
            vrf: "production"
        protoPorts:
          - protocol: "TCP"
            port: 8080
          - protocol: "TCP"
            port: 8443
```

**Expansion:** 3 sources × 2 destinations = **6 rules**

Each rule includes both ports (8080 and 8443) as an array.

---

## IPv6 Policies

### Allow IPv6 HTTP Traffic

Policy for IPv6 web traffic.

```yaml
apiVersion: isovalent.com/v1alpha1
kind: SmartSwitchNetworkPolicy
metadata:
  name: allow-ipv6-web
  namespace: default
spec:
  description: "Allow IPv6 HTTP and HTTPS traffic"
  rules:
    - description: "Allow IPv6 HTTP and HTTPS"
      action: allow
      source:
        ipBlock:
          - cidr: "2001:db8:1::/48"
      destination:
        ipBlock:
          - cidr: "2001:db8:2::100/128"
        protoPorts:
          - protocol: "TCP"
            port: 80
          - protocol: "TCP"
            port: 443
```

**Important:** IPv4 and IPv6 addresses cannot be mixed within the same rule. A rule with an IPv4 source and IPv6 destination (or vice versa) will be silently skipped during expansion.

---

## Deny Rules

### Network Segmentation with Deny Rules

A policy demonstrating multiple deny rules to enforce network segmentation between different security zones.

```yaml
apiVersion: isovalent.com/v1alpha1
kind: SmartSwitchNetworkPolicy
metadata:
  name: deny-cross-zone-traffic
  namespace: security
spec:
  description: "Enforce network segmentation between security zones"
  rules:
    - description: "Block DMZ from accessing internal network"
      action: deny
      source:
        ipBlock:
          - cidr: "10.10.0.0/16"
            vrf: "dmz"
      destination:
        ipBlock:
          - cidr: "10.20.0.0/16"
            vrf: "internal"
          - cidr: "10.30.0.0/16"
            vrf: "internal"
        protoPorts:
          - protocol: "TCP"
          - protocol: "UDP"
    - description: "Block guest network from accessing production"
      action: deny
      source:
        ipBlock:
          - cidr: "172.16.0.0/16"
            vrf: "guest"
      destination:
        ipBlock:
          - cidr: "10.20.0.0/16"
            vrf: "internal"
        protoPorts:
          - protocol: "TCP"
          - protocol: "UDP"
    - description: "Block IoT devices from management network"
      action: deny
      source:
        ipBlock:
          - cidr: "192.168.100.0/24"
            vrf: "iot"
      destination:
        ipBlock:
          - cidr: "10.0.0.0/24"
            vrf: "management"
        protoPorts:
          - protocol: "TCP"
            port: 22
          - protocol: "TCP"
            port: 443
          - protocol: "TCP"
            port: 3389
```

**Expansion:**
- Rule 1: 1 source × 2 destinations = **2 rules**
- Rule 2: 1 source × 1 destination = **1 rule**
- Rule 3: 1 source × 1 destination = **1 rule**
- **Total: 4 rules**

---

## Mixed Protocol Services

### Kubernetes Services Policy

A policy allowing traffic to Kubernetes cluster services that use a mix of TCP and UDP protocols.

```yaml
apiVersion: isovalent.com/v1alpha1
kind: SmartSwitchNetworkPolicy
metadata:
  name: allow-k8s-services
  namespace: kubernetes
spec:
  description: "Allow traffic to Kubernetes cluster services"
  rules:
    - description: "Allow access to Kubernetes API server"
      action: allow
      source:
        ipBlock:
          - cidr: "10.0.0.0/8"
            vrf: "cluster"
      destination:
        ipBlock:
          - cidr: "10.96.0.1/32"
            vrf: "cluster"
        protoPorts:
          - protocol: "TCP"
            port: 443
          - protocol: "TCP"
            port: 6443
    - description: "Allow CoreDNS queries (UDP and TCP)"
      action: allow
      source:
        ipBlock:
          - cidr: "10.0.0.0/8"
            vrf: "cluster"
      destination:
        ipBlock:
          - cidr: "10.96.0.10/32"
            vrf: "cluster"
        protoPorts:
          - protocol: "UDP"
            port: 53
          - protocol: "TCP"
            port: 53
          - protocol: "TCP"
            port: 9153
    - description: "Allow etcd cluster communication"
      action: allow
      source:
        ipBlock:
          - cidr: "10.96.0.0/16"
            vrf: "cluster"
      destination:
        ipBlock:
          - cidr: "10.96.1.0/24"
            vrf: "cluster"
        protoPorts:
          - protocol: "TCP"
            port: 2379
          - protocol: "TCP"
            port: 2380
    - description: "Allow NodePort service range"
      action: allow
      source:
        ipBlock:
          - cidr: "0.0.0.0/0"
      destination:
        ipBlock:
          - cidr: "10.0.0.0/8"
            vrf: "cluster"
        protoPorts:
          - protocol: "TCP"
            port: 30000
            endPort: 32767
          - protocol: "UDP"
            port: 30000
            endPort: 32767
```

**Expansion:**
- Rule 1: 1 source × 1 destination = **1 rule** (with 2 TCP ports)
- Rule 2: 1 source × 1 destination = **1 rule** (with UDP 53, TCP 53, TCP 9153)
- Rule 3: 1 source × 1 destination = **1 rule** (with 2 TCP ports)
- Rule 4: 1 source × 1 destination = **1 rule** (with TCP and UDP port ranges)
- **Total: 4 rules**

---

## Multiple Policies in One File

You can define multiple policies in a single YAML file using the `---` document separator.

```yaml
apiVersion: isovalent.com/v1alpha1
kind: SmartSwitchNetworkPolicy
metadata:
  name: allow-web-tier
  namespace: production
spec:
  description: "Allow inbound web traffic to the web tier"
  rules:
    - description: "Allow inbound web traffic"
      action: allow
      source:
        ipBlock:
          - cidr: "0.0.0.0/0"
      destination:
        ipBlock:
          - cidr: "10.100.0.0/24"
        protoPorts:
          - protocol: "TCP"
            port: 80
          - protocol: "TCP"
            port: 443
---
apiVersion: isovalent.com/v1alpha1
kind: SmartSwitchNetworkPolicy
metadata:
  name: allow-app-to-db
  namespace: production
spec:
  description: "Allow application tier to access database tier"
  rules:
    - description: "Allow app tier to database tier"
      action: allow
      source:
        ipBlock:
          - cidr: "10.100.0.0/24"
      destination:
        ipBlock:
          - cidr: "10.200.0.0/24"
        protoPorts:
          - protocol: "TCP"
            port: 5432
          - protocol: "TCP"
            port: 3306
---
apiVersion: isovalent.com/v1alpha1
kind: SmartSwitchNetworkPolicy
metadata:
  name: deny-db-egress
  namespace: production
spec:
  description: "Block database tier from initiating external connections"
  rules:
    - description: "Block database tier from initiating external connections"
      action: deny
      source:
        ipBlock:
          - cidr: "10.200.0.0/24"
      destination:
        ipBlock:
          - cidr: "0.0.0.0/0"
        protoPorts:
          - protocol: "TCP"
```

---

## Complete Application Stack Example

A comprehensive example showing policies for a typical three-tier application architecture.

```yaml
# Frontend tier - accepts external traffic
apiVersion: isovalent.com/v1alpha1
kind: SmartSwitchNetworkPolicy
metadata:
  name: frontend-ingress
  namespace: myapp
spec:
  description: "Allow HTTPS traffic from the internet to frontend tier"
  rules:
    - description: "Allow HTTPS from internet"
      action: allow
      source:
        ipBlock:
          - cidr: "0.0.0.0/0"
      destination:
        ipBlock:
          - cidr: "10.100.1.0/24"
            vrf: "frontend"
        protoPorts:
          - protocol: "TCP"
            port: 443
---
# Frontend to API communication
apiVersion: isovalent.com/v1alpha1
kind: SmartSwitchNetworkPolicy
metadata:
  name: frontend-to-api
  namespace: myapp
spec:
  description: "Allow frontend tier to communicate with API tier"
  rules:
    - description: "Allow frontend to call API"
      action: allow
      source:
        ipBlock:
          - cidr: "10.100.1.0/24"
            vrf: "backend"
      destination:
        ipBlock:
          - cidr: "10.100.2.0/24"
            vrf: "backend"
        protoPorts:
          - protocol: "TCP"
            port: 8080
---
# API to database communication
apiVersion: isovalent.com/v1alpha1
kind: SmartSwitchNetworkPolicy
metadata:
  name: api-to-database
  namespace: myapp
spec:
  description: "Allow API tier to access database and cache services"
  rules:
    - description: "Allow API to query PostgreSQL"
      action: allow
      source:
        ipBlock:
          - cidr: "10.100.2.0/24"
            vrf: "backend"
      destination:
        ipBlock:
          - cidr: "10.100.3.0/24"
            vrf: "backend"
        protoPorts:
          - protocol: "TCP"
            port: 5432
    - description: "Allow API to query Redis cache"
      action: allow
      source:
        ipBlock:
          - cidr: "10.100.2.0/24"
            vrf: "backend"
      destination:
        ipBlock:
          - cidr: "10.100.4.0/24"
            vrf: "backend"
        protoPorts:
          - protocol: "TCP"
            port: 6379
---
# Deny direct database access from frontend
apiVersion: isovalent.com/v1alpha1
kind: SmartSwitchNetworkPolicy
metadata:
  name: deny-frontend-to-db
  namespace: myapp
spec:
  description: "Block frontend tier from directly accessing database tier"
  rules:
    - description: "Block frontend from directly accessing database"
      action: deny
      source:
        ipBlock:
          - cidr: "10.100.1.0/24"
            vrf: "backend"
      destination:
        ipBlock:
          - cidr: "10.100.3.0/24"
            vrf: "backend"
          - cidr: "10.100.4.0/24"
            vrf: "backend"
        protoPorts:
          - protocol: "TCP"
```

**Total expansion for this stack:**
- `frontend-ingress`: 1 × 1 = 1 rule
- `frontend-to-api`: 1 × 1 = 1 rule  
- `api-to-database`: (1 × 1) + (1 × 1) = 2 rules
- `deny-frontend-to-db`: 1 × 2 = 2 rules
- **Total: 6 rules across 4 policies**
