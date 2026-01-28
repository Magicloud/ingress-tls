# Ingress TLS

This is a tool to enforce TLS on HTTP interfaces in K8S, like Ingress / Gateway.

This tool designed to provide both validation and mutation. But giving that a legit HTTP setup could miss some information necessary for HTTPS setup, I would not recommend using the mutation.

This tool supports both Nginx and Traefik. But giving Traefik Gateway implementation is just wrong. The mutation could be more unreliable.

All resources support `ingress-tls.magiclouds.cn/skip: true` annotation to have this tool pass the resources.

## Ingress

The validation on Ingress is just checking if there is a `spec.tls` section.

## Gateway / HTTPRoute

For Gateway, there are two validations.

One is there is at least one listener which protocol is `HTTPS`. Due to `HTTPS` listener without TLS configuration won't be programmed, this tool does not furtherly check TLS.

The other is checking if there are existing HTTPRoute-s that referencing to `HTTP` listeners, and those HTTPRoute-s are not full (matching `/`) redirections to https.

For HTTPRoute, there are three validations.

One, pass if it does not contain a `spec.parentrefs` section

Two, pass if it is a full redirection to https.

Three, fail if it references to a `HTTP` listener and is not full redirection to https.

## Usage

For Ingress, checking the resource itself is sufficient, but for Gateway / HTTPRoute, checking would involve getting existing HTTPRoute-s / Gateways. Hence if this tool is working Gateway / HTTPRoute, following RBAC setup is needed:

```YAML
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: ingress-tls
rules:
- apiGroups: [""]
  resources: ["namespaces"]
  verbs: ["list"]
- apiGroups: ["gateway.networking.k8s.io"]
  resources: ["gateways"]
  verbs: ["get"]
- apiGroups: ["gateway.networking.k8s.io"]
  resources: ["httproutes"]
  verbs: ["get", "list"]
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: ingress-tls
automountServiceAccountToken: true
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: ingress-tls
subjects:
- kind: ServiceAccount
  name: ingress-tls
roleRef:
  kind: ClusterRole
  name: ingress-tls
  apiGroup: rbac.authorization.k8s.io
```

Then we need to deploy and expose the tool itself. But be aware, since K8S requires Admission Control webhook traffic to be TLS protected, a TLS cert pair should be passed to the tool. Here I demo with cert-manager:

```YAML
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ingress-tls
spec:
  selector:
    matchLabels:
      app: ingress-tls
  replicas: 1
  template:
    metadata:
      labels:
        app: ingress-tls
    spec:
      serviceAccountName: ingress-tls
      automountServiceAccountToken: true
      containers:
      - name: ingress-tls
        image: ghcr.io/magicloud/ingress-tls:latest
        args:
          # cert manager setup, not all necessary.
          - --issuer
          - namespaced:step-issuer # if it is a cluster-issuer, use `clustered` prefix.
          - --kind
          - StepClusterIssuer
          - --group
          - certmanager.step.sm
          # https redirect middleware for Traefik Ingress. Skip this for Nginx Ingress.
          - -t
          - test/https-redirect
          # TLS cert file folder
          - -f
          - /tls
          # TLS cert file name
          - -c
          - tls.crt
          # TLS cert priv key file name
          - -k
          - tls.key
        ports:
        - containerPort: 443
          name: ingress-tls
        volumeMounts:
        - name: tls
          mountPath: /tls
      volumes:
        - name: tls
          csi:
            driver: csi.cert-manager.io
            readOnly: true
            volumeAttributes:
              csi.cert-manager.io/issuer-name: step-issuer
              csi.cert-manager.io/issuer-kind: StepClusterIssuer
              csi.cert-manager.io/issuer-group: certmanager.step.sm
              # Those two hostnames are necessary
              csi.cert-manager.io/dns-names: ingress-tls.test.svc,ingress-tls.test.svc.cluster.local
              # This is for Step CA, which restrict the max duration on issuer side.
              csi.cert-manager.io/duration: 24h
              csi.cert-manager.io/renew-before: 1h
              # The tool running as uid 1000
              csi.cert-manager.io/fs-group: "1000"
---
apiVersion: v1
kind: Service
metadata:
  name: ingress-tls
  namespace: test
spec:
  selector:
    app: ingress-tls
  type: ClusterIP
  ports:
  - name: ingress-tls
    protocol: TCP
    port: 443
    targetPort: ingress-tls
```

Now comes to the webhooks setup. For validation:

```YAML
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: ingress-tls
webhooks:
- name: "ingress-tls.magicloud.lan"
  rules:
  - apiGroups:   ["*"]
    apiVersions: ["*"]
    operations:  ["CREATE", "UPDATE"]
    resources:   ["ingresses", "gateways", "httproutes"]
    scope:       "*"
  clientConfig:
    service:
      name: "ingress-tls"
      path: "/validate"
      port: 443
    # Since I use custom CA, and I could not figure out how to install the CA for K3S, I have to specify this field.
    caBundle: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUJwRENDQVVxZ0F3SUJBZ0lSQUw5bUxNVnpXMStzTkpsTFlnY3hhN1F3Q2dZSUtvWkl6ajBFQXdJd01ERVMKTUJBR0ExVUVDaE1KVFdGbmFXTnNiM1ZrTVJvd0dBWURWUVFERXhGTllXZHBZMnh2ZFdRZ1VtOXZkQ0JEUVRBZQpGdzB5TlRFd01Ua3hNVE14TWpaYUZ3MHpOVEV3TVRjeE1UTXhNalphTURBeEVqQVFCZ05WQkFvVENVMWhaMmxqCmJHOTFaREVhTUJnR0ExVUVBeE1SVFdGbmFXTnNiM1ZrSUZKdmIzUWdRMEV3V1RBVEJnY3Foa2pPUFFJQkJnZ3EKaGtqT1BRTUJCd05DQUFUcVQxYjVUcEs5UUtnL3J2Z2REUEE3WnZLRWpEK1RaY201TURpY3l6cGNocnZVU1lubAorcDhaaUVULzdHSnpSdE5DQTVMQUkxL1I1UGc0UDM3bnpIcGlvMFV3UXpBT0JnTlZIUThCQWY4RUJBTUNBUVl3CkVnWURWUjBUQVFIL0JBZ3dCZ0VCL3dJQkFUQWRCZ05WSFE0RUZnUVVTMm9RTGVRMnlGZ2lVVTFuMElrRGRCd1kKcmhJd0NnWUlLb1pJemowRUF3SURTQUF3UlFJaEFQdFdIYTFFaHVzbWRoZHgwWVJzaVRGSU1qZU9ZdFlqK05XYgpZOWM2eDRRYkFpQURqSTVPY3hZdkNqeFR3cU1ERlNwcVc4RUFSQWVwK2xRTkxDUzZzT2VUUlE9PQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0t
  admissionReviewVersions: ["v1"]
  sideEffects: None
  timeoutSeconds: 5
```

For mutation:

```YAML
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingWebhookConfiguration
metadata:
  name: ingress-tls
webhooks:
- name: "ingress-tls.magicloud.lan"
  rules:
  - apiGroups:   ["*"]
    apiVersions: ["*"]
    operations:  ["CREATE", "UPDATE"]
    resources:   ["ingresses", "gateways", "httproutes"]
    scope:       "*"
  clientConfig:
    service:
      name: "ingress-tls"
      path: "/mutate"
      port: 443
    caBundle: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUJwRENDQVVxZ0F3SUJBZ0lSQUw5bUxNVnpXMStzTkpsTFlnY3hhN1F3Q2dZSUtvWkl6ajBFQXdJd01ERVMKTUJBR0ExVUVDaE1KVFdGbmFXTnNiM1ZrTVJvd0dBWURWUVFERXhGTllXZHBZMnh2ZFdRZ1VtOXZkQ0JEUVRBZQpGdzB5TlRFd01Ua3hNVE14TWpaYUZ3MHpOVEV3TVRjeE1UTXhNalphTURBeEVqQVFCZ05WQkFvVENVMWhaMmxqCmJHOTFaREVhTUJnR0ExVUVBeE1SVFdGbmFXTnNiM1ZrSUZKdmIzUWdRMEV3V1RBVEJnY3Foa2pPUFFJQkJnZ3EKaGtqT1BRTUJCd05DQUFUcVQxYjVUcEs5UUtnL3J2Z2REUEE3WnZLRWpEK1RaY201TURpY3l6cGNocnZVU1lubAorcDhaaUVULzdHSnpSdE5DQTVMQUkxL1I1UGc0UDM3bnpIcGlvMFV3UXpBT0JnTlZIUThCQWY4RUJBTUNBUVl3CkVnWURWUjBUQVFIL0JBZ3dCZ0VCL3dJQkFUQWRCZ05WSFE0RUZnUVVTMm9RTGVRMnlGZ2lVVTFuMElrRGRCd1kKcmhJd0NnWUlLb1pJemowRUF3SURTQUF3UlFJaEFQdFdIYTFFaHVzbWRoZHgwWVJzaVRGSU1qZU9ZdFlqK05XYgpZOWM2eDRRYkFpQURqSTVPY3hZdkNqeFR3cU1ERlNwcVc4RUFSQWVwK2xRTkxDUzZzT2VUUlE9PQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0t
  admissionReviewVersions: ["v1"]
  sideEffects: None
  timeoutSeconds: 5
```

## Note

There are cases that after mutating, the resource is still invalid. Since K8S runs validation after mutation, if both are enabled, the wrong resource won't pass silently.