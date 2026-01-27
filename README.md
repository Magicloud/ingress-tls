# Ingress TLS

This is a tool demostrating AdmissionControl in K8S.

In K8S, the way to audit resources about to be created or updated is called AdmissionControl webhook. This tool acts as a webhook to ensure Ingresses are configured with TLS configuration.

The developing right now is targetting Traefik ingress controller.
