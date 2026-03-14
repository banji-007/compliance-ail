{{/*
Expand the name of the chart.
*/}}
{{- define "ail-gateway.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this.
*/}}
{{- define "ail-gateway.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart label value (name-version).
*/}}
{{- define "ail-gateway.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels — applied to every resource for consistent kubectl selection.
*/}}
{{- define "ail-gateway.labels" -}}
helm.sh/chart: {{ include "ail-gateway.chart" . }}
{{ include "ail-gateway.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels — used in Deployment/StatefulSet matchLabels and Service selectors.
*/}}
{{- define "ail-gateway.selectorLabels" -}}
app.kubernetes.io/name: {{ include "ail-gateway.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
ServiceAccount name — shared by all AIL workloads for SPIRE PSAT attestation.
*/}}
{{- define "ail-gateway.serviceAccountName" -}}
{{ include "ail-gateway.fullname" . }}
{{- end }}

{{/*
ImmuDB internal service hostname (K8s cluster-local DNS).
*/}}
{{- define "ail-gateway.immudbHost" -}}
{{- printf "%s-immudb.%s.svc.cluster.local" (include "ail-gateway.fullname" .) .Release.Namespace }}
{{- end }}

{{/*
Control plane internal service hostname (K8s cluster-local DNS).
Used by OPA sidecar for bundle polling and by ImmuDB ledger client.
*/}}
{{- define "ail-gateway.controlPlaneHost" -}}
{{- printf "ail-control-plane.%s.svc.cluster.local" .Release.Namespace }}
{{- end }}

{{/*
SPIRE socket hostPath directory — switches between bundled and external SPIRE.
*/}}
{{- define "ail-gateway.spireSocketDir" -}}
{{- if .Values.spire.enabled }}
{{- index .Values.spire "spire-agent" "hostSocketDir" | default "/run/spire/sockets" }}
{{- else }}
{{- .Values.externalSpire.socketDir | default "/run/spire/sockets" }}
{{- end }}
{{- end }}
