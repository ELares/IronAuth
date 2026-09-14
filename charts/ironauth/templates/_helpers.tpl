{{/* SPDX-License-Identifier: MIT OR Apache-2.0 */}}

{{- define "ironauth.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "ironauth.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "ironauth.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "ironauth.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "ironauth.selectorLabels" -}}
app.kubernetes.io/name: {{ include "ironauth.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "ironauth.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "ironauth.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
The name of the Secret holding the rendered ironauth.toml: the one the chart
renders, or an operator-supplied one.
*/}}
{{- define "ironauth.configSecretName" -}}
{{- if .Values.database.existingConfigSecret -}}
{{- .Values.database.existingConfigSecret -}}
{{- else -}}
{{- printf "%s-config" (include "ironauth.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/*
Fail rendering on a configuration that cannot work, rather than installing
something that comes up wrong.

public_url is required because scheme, host and issuer derive from it and never
from request headers; without it a multi-replica deployment behind a Service
would mint issuer URLs from whatever Host it was asked with, which is a token
forgery surface rather than a missing convenience.

An accelerator enabled without an endpoint is the other one: it reads as "the
cache is on" while nothing is wired, which is the shape that looks configured
and is not.
*/}}
{{- define "ironauth.validateValues" -}}
{{- if not .Values.server.publicUrl -}}
{{- fail "ironauth: server.publicUrl is required. Issuer and endpoint URLs derive from it, never from request headers, so there is no safe default to guess." -}}
{{- end -}}
{{- if and (not .Values.database.url) (not .Values.database.existingConfigSecret) -}}
{{- fail "ironauth: set database.url (the full DSN) or database.existingConfigSecret (a Secret holding a complete ironauth.toml)." -}}
{{- end -}}
{{- if and .Values.ironcache.enabled (not .Values.ironcache.endpoint) -}}
{{- fail "ironauth: ironcache.enabled is true but ironcache.endpoint is empty. An accelerator switched on with nowhere to reach reads as configured and is not." -}}
{{- end -}}
{{- if and .Values.ironbus.enabled (not .Values.ironbus.addr) -}}
{{- fail "ironauth: ironbus.enabled is true but ironbus.addr is empty. An accelerator switched on with nowhere to reach reads as configured and is not." -}}
{{- end -}}
{{- end -}}
