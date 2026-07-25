{{- define "mesh-release-origin.name" -}}
mesh-release-origin
{{- end -}}

{{- define "mesh-release-origin.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "mesh-release-origin.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "mesh-release-origin.labels" -}}
app.kubernetes.io/name: {{ include "mesh-release-origin.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | quote }}
{{- end -}}

{{- define "mesh-release-origin.selectorLabels" -}}
app.kubernetes.io/name: {{ include "mesh-release-origin.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "mesh-release-origin.image" -}}
{{- printf "%s@%s" (required "image.repository is required" .Values.image.repository) (required "image.digest is required" .Values.image.digest) -}}
{{- end -}}

{{- define "mesh-release-origin.claimName" -}}
{{- default (include "mesh-release-origin.fullname" .) .Values.content.existingClaim -}}
{{- end -}}
