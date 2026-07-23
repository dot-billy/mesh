{{- define "mesh-control-plane.name" -}}
mesh-control-plane
{{- end -}}

{{- define "mesh-control-plane.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "mesh-control-plane.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "mesh-control-plane.labels" -}}
app.kubernetes.io/name: {{ include "mesh-control-plane.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | quote }}
{{- end -}}

{{- define "mesh-control-plane.selectorLabels" -}}
app.kubernetes.io/name: {{ include "mesh-control-plane.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "mesh-control-plane.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "mesh-control-plane.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- required "serviceAccount.name is required when serviceAccount.create=false" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "mesh-control-plane.image" -}}
{{- printf "%s@%s" (required "image.repository is required" .Values.image.repository) (required "image.digest is required" .Values.image.digest) -}}
{{- end -}}
