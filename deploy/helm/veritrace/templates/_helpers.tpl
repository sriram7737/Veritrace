{{- define "veritrace.name" -}}veritrace{{- end -}}
{{- define "veritrace.fullname" -}}{{ .Release.Name }}-veritrace{{- end -}}
{{- define "veritrace.labels" -}}
app.kubernetes.io/name: {{ include "veritrace.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: "{{ .Chart.AppVersion }}"
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}
{{- define "veritrace.selectorLabels" -}}
app.kubernetes.io/name: {{ include "veritrace.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
