{{- define "pramagent.name" -}}pramagent{{- end -}}
{{- define "pramagent.fullname" -}}{{ .Release.Name }}-pramagent{{- end -}}
{{- define "pramagent.labels" -}}
app.kubernetes.io/name: {{ include "pramagent.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: "{{ .Chart.AppVersion }}"
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}
{{- define "pramagent.selectorLabels" -}}
app.kubernetes.io/name: {{ include "pramagent.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
