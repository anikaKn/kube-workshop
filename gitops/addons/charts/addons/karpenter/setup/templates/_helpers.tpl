{{- define "karpenter-setup.crds" -}}
{{- range .Files.Glob "crds/*.yaml" }}
---
{{ .Content | indent 4 }}
{{- end }}
{{- end }}