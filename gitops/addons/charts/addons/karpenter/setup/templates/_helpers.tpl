# {{- define "karpenter-setup.crds" -}}
# {{- range $path, $bytes := .Files.Glob "crds/*.yaml" }}
# {{- $file := $.Files.Get $path }}
# ---
# {{ $file | indent 4 }}
# {{- end }}
# {{- end }}
