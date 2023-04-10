#!/bin/bash

folder_path="k8s"
output_folder="k8s/yaml"

for file in "$folder_path"/*.rego; do
    if [[ -f "$file" ]]; then
    
        content=$(cat $file)
        echo "$content"
        # Remove lines starting with "import"
        sed -i '/^import/d' "$file"

        # Replace lines starting with "deny"
        sed -i '/^deny/s/.*/violation[{"msg": msg}]/' "$file"

        # Generate OPA Gatekeeper constraint template
#         kind=$(echo "$file" | sed 's/.*kind_\([^.]*\).reg/\1/')
#         name="deny-import-$kind"
#         constraint_template=$(cat <<EOF
# apiVersion: constraints.gatekeeper.sh/v1beta1
# kind: K8sValueConstraintTemplate
# metadata:
#   name: $name
# spec:
#   crd:
#     spec:
#       names:
#         kind: $kind
#   targets:
#     - target: admission.k8s.gatekeeper.sh
#       rego: |
# $(cat "$file" | sed 's/^/        /')
#   parameters:
#     message:
#       type: string
#       default: "Import statements are not allowed"
#   revisionHistoryLimit: 3
# EOF
# )

#         # Output OPA Gatekeeper constraint template to console
#         echo "$constraint_template"

#         # Save OPA Gatekeeper constraint template as YAML file
#         template_output_file="$output_folder/$name-template.yaml"
#         echo "$constraint_template" > "$template_output_file"

#         # Generate OPA Gatekeeper constraint
#         constraint=$(cat <<EOF
# apiVersion: constraints.gatekeeper.sh/v1beta1
# kind: K8sValueConstraint
# metadata:
#   name: $name
# spec:
#   match:
#     kinds:
#     - apiGroups: [""]
#       kinds: [$kind]
#   parameters:
#     message: "Import statements are not allowed"
#     path: "metadata/annotations"
#     value:
#       regex: '^(?!.*import)'
#   enforcementAction: deny
#   validate: true
#   remediationAction: inform
#   message: "Import statements are not allowed"
#   violationSchema: {}
#   sync: {}
#   exclude: []
#   include: []
#   annotations:
#     category: security
#   enforcementAction: deny
#   parameters:
#     message: "Import statements are not allowed"
#   constraintTemplateName: $name
# EOF
# )

#         # Output OPA Gatekeeper constraint to console
#         echo "$constraint"

#         # Save OPA Gatekeeper constraint as YAML file
#         constraint_output_file="$output_folder/$name-constraint.yaml"
#         echo "$constraint" > "$constraint_output_file"
    fi
done
