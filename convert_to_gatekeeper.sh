#!/bin/bash

folder_path="k8s"
output_folder="k8s/yaml"

declare -p -A apigroups=( 
  ["ConfigMap"]=""
  ["PersistentVolumeClaim"]=""
  ["PersistentVolume"]=""
  ["Pod"]=""
  ["Secret"]=""
  ["ServiceAccount"]=""
  ["Service"]=""
  ["Deployment"]="apps"
  ["HorizontalPodAutoscaler"]="autoscaling"
  ["Job"]="batch"
  ["PodDisruptionBudget"]="policy"
  ["RoleBinding"]="rbac.authorization.k8s.io"
  ["Role"]="rbac.authorization.k8s.io"
  ["Ingress"]="networking.k8s.io" 
  ["NetworkPolicy"]="networking.k8s.io"
  )

# create necessary folders
mkdir -p "$output_folder"/tmp/
mkdir -p "$output_folder"/constraint-template/
mkdir -p "$output_folder"/constraint/


# read general content for pasting it into the other rego file
cp $folder_path/general.rego $output_folder/tmp/general.rego

# read trusted registry content for pasting it into the other rego file
cp registries//container_trusted_registries.rego $output_folder/tmp/container_trusted_registries.rego

# Remove lines starting with "package" for the general.rego and the trusted_registries file
sed -i '/^package/d' "$output_folder/tmp/general.rego"
sed -i '/^package/d' "$output_folder/tmp/container_trusted_registries.rego"

general=$(cat $output_folder/tmp/general.rego)
trusted_registries=$(cat $output_folder/tmp/container_trusted_registries.rego)

for file in "$folder_path"/*.rego; do

    if [[ -f "$file" ]]; then

      filename=$(basename "$file" .rego)
      outputfile=$output_folder/tmp/$filename.rego

      # ignore the general and utility file
      if [ "$filename" == "utility" ] || [ "$filename" == "general" ] ; then
        continue;
      fi

      cp $file $outputfile


      echo "$general" >> $outputfile
      echo "$trusted_registries" >> $outputfile

      # Remove lines starting with "import"
      sed -i '/^import/d' "$outputfile"

      # Remove lines with "kubernetes.is"
      sed -i '/kubernetes.is/d' "$outputfile"

      # Replace lines starting with "deny"
      sed -i '/^deny/s/.*/violation[{"msg": msg}] {/' $outputfile

      # Replace input. with "input.review.object"
      sed -i '/input./s//input.review.object./' $outputfile

      #Generate OPA Gatekeeper constraint template
      name=$(echo "$filename" | tr '[:upper:]' '[:lower:]')
      apigroup="${apigroups[$filename]}"

        constraint_template=$(cat <<EOF
apiVersion: templates.gatekeeper.sh/v1beta1
kind: ConstraintTemplate
metadata:
  name: validate-$name
spec:
  crd:
    spec:
      names:
        kind: validate-$name
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
$(cat "$outputfile" | sed 's/^/        /')
EOF
)

      # Output OPA Gatekeeper constraint template to console
      #echo "$constraint_template"

      # Save OPA Gatekeeper constraint template as YAML file
      template_output_file="$output_folder/constraint-template/$filename.yaml"
      echo "$constraint_template" > "$template_output_file"

      # Generate OPA Gatekeeper constraint
      constraint=$(cat <<EOF
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: validate-$name
metadata:
  name: validate-$name
spec:
  match:
    kinds:
    - apiGroups: ["$apigroup"]
      kinds: [$filename]
EOF
)

      # Output OPA Gatekeeper constraint to console
      #echo "$constraint"

      # Save OPA Gatekeeper constraint as YAML file
      constraint_output_file="$output_folder/constraint/$filename.yaml"
      echo "$constraint" > "$constraint_output_file"

      
    fi
done


rm -r $output_folder/tmp/