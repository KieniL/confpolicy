# conftest

## Testing

Add a a file into testfiles and then run <br/>

<code>
conftest test testfiles/ --policy ./
</code>
<br/>


This will ensure that every file inside testfiles will be executed


## Converting to OPA Gatekeeper

Run <code>./convert_to_gatekeeper.sh</code><br/>


This will generate the k8s/yaml/tmp folder and parse the conftest policy to match gatekeeper.

Then the contraint-templates and the constraints can be applied with the following commands:

<code>
kubectl apply -f .\constraint-template\ <br/>
kubectl apply -f .\constraint\
</code>