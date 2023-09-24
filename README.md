# conftest

> **_DISCLAIMER_** This repository also contains rules Related to my cluster like deployment names or allowed registries. Since this might not fit your needs feel free to fork and remove the unnecessary stuff but still receive one of the irregular Updates.

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
