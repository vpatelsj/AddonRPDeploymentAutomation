# AddonRPDeploymentAutomation
## Status: 

7/23/2018 - Able to generate certs, insert into kv, modify sf template with cert locations and deploy sf template in one "click"


## Usage:
* Modify Parameters.json for azurestack environment specific values.
* Run ./Deploy_IOT_RP.PS1
* The script is idempotent, it will delete existing resources and redeploy from scratch.
* Currently the script takes about 30-35mins to reach finishline.
