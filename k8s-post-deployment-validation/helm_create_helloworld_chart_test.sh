#! /bin/bash
#Define Console Output Color
RED='\033[0;31m'    # For error
GREEN='\033[0;32m'  # For crucial check success 
NC='\033[0m'        # No color, back to normal

if [[ $1 == "AUTO" ]]; then
  echo "Test case disabled for Automation."
  exit 3
fi

echo "Make a helm chart for hello-world app and deploy in Kubernete to verify the usability of helm"
echo "Check helm..."

# Check healm health status
helmClientVer="$(helm version | grep -o 'Client: \(.*\)[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}')"
helmServerVer="$(helm version | grep -o 'Server: \(.*\)[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}')"

if [[ -z $helmClientVer ]] || [[ -z $helmServerVer ]]; then
  echo  -e "${RED}Validation failed. Helm is not ready. Please install and initial helm before run this validation script.${NC}"
  exit 3
fi

echo -e "${GREEN}Helm is ready.${NC}"

# Create environment for chart
echo "Preparing for helloworld chart... "
mkdir ~/helmtest
cd ~/helmtest/

echo "Create helloworld chart..."
helm create helloworld

echo "Modify values and template..."
cd ./helloworld/
rm values.yaml
curl https://raw.githubusercontent.com/LingyunSu/AzureStack-QuickStart-Templates/master/k8s-post-deployment-validation/values.yaml > values.yaml
rm -rf templates
mkdir templates
curl https://raw.githubusercontent.com/LingyunSu/AzureStack-QuickStart-Templates/master/k8s-post-deployment-validation/helloworld.yaml > ./templates/helloworld.yaml
curl https://raw.githubusercontent.com/LingyunSu/AzureStack-QuickStart-Templates/master/k8s-post-deployment-validation/helloworlddeployment.yaml > ./templates/helloworlddeployment.yaml

echo "Package helloworld chart..."
cd ~/helmtest/
helm package ./helloworld/

echo "Check chart package ..."
chartpkg="$(ls | grep 'helloworld\(.*\).tgz')"

if [[ -z $chartpkg ]]; then
  echo  -e "${RED}Validation failed. Helm didn't package helloworld chart.${NC}"
fi

echo -e "${GREEN}Done with package helloworld chart.${NC}"

echo "Installing helloworld chart"
helm install ./helloworld

sleep 5s

echo "Done with installation, checking release status..."
hwRelease=$(helm ls -d -r | grep 'DEPLOYED\(.*\)helloworld' | grep -Eo '^[a-z,-]+')

if [[ -z $hwRelease ]]; then
  echo  -e "${RED}Validation failed. Helm release for helloworld not found.${NC}"
  exit 3
else
  echo -e "${GREEN}Helloworld is deployed through helm. The release name is ${hwRelease}${NC}"
fi 

# Check pods status
echo "Monitoring pods status..."
i=0
isPodsRunning=0
while [ $i -lt 20 ];do
  podsCount="$(sudo kubectl get pods --selector app=helloworld | grep -c 'Running')"

  if [ $podsCount -ne 3 ]; then
    echo "Tracking pods status helloworld... current running pods ${podsCount}"
    sleep 30s
  else
    echo -e "${GREEN}Pods are all ready.${NC}"
	isPodsRunning=1
    break
  fi
  let i=i+1
done

if [ $isPodsRunning -ne 1 ]; then
  echo  -e "${RED}Validation failed. Desired count of helloworld pods are not ready.${NC}"
  exit 3
fi

# Check service availability
function checkService {
  # Check external IP for helloworld chart
  i=0
  while [ $i -lt 20 ];do
    externalIp=$(sudo kubectl get services helloworld -o=custom-columns=NAME:.status.loadBalancer.ingress[0].ip | grep -oP '(\d{1,3}\.){1,3}\d{1,3}')

    if [[ -z $externalIp ]]; then
      echo "Tracking helloworld external IP status..."
      sleep 30s
    else
      echo -e "${GREEN}External IP is available: ${externalIp}.${NC}"
      break
    fi
    let i=i+1
  done

  if [[ -z $externalIp ]]; then
    echo -e "${RED}Validation failed. The external IP of helloworld is not available.${NC}"
    exit 3
  fi
  
  # Check portal status
  portalState="$(curl http://${externalIp} --head -s | grep '200 OK')"

  if [[ -z portalState ]]; then
    echo -e "${RED}Validation failed. Helloworld app is not on.${NC}"
    exit 3
  fi
}

echo "Validating service and portal healthy state..."
checkService

# Delete the release
echo "Delete release ${hwRelease} ..."
helm delete $hwRelease

# Check again to make sure the release is removed
sleep 5s
hwReleaseN=$(helm ls -d -r | grep 'DEPLOYED\(.*\)helloworld' | grep -Eo '^[a-z,-]+')

if [[ ! -z $hwReleaseN ]]; then
  echo "${RED}Test failed. Delete release ${hwRelease} failed.${NC}"
fi
echo -e "${GREEN}Successfully deleted release ${hwRelease} ...${NC}"

# Rollback release
echo "Rollback release ${hwRelease} ..."
helm rollback $hwRelease 1

# Check availability again
sleep 5s
hwRelease=$(helm ls -d -r | grep 'DEPLOYED\(.*\)helloworld' | grep -Eo '^[a-z,-]+')

if [[ -z $hwRelease ]]; then
  echo  -e "${RED}Validation failed. Rollback helloworld release ${hwRelease} failed.${NC}"
  exit 3
else
  echo -e "${GREEN}Rollback helloworld successfully. The release name is ${hwRelease}${NC}"
fi 

echo "Validating service and portal healthy state..."
checkService

echo -e "${GREEN}Helm chart validation pass!${NC}"
exit 0
