#! /bin/bash
#Define Console Output Color
RED='\033[0;31m'    # For error
GREEN='\033[0;32m'  # For crucial check success 
NC='\033[0m'        # No color, back to normal

echo "Make a helm chart for hello-world app and deploy in Kubernete to verify the usability of helm"
echo "Preparing helm..."

# Install helm if it is not available
helmcmd="$(helm)"
if [[ -z helmcmd ]]; then
  echo "Helm is not available, install helm..."
  
  # Create a folder for installation
  cd ~
  mkdir helm
  cd ./helm
  
  # Download and install helm
  curl https://raw.githubusercontent.com/kubernetes/helm/master/scripts/get > get_helm.sh
  chmod 700 get_helm.sh
  ./get_helm.sh

  # Check again, if still not available, test fail
  helmcmd="$(helm)"
  if [[ -z helmcmd ]]; then
    echo  -e "${RED}Validation failed. Unable to install helm. ${NC}"
	exit 3
  fi
  
  echo -e "${GREEN}Helm is installed.${NC}"
fi

echo -e "${GREEN}Helm is ready.${NC}"

# Initial helm
echo "Initial helm..."
helm init --upgrade

# Check healm health status
helmClientVer="$(helm version | grep -o 'Client: \(.*\)[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}')"
helmServerVer="$(helm version | grep -o 'Server: \(.*\)[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}')"

if [[ -z $helmClientVer ]] || [[ -z $helmServerVer ]]; then
  echo  -e "${RED}Validation failed. Helm initial failed.${NC}"
  exit 3
else
  echo -e "${GREEN}Helm is initialed.${NC}"
fi

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
curl https://raw.githubusercontent.com/LingyunSu/AzureStack-QuickStart-Templates/master/k8s-post-deployment-validation/helloworld.yaml > helloworld.yaml

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

echo -e "${GREEN}Helm chart validation pass!${NC}"
exit 0
