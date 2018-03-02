#! /bin/bash
#Define Console Output Color
RED='\033[0;31m'    # For error
GREEN='\033[0;32m'  # For crucial check success 
NC='\033[0m'        # No color, back to normal

echo "Run post-deployment test based on helm to validate the health of Kubernete deployment..."
echo "Preparing helm..."
cd ~
mkdir heml
cd ./helm

# Download, install helm
curl https://raw.githubusercontent.com/kubernetes/helm/master/scripts/get > get_helm.sh
chmod 700 get_helm.sh
./get_helm.sh

# Initial helm
echo "Initial helm..."
helm init --upgrade

# Check healm health status
helmClientVer="$(helm version | grep -o 'Client: \(.*\)[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}')"
helmServerVer="$(helm version | grep -o 'Server: \(.*\)[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}')"

if [ -z $helmClientVer ] || [ -z $helmServerVer ]; then
  echo  -e "${RED}Validation failed. Helm initial failed.${NC}"
  exit 3
else
  echo -e "${GREEN}Helm is started.${NC}"
fi

# Deploy wordpress 
echo "Deploy wordpress"
helm repo update
helm install stable/wordpress

wpRelease=$(helm ls -d -r | grep 'DEPLOYED\(.*\)wordpress' | grep -Eo '^[a-z,-]+')

if [ -z $wpRelease ]; then
  echo  -e "${RED}Validation failed. Helm release for wordpress not found.${NC}"
  exit 3
else
  echo -e "${GREEN}Wordpress is deployed through helm.${NC}"
fi

# Check pods status
i=0
while [ $i -lt 20 ];do
  mariadbPodstatus="$(sudo kubectl get pods --selector app=${wpRelease}-mariadb | grep 'Running')"
  wdpressPodstatus="$(sudo kubectl get pods --selector app=${wpRelease}-mariadb | grep 'Running')"

  if [ -z $mariadbPodstatus ] || [ -z $wdpressPodstatus ]; then
    echo "Tracking mariadb and wordpress pods status..."
    sleep 30s
  else
    echo -e "${GREEN}Pods are ready.${NC}"
    break
  fi
  let i=i+1
done

# Test fail if the either pod is not running
failingPod=""
if [ -z $mariadbPodstatus ]; then
  $failingPod="mariadb"
fi

if [ -z $wdpressPodstatus ]; then
  $failingPod=$failingPod" and wordpress"
fi

if [ -z failingPod ]; then
  echo -e "${RED}Validation failed because the pods for "$failingPod"is not running.${NC}"
  exit 3
fi

# Check external Ip for wordpress


# Check portal status
