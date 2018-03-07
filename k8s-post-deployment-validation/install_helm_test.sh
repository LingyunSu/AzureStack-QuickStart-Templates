#! /bin/bash
#Define Console Output Color
RED='\033[0;31m'    # For error
GREEN='\033[0;32m'  # For crucial check success 
NC='\033[0m'        # No color, back to normal

echo "Install Helm to check the health of Kubernete deployment..."

# Install helm if it is not available
helmcmd="$(helm)"
if [[ -z helmcmd ]]; then
  echo "Helm is not available, install helm..."

  # Create a folder for installation
  echo "Preparing directory for Helm installation..."
  cd ~
  mkdir helm
  cd ./helm

  # Download and install helm
  echo "Download installation script..."
  curl https://raw.githubusercontent.com/kubernetes/helm/master/scripts/get > get_helm.sh
  chmod 700 get_helm.sh
  ./get_helm.sh

  # Check again, if still not available, test fail
  helmcmd="$(helm)"
  if [[ -z helmcmd ]]; then
    echo  -e "${RED}Validation failed. Unable to install helm client. ${NC}"
	exit 3
  fi

  echo -e "${GREEN}Helm client has been installed.${NC}"
fi

echo -e "${GREEN}Helm client is ready.${NC}"

# Initial helm
echo "Initial helm..."
helm init --upgrade

# Wait for Tiller ready
echo "Check Helm client and Tiller availability..."
sleep 10s

# Check helm client and tiller status
helmClientVer="$(helm version | grep -o 'Client: \(.*\)[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}')"
helmServerVer="$(helm version | grep -o 'Server: \(.*\)[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}')"

if [[ -z $helmClientVer ]] || [[ -z $helmServerVer ]]; then
  echo  -e "${RED}Validation failed. Helm initial failed.${NC}"
  exit 3
fi

echo -e "${GREEN}Validation Pass! Helm has been initialed.${NC}"
