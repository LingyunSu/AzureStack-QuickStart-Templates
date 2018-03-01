#! /bin/sh

#Define Console Output Color
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

echo "Run post-deployment test to check the health of minikube deployment..."

# Check minikube status, if it is not running start minkube
echo "Check minikube status..."
isMinikubeRunning="$(sudo minikube status | grep 'minikube: Running')"

# Start minikube if it is off
if [ -z $isMinikubeRunning ]; then
  echo "Minikube is off, starting minikube..."
  sudo minikube start --vm-driver 'none'
  sleep 5s

  # Check status again
  isMinikubeRunning="$(sudo minikube status | grep 'minikube: Running')"
  if [ -z $isMinikubeRunning ]; then
    echo "${RED}Failed to start minikube. Please troubleshoot the root cause.${NC} "
    exit 3
  else
    echo "${GREEN}Minikube is started.${NC}"
  fi
else
  echo "${GREEN}Minikube is started.${NC}"
fi

# Now start install helloworld application on mikikube
echo "Running hello-world on minikube"
sudo kubectl run helloworld --image=msazurestackdocker/linsuhyperkube:v1 --port=8080
sudo kubectl expose deployment helloworld --type=LoadBalancer


echo "${GREEN}Minikube post-deployment validation pass!${NC}"
exit 0



