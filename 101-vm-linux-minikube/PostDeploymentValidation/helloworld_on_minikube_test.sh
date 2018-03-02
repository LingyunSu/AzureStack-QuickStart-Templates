#! /bin/bash
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
  if [[ -z $isMinikubeRunning ]]; then
    echo -e "${RED}Failed to start minikube. Please troubleshoot the root cause.${NC} "
    exit 3
  else
    echo -e "${GREEN}Minikube is started.${NC}"
  fi
else
  echo -e "${GREEN}Minikube is started.${NC}"
fi

# Run helloworld application on mikikube
echo "Run hello-world on minikube..."
sudo kubectl run helloworld --image=msazurestackdocker/linsuhyperkube:v1 --port=8080

# Check pod status
i=0
isPodRunning=0
while [ $i -lt 10 ];do
  podstatus="$(sudo kubectl get pods | grep 'Running')"

  if [[ -z $podstatus ]]; then
    echo "Tracking helloworld pod status..."
    sleep 10s
  else
    echo -e "${GREEN}Pod is running.${NC}"
    isPodRunning=1
    break
  fi
  let i=i+1
done

# Test fail if the pod is not running
if [ $isPodRunning -eq 0 ]; then
  echo -e "${RED}Validation failed because the pod for hello-world app is not running.${NC}"
  exit 3
fi

# Expose hello-world app
echo "Expose hello-world app..."
sudo kubectl expose deployment helloworld --type=LoadBalancer

i=0
while [ $i -lt 10 ];do
  # Retrive external IP
  externalIp=$(sudo kubectl get services helloworld -o=custom-columns=NAME:.status.loadBalancer.ingress[0].ip | grep -oP '(\d{1,3}\.){1,3}\d{1,3}')

  if [[ -z $externalIp ]]; then
    echo "Tracking helloworld servic status..."
    sleep 10s
  else
    echo "External IP for helloworld:"$externalIps
  fi
  let i=i+1
done

if [[ -z $externalIp ]]; then
  echo -e "${RED}Validation failed because the external ip for hello-world app is not available.${NC}"
  exit 3
fi

appurl="http://"$externalIp":8080"
appContent="$(curl ${appurl})"
if [ $appContent -eq "Hello World!" ]; then
  echo -e "${GREEN}Minikube post-deployment validation pass!${NC}"
  exit 0
else
  echo -e "${RED}Validation failed because the app is not return right content. App return:"$appContent "${NC}"
  exit 3
fi
