#! /bin/bash
#Define Console Output Color
RED='\033[0;31m'    # For error
GREEN='\033[0;32m'  # For crucial check success 
NC='\033[0m'        # No color, back to normal

LOGFILE="minikubetest.log"
ISAUTO=false
if [[ $1 == "AUTO" ]]; then
  ISAUTO=true
  echo "Test Start: "$(date +'%Y-%m-%d %H:%M:%S') > ./$LOGFILE
fi

echo "Run post-deployment test to validate the health of minikube deployment..."

# Check minikube status, if it is off start minkube
echo "Check minikube status..."
isMinikubeRunning="$(sudo minikube status | grep 'minikube: Running')"

# Start minikube if it is off
if [ -z $isMinikubeRunning ]; then
  echo "Minikube is off, starting minikube..."
  sudo minikube start --vm-driver 'none'

  # Check status again
  isMinikubeRunning="$(sudo minikube status | grep 'minikube: Running')"
  if [[ -z $isMinikubeRunning ]]; then
    echo -e "${RED}Validation failed. Unable to start minikube. ${NC} "
    exit 3
  else
    echo -e "${GREEN}Minikube has been started.${NC}"
  fi
else
  echo -e "${GREEN}Minikube is started.${NC}"
fi

if $ISAUTO; then
  echo "====== LOG Kubernete Version ====" >> ./$LOGFILE
  sudo kubectl version >> ./$LOGFILE
  echo >> ./$LOGFILE
fi

# Run helloworld application on mikikube
echo "Run hello-world on minikube...(image:msazurestackdocker/linsuhyperkube:v1)"
sudo kubectl run helloworld --image=msazurestackdocker/linsuhyperkube:v1 --port=8080

# Check pod status
i=0
isPodRunning=0
while [ $i -lt 30 ];do
  podstatus="$(sudo kubectl get pods --selector run=helloworld | grep 'Running')"

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

# Expose hello-world service
echo "Expose hello-world service..."
sudo kubectl expose deployment helloworld --type=LoadBalancer

i=0
while [ $i -lt 10 ];do
  # Retrive external IP
  nodeIp=$(sudo kubectl describe service helloworld | grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}:8080')

  if [[ -z $nodeIp ]]; then
    echo "Tracking helloworld servic status..."
    sleep 10s
  else
    echo "Get node IP/port for helloworld:"$nodeIp
    break
  fi
  let i=i+1
done

if [[ -z $nodeIp ]]; then
  echo -e "${RED}Validation failed because the external ip for hello-world app is not available.${NC}"
  exit 3
fi

appurl="http://"$nodeIp
appContent="$(curl ${appurl})"
echo "curl return: "$appContent
if [[ $appContent == "Hello World!" ]]; then
  echo -e "${GREEN}Minikube post-deployment validation pass!${NC}"
  # Write return
  if $ISAUTO; then
    echo
    echo "[[[(TESTOUTPUT)  PodIP:$nodeIp ]]]"
  fi

  exit 0
else
  echo -e "${RED}Validation failed. The hello-world app did not return expected content.${NC}"
  exit 3
fi
