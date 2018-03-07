#! /bin/bash
#Define Console Output Color
RED='\033[0;31m'    # For error
GREEN='\033[0;32m'  # For crucial check success 
NC='\033[0m'        # No color, back to normal

ISAUTO=false
if [[ $1 == "AUTO" ]]; then
  ISAUTO=true
  echo "Test Start: "$(date +'%Y-%m-%d %H:%M:%S') > ./$LOGFILE
fi

echo "Deploy wordpress on Kubernete cluster through helm to check the health of Kubernete deployment ..."
echo "Check prerequisite: helm..."

# Check healm status
helmClientVer="$(helm version | grep -o 'Client: \(.*\)[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}')"
helmServerVer="$(helm version | grep -o 'Server: \(.*\)[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}')"

if [[ -z $helmClientVer ]] || [[ -z $helmServerVer ]]; then
  echo  -e "${RED}Validation failed. Helm is not ready. Please install and initial helm before run this validation script.${NC}"
  exit 3
fi

echo -e "${GREEN}Helm is ready.${NC}"

# Deploy wordpress 
echo "Update helm repository..."
helm repo update

echo "Install wordpress..."
helm install stable/wordpress

echo "Done with installation, checking release status..."
wpRelease=$(helm ls -d -r | grep 'DEPLOYED\(.*\)wordpress' | grep -Eo '^[a-z,-]+')

if [[ -z $wpRelease ]]; then
  echo  -e "${RED}Validation failed. Helm release for wordpress not found.${NC}"
  exit 3
else
  echo -e "${GREEN}Wordpress is deployed through helm. The release name is ${wpRelease}${NC}"
fi

# Check pods status
echo "Monitoring pods status..."
i=0
while [ $i -lt 20 ];do
  mariadbPodstatus="$(sudo kubectl get pods --selector app=${wpRelease}-mariadb | grep 'Running')"
  wdpressPodstatus="$(sudo kubectl get pods --selector app=${wpRelease}-wordpress | grep 'Running')"

  if [[ -z $mariadbPodstatus ]] || [[ -z $wdpressPodstatus ]]; then
    echo "Tracking pods status of mariadb and wordpress..."
    sleep 30s
  else
    echo -e "${GREEN}Pods for mariadb and wordpress are all ready.${NC}"
    break
  fi
  let i=i+1
done

# Test fail if the either pod is not running
failedPods=""
if [[ -z $mariadbPodstatus ]]; then
  $failedPods="mariadb"
fi

if [[ -z $wdpressPodstatus ]]; then
  $failedPods=$failedPods" and wordpress"
fi

if [[ -z failedPods ]]; then
  echo -e "${RED}Validation failed because the pods for "$failedPods"is not running.${NC}"
  exit 3
fi

# Check external IP for wordpress
i=0
while [ $i -lt 20 ];do
  externalIp=$(sudo kubectl get services ${wpRelease}-wordpress -o=custom-columns=NAME:.status.loadBalancer.ingress[0].ip | grep -oP '(\d{1,3}\.){1,3}\d{1,3}')

  if [[ -z $externalIp ]]; then
    echo "Tracking wordpress external IP status..."
    sleep 30s
  else
    echo -e "${GREEN}External IP is available: ${externalIp}.${NC}"
    break
  fi
  let i=i+1
done

if [[ -z $externalIp ]]; then
  echo -e "${RED}Validation failed. The external IP of wordpress is not available.${NC}"
  exit 3
fi

# Check portal status
portalState="$(curl http://${externalIp} --head -s | grep '200 OK')"

if [[ -z portalState ]]; then
  echo -e "${RED}Validation failed. The portal of wordpress is unhealthy.${NC}"
  exit 3
else
  echo -e "${GREEN} Wordpress is on. Portal returns status: ${portalState}.${NC}"

  # If it is called from automation, return external ip for additional validation
  if $ISAUTO; then
    echo
    echo "[[[(TESTOUTPUT)  WordpressIP:$externalIp ]]]"
  fi
fi

echo -e "${GREEN}Successfully deployed wordpress on Kubernete cluster through helm, validation pass!.${NC}"
exit 0
