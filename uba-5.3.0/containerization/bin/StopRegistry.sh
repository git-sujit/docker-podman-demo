#!/bin/bash

DIR=/opt/caspida/bin
source ${DIR}/CaspidaCommonEnv.sh
source ${DIR}/CaspidaFunctions

usage() {
  echo "Usage: comand to stop registry & optionally delete it"
  echo "  $0 -r"
  echo "  -r Remove registry to free up disk space[optional]"
  echo
}

RemoveRegistry="false"
while getopts "hr" arg; do
  case $arg in
    r)
      RemoveRegistry="true"
      ;;
    h)
      usage
      exit 1
      ;;
  esac
done

NAME=registry
echo "Running: $0 $@"

echo "Stopping Registry"
${SUDOCMD} docker stop ${NAME}
status=$?

if [[ ${RemoveRegistry} == "false" ]]; then
  exit ${status} # done
fi

nonmaster_ips_string=$(get_container_nonmaster_nodes_ip)
external_interface=`route | grep default | awk '{print $8}'`
echo "Removing iptable rules for the worker nodes ${nonmaster_ips_string} and interface ${external_interface}"
${SUDOCMD} iptables -D DOCKER-USER -i ${external_interface} -j DROP
${SUDOCMD} iptables -D DOCKER-USER -s ${nonmaster_ips_string} -i ${external_interface} -j ACCEPT

# remove registry: The registry doesn't garbage collect effectively causing a lot of disk usage
# when images are pushed frequently. See UBA-

echo "$(date): Removing Registry data"
echo "$(date): $0: Running: docker rm ${NAME}"

${SUDOCMD} docker rm ${NAME} # remove container (not image)
if [[ ${status} -ne 0 ]]; then
  echo "failed to remove registry, ignoring & trying to free up storage"
fi

echo "$(date): $0: Running: docker volume prune"
${SUDOCMD} docker volume prune -f
status=$?

exit ${status}

#echo "Removing Registry Portforwarding"
#ps -ef | grep ".conf port-forward" | grep -v grep | awk '{ print $2 }' | xargs -r $SUDOCMD kill -15

#echo "Deleting Registry PersistentVolume"
#${SUDOCMD} /usr/bin/kubectl --kubeconfig ${KUBE_ADMIN_CONF} delete -f /opt/caspida/containerization/orchestration/kubernetes/registry/registry-pv.yaml.in

#echo "Deleting Registry PersistentVolumeClaim"
#${SUDOCMD} /usr/bin/kubectl --kubeconfig ${KUBE_ADMIN_CONF} delete -f /opt/caspida/containerization/orchestration/kubernetes/registry/registry-pvc.yaml.in

#echo "Deleting Registry ReplicationController"
#${SUDOCMD} /usr/bin/kubectl --kubeconfig ${KUBE_ADMIN_CONF} delete -f /opt/caspida/containerization/orchestration/kubernetes/registry/registry-rc.yaml

#echo "Deleting Registry Service"
#${SUDOCMD} /usr/bin/kubectl --kubeconfig ${KUBE_ADMIN_CONF} delete -f /opt/caspida/containerization/orchestration/kubernetes/registry/registry-svc.yaml

#echo "Deleting Registry DaemonSet"
#${SUDOCMD} /usr/bin/kubectl --kubeconfig ${KUBE_ADMIN_CONF} delete -f /opt/caspida/containerization/orchestration/kubernetes/registry/registry-ds.yaml
 
