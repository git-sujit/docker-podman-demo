#! /bin/bash

DIR=/opt/caspida/bin
source ${DIR}/CaspidaCommonEnv.sh
source ${DIR}/CaspidaFunctions

# needed when kubernetes complains about: 
#  cni0 Error adding network: failed to allocate for range 0: no IP addresses available in range set
# https://github.com/kubernetes/kubernetes/issues/57280

usage() {
  echo "$0 [ -y ]"
  exit 0
}

cont="N"

while getopts "hy" arg; do
  case $arg in
    y)
     cont="Y"
     ;;

    ?)
     usage
     ;;

    h)
     usage
     exit 1;
  esac
done

echo "$(date): Running: $0 $@" >> ${CASPIDA_OUT}

# if -y not specified on command-line
if [[ $cont =~ [Nn] ]]; then
  echo "this will reset kubernetes & kubernetes networking. You will have to rejoin this node to master"
  read -e -i "${cont}" -p  "Continue [Yy/Nn]: " cont
  if [[ "$cont" =~ [Nn] ]]; then
    msg="leaving kubernetes as is, exiting"
    echo ${msg}
    echo "$(date): ${msg}" >> ${CASPIDA_OUT}
    exit 0
  fi
fi

msg="resetting kubernetes & kubernetes networking"
echo ${msg}
echo "$(date): ${msg}" >> ${CASPIDA_OUT}

${SUDOCMD} service kubelet stop
${SUDOCMD} service cri-docker stop
${SUDOCMD} service docker stop

mounts=$(mount | grep volumes/kubernetes.io | awk  '{print $3}')
echo "$(date): ${node}: unmounting dangling kubernetes mounts: ${mounts}" >> ${CASPIDA_OUT}
if [[ -n ${mounts} ]]; then
  ${SUDOCMD} umount -f ${mounts} >> ${CASPIDA_OUT} 2>&1
fi

# if kubeadm doesn't exist: ${SUDOCMD} kubeadm reset -f will prompt for
# sudo password when running with restricted sudoers
command -v kubeadm
if [[ $? -eq 0 ]]; then
  ${SUDOCMD} kubeadm reset -f
else
  echo "kubeadm not found: skipping kubeadm reset"
fi

${SUDOCMD} rm -rf /var/lib/cni/
${SUDOCMD} rm -rf /var/lib/kubelet/*
${SUDOCMD} rm -rf /etc/cni/

# no ifconfig on CentOS/RHEL 7.5
${SUDOCMD} ip link set cni0 down
${SUDOCMD} ip link set flannel.1 down
${SUDOCMD} ip link set docker0 down

${SUDOCMD} ip link delete cni0
${SUDOCMD} ip link delete flannel.1

# uncomment these only as a last-resort if setup-containerization doesn't work
#  after a  CleanupKubeNetworking.sh on all nodes
# ${SUDOCMD} iptables -P INPUT ACCEPT
# ${SUDOCMD} iptables -P FORWARD ACCEPT
# ${SUDOCMD} iptables -P OUTPUT ACCEPT
# ${SUDOCMD} iptables -t nat -F
# ${SUDOCMD} iptables -t mangle -F
# ${SUDOCMD} iptables -F
# ${SUDOCMD} iptables -X
