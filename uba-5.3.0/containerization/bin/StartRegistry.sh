#!/bin/bash

DIR=/opt/caspida/bin
source ${DIR}/CaspidaCommonEnv.sh
source ${DIR}/CaspidaFunctions

# only need to restart docker locally
docker_restart() {
  local retry=$1
  echo "$(date): stopping docker: #attempt=${retry}"
  ${SUDOCMD} service docker stop

  echo "$(date): starting docker: #attempt=${retry}"
  ${SUDOCMD} service docker start
  sleep 10 # give it a few seconds after startup
  echo
}

NAME=registry
PORT=5000

attempt=0
MaxRetry=3

while [[ ${attempt} -le ${MaxRetry} ]]; do
  # use the docker registry directly
  output=$(${SUDOCMD} docker container ls -a -f name=${NAME})
  status=$?
  if [[ ${status} -eq 0 ]]; then
    echo "${output}" | grep ${NAME}
    status=$?
    if [[ ${status} -eq 0 ]]; then
      # just needs a start
      echo "resume existing registry: #attempt=${attempt}"
      ${SUDOCMD} docker start ${NAME}
    else
      # run it
      echo "starting new registry: #attempt=${attempt}"
      ${SUDOCMD} docker run -d -e REGISTRY_STORAGE_DELETE_ENABLED=true -p ${PORT}:${PORT} \
            --restart=always --name ${NAME} ${NAME}:2
      nonmaster_ips_string=$(get_container_nonmaster_nodes_ip)
      external_interface=`route | grep default | awk '{print $8}'`
      echo "Adding iptable rules for the worker nodes ${nonmaster_ips_string} and interface ${external_interface}"
      ${SUDOCMD} iptables -I DOCKER-USER -i ${external_interface} -j DROP
      ${SUDOCMD} iptables -I DOCKER-USER -s ${nonmaster_ips_string} -i ${external_interface} -j ACCEPT
      # To run a secure registry
      #   https://docs.docker.com/registry/insecure/#use-self-signed-certificates
      # ${SUDOCMD} docker run -d --restart=always --name registry -v /var/vcap/store/caspida/certs:/certs \
      #  -e REGISTRY_HTTP_ADDR=0.0.0.0:${PORT} -e REGISTRY_HTTP_TLS_CERTIFICATE=/certs/my-server.crt.pem  \
      #    -e REGISTRY_HTTP_TLS_KEY=/certs/my-server.key.pem -p ${PORT}:${PORT}  ${NAME}:2

      # doesn't work with the cert in /var/vcap/store/caspida/certs, complains
      #    x509: certificate is valid for 10.140.195.162, not ubaperf5 (our cert contains IP addr not hostname)
      # works with a new self-signed cert as described in:
      #    https://docs.docker.com/registry/insecure/#use-self-signed-certificates
    fi
    status=$?
  fi

  if [[ ${status} -eq 0 ]]; then
    break;
  elif [[ ${attempt} -lt ${MaxRetry} ]]; then
    echo "could not launch registry: #attempt=${attempt}/#max=${MaxRetry}"
    docker_restart ${attempt}
  fi
  ((attempt++))
done

if [[ ${status} -eq 0 ]]; then
  echo "successfully launched registry (#atempts=$attempt)"
else
  echo "launch registry failed, exceeded max-retries: #attempt=${attempt}/#max=${MaxRetry}"
fi

exit ${status}

# The registry-svc doces not work because the hostPort is not supported by CNI currently (kubernetes 1.9)
# See https://kubernetes.io/docs/concepts/cluster-administration/network-plugins/#cni
#  Limitation: Due to #31307, HostPort won’t work with CNI networking plugin at the moment. That means all hostPort
#    attribute in pod would be simply ignored.
# to workaround this, we were turning off CNI KUBELET_NETWORK_ARGS in /etc/systemd/system/kubelet.service.d/10-kubeadm.conf
# which was preventing the DNS from working

#echo "Launching Registry PersistentVolume"
#${SUDOCMD} /usr/bin/kubectl --kubeconfig ${KUBE_ADMIN_CONF} apply -f /opt/caspida/containerization/orchestration/kubernetes/registry/registry-pv.yaml.in
#
#echo "Launching Registry PersistentVolumeClaim"
#${SUDOCMD} /usr/bin/kubectl --kubeconfig ${KUBE_ADMIN_CONF} apply -f /opt/caspida/containerization/orchestration/kubernetes/registry/registry-pvc.yaml.in
#
#echo "Launching Registry ReplicationController"
#${SUDOCMD} /usr/bin/kubectl --kubeconfig ${KUBE_ADMIN_CONF} apply -f /opt/caspida/containerization/orchestration/kubernetes/registry/registry-rc.yaml
#
#echo "Launching Registry Service"
#${SUDOCMD} /usr/bin/kubectl --kubeconfig ${KUBE_ADMIN_CONF} apply -f /opt/caspida/containerization/orchestration/kubernetes/registry/registry-svc.yaml
#
#echo "Launching Registry DaemonSet"
#${SUDOCMD} /usr/bin/kubectl --kubeconfig ${KUBE_ADMIN_CONF} apply -f /opt/caspida/containerization/orchestration/kubernetes/registry/registry-ds.yaml

#Not Required on Master
#sleep 10

#POD=$(kubectl --kubeconfig ${KUBE_ADMIN_CONF} get pods --namespace kube-system -l k8s-app=kube-registry-upstream \
#            -o template --template '{{range .items}}{{.metadata.name}} {{.status.phase}}{{"\n"}}{{end}}' \
#            | grep Running | head -1 | cut -f1 -d' ')
#kubectl --kubeconfig ${KUBE_ADMIN_CONF} port-forward --namespace kube-system $POD ${PORT}:${PORT} &
