#!/bin/bash

##
# Copyright (C) 2014-2018 - Splunk Inc., All rights reserved.
# This is Splunk proprietary and confidential material and its use
# is subject to license terms.
##

CASPIDA_BIN_DIR=/opt/caspida/bin
CASPIDA_UPGRADE_UTILS_DIR=/opt/caspida/upgrade/utils
source ${CASPIDA_BIN_DIR}/CaspidaCommonEnv.sh
source ${CASPIDA_BIN_DIR}/CaspidaFunctions
source ${CASPIDA_BIN_DIR}/uba_upgrade_common.sh

# get the ubuntu version
get_os_version() {
  rel=`lsb_release -r 2>/dev/null| cut -d":" -f2`
  if [[ -z "$rel" ]]; then
    rel=`grep RELEASE /etc/lsb-release | cut -d"=" -f2`
  fi
  echo $rel
}

remove_old_containerization() {
  echo "removing earlier kubernetes setup"
  thisHost=`hostname -s`
  thisHost=${thisHost,,}  # to-lower
  thisHostFQDN=`hostname -f`
  thisHostFQDN=${thisHostFQDN,,}  # to-lower

  # remove the symlink, it will get created again by setup-containerization
  # otherwise the docker start will complain about the template'd daemon.json
  ${SUDOCMD} rm -fv /etc/docker/daemon.json

  # kubeadm reset needs docker running for reset to remove containers
  ${SUDOCMD} service docker start # start if not running

  kube_master=`$SUDOCMD kubectl --kubeconfig ${KUBELET_CONF} get nodes | grep master | cut -d' ' -f1`
  if [[ -z "$kube_master" ]]; then
    # can't tell if we are a running instance
    msg="kubernetes not running or installed, can't determine node role"
    echo "$(date): ${msg}"
  elif [[ "$kube_master" = "${thisHost}" || "$kube_master" = "${thisHostFQDN}" ||
          "$kube_master" = "${MYIP}" || "$kube_master" = "localhost" || "$kube_master" = 127.* ]]; then
    msg="calling Caspida remove-containerization"
    echo "$(date): ${msg}"
    ${CASPIDA_BIN_DIR}/Caspida remove-containerization
  else
    msg="not kubernetes master"
    echo "$(date): ${msg}"
  fi

  # Kubernetes 1.20.x will need an -f to bypass [y/n] prompt
  ${SUDOCMD} kubeadm reset -f

  ${SUDOCMD} service docker stop
  return 0
}

remove_docker_kube_packages() {
  # ok if not found
  ${SUDOCMD} service kubelet stop
  ${SUDOCMD} service docker stop
  status=0
  KubePkgs="kubectl kubelet kubernetes-cni kubeadm cri-tools"
  if [[ "${PLATFORM}" = "Red Hat" || "${PLATFORM}" = "OEL" ]]; then
    DockerPkgs="docker docker-common docker-client"
    rpm -qa | grep docker-1.12
    if [[ $? -eq 0 ]]; then
      remove_old_containerization
      echo "removing old docker packages"
      ${SUDOCMD} rpm -e ${DockerPkgs}
    fi

    echo "$(date): looking for Kubernetes packages lower than ${KUBE_VERSION}"
    rpm -qa | grep kubelet-${KUBE_VERSION}.*
    if [[ $? -ne 0 ]]; then
      remove_old_containerization
      echo "$(date): removing kubernetes old packages"
      # need to remove it since rpm -Uvh fails when same version is found installed (kubernetes-cni, socat..)
      ${SUDOCMD} rpm -e ${KubePkgs}
    fi
  else
    # remove additional pkgs for kubernetes
    KubePkgs="${KubePkgs} ebtables socat"
    DockerPkgs="bridge-utils cgroupfs-mount containerd dnsmasq-base dns-root-data docker docker.io libnetfilter-conntrack3 runc ubuntu-fan"
    dpkg -l | grep docker.io
    if [[ $? -eq 0 ]]; then
      remove_old_containerization
      echo "removing old docker packages"
      ${SUDOCMD} dpkg -P ${DockerPkgs}

      # need to rm it since we symlink it to /var/vcap/store/docker
      ${SUDOCMD} rm -rfv /var/lib/docker
    fi

    echo "$(date): looking for Kubernetes packages lower than ${KUBE_VERSION}"
    dpkg -l | egrep "kubelet.*${KUBE_VERSION}.*"
    if [[ $? -ne 0 ]]; then
      remove_old_containerization
      echo "$(date): removing kubernetes old packages"
      ${SUDOCMD} dpkg -P ${KubePkgs}
    fi
  fi

  if [[ $status -ne 0 ]]; then
    echo "$(date): failed uninstalling old docker/kubernetes packages"
    return $status
  fi

  # umount dangling kubernetes volumes: ignore return value
  thisHost=$(hostname -s)
  cleanup_kube_data ${thisHost} # in CaspidaFunctions

  # remove previous config
  ${SUDOCMD} rm -fv /etc/systemd/system/kubelet.service.d/90-splunkuba-local.conf
  rm -fv /etc/caspida/local/conf/containerization.properties
  return 0
}

# remove all kubernetes & our images.
remove_old_kubernetes_images() {
  # stop registry if running
  /opt/caspida/containerization/bin/StopRegistry.sh -r

  # get all except ubabase, this depends on ubuntu-splunkuba-deps & will fail if the order
  # gets messed up & centos comes before ubabase.
  local DockerImages=$(${SUDOCMD} docker images)

  # for debug: log the images to o/p
  echo "$(date): docker images listing"
  echo "${DockerImages}"

  local otherImages=$(echo "${DockerImages}" | egrep -v 'IMAGE|ubabase' | awk '{print $3}' | sort | uniq) # all except ubabase
  local ubaImage=$(echo "${DockerImages}" | grep ubabase | awk '{print $3}' | sort | uniq) # only ubabase
  if [[ -z ${otherImages} && -z ${ubaImage} ]]; then
    echo "$(date): WARNING: no previous kubernetes images found !!"
    return 0
  fi

  local OldImages="${ubaImage} ${otherImages}"
  echo "$(date): removing older kubernetes images:" $OldImages
  ${SUDOCMD} docker rmi -f ${OldImages}
  status=$?
  if [[ ${status} -ne 0 ]]; then
    echo "$(date): error : failed to remove older kubernetes images, if containers are still running, please stop containers and try again."
  fi
  return ${status}
}

#
# To save container images:
# sudo  docker images  | egrep -v "ubabase|CREATED" > /tmp/images
# awk '{ gsub("/", "^", $1);  printf "sudo docker save %s > /var/vcap/sys/tmp/caspida/images/%s:%s:%s.tar\n", $3,$3,$1,$2 }' /tmp/images
#   filename format: hash:name:version.tar
#   name: "/" replaced with "^"
#

# installs docker, kubernetes packages and loads the docker images we need
install_docker_kubernetes() {
  PKG_DIR=$1
  status=0
  DockerVersion=24.0
  echo "$(date): detected platform: ${PLATFORM}"

  TOP_DIR=${PKG_DIR}/rpm
  KUBERNETES_DIR=kubernetes

  if [ "${PLATFORM}" = "Red Hat" ] || [ "${PLATFORM}" = "OEL" ]; then
    InstallOrUpgradeDocker=""

    rpm -qa | grep docker-ce
    if [[ $? -eq 0 ]]; then
      echo "docker-ce already installed, checking version"
      rpm -qa | grep docker-ce-${DockerVersion}
      if [[ $? -eq 0 ]]; then
        echo "docker-ce already at ${DockerVersion}, skipping"
      else
        # only upgrade the docker-ce packages
        InstallOrUpgradeDocker="-Uvh" # upgrade
      fi
    else
      InstallOrUpgradeDocker="-ivh" # install
    fi

    if [[ -n ${InstallOrUpgradeDocker} ]]; then
      echo "$(date): installing/upgrading docker: ${InstallOrUpgradeDocker}"
      ${SUDOCMD} rpm ${InstallOrUpgradeDocker} --replacepkgs ${TOP_DIR}/docker-ce/*.rpm
      status=$?
      if [[ $status -ne 0 ]]; then
        echo "$(date): failed installing/upgrading docker packages"
        return $status
      fi
    fi

    rpm -qa| grep kubeadm-${KUBE_VERSION}
    if [[ $? -eq 0 ]]; then
      echo "$(date): kubeadm-${KUBE_VERSION} already installed, skipping"
    else
      echo "$(date): installing kubernetes"
      #Kubernetes needs to be installed in this order due to interdependencies.
      ${SUDOCMD} rpm -Uvh ${TOP_DIR}/${KUBERNETES_DIR}/libnetfilter*.rpm
      ${SUDOCMD} rpm -Uvh ${TOP_DIR}/${KUBERNETES_DIR}/conntrack-tools*.rpm
      ${SUDOCMD} rpm -Uvh ${TOP_DIR}/${KUBERNETES_DIR}/*cri-tools*.rpm
      ${SUDOCMD} rpm -Uvh ${TOP_DIR}/${KUBERNETES_DIR}/*kubectl*.rpm
      ${SUDOCMD} rpm -Uvh ${TOP_DIR}/${KUBERNETES_DIR}/*kubernetes-cni*.rpm ${TOP_DIR}/${KUBERNETES_DIR}/*kubelet*.rpm
      ${SUDOCMD} rpm -Uvh ${TOP_DIR}/${KUBERNETES_DIR}/*kubeadm*.rpm
      status=$?
      if [[ $status -ne 0 ]]; then
        echo "$(date): failed installing kubernetes packages"
        return $status
      fi
    fi

    # prevent them from being upgraded
    ${SUDOCMD} yum versionlock add kubectl kubelet kubernetes-cni kubeadm cri-tools
  else
    # check if we are at the right version of ubuntu
    osVer=`get_os_version`
    checkVersion $osVer ${UBUNTU_VERSION[@]}
    status=$?
    if [[ $status -ne 0 ]]; then
      echo "$(date): need ubuntu release ${UBUNTU_VERSION[@]}, found ubuntu ${osVer}, aborting"
      return 1
    fi

    # ubuntu
    dpkg -l | egrep docker-ce.*${DockerVersion}
    if [[ $? -eq 0 ]]; then
      echo "docker-ce already installed, skipping"
    else
      echo "$(date): installing docker"
      ${SUDOCMD} dpkg -Ei ${PKG_DIR}/deb/docker-ce/*.deb
      status=$?
      if [[ $status -ne 0 ]]; then
        echo "$(date): failed installing docker packages"
        return $status
      fi
    fi

    echo "$(date): installing new kubernetes packages"
    ${SUDOCMD} dpkg -Ei ${PKG_DIR}/deb/kubernetes/*.deb
    status=$?
    if [[ $status -ne 0 ]]; then
      echo "$(date): failed installing kubernetes packages"
      return $status
    fi

    # prevent them from being upgraded
    ${SUDOCMD} apt-mark hold kubeadm kubectl kubelet kubernetes-cni cri-tools
  fi

  # link /var/lib/docker to /var/vcap/store/docker: containers need a lot of disk space
  Stopped="false"
  for dir in docker kubelet
  do
    SrcDir="/var/lib/${dir}"
    if [[ -L "${SrcDir}" ]]; then
      echo "$(date): is already a symlink: ${SrcDir}"
      continue;
    fi

    if [[ "${Stopped}" == "false" ]]; then
      Stopped="true" # stop once
      ${SUDOCMD} service docker stop
      ${SUDOCMD} service kubelet stop
    fi

    if [[ -d ${SrcDir} ]]; then
      # directory & not a symlink
      echo "$(date): symlinking non-empty dir: ${dir}"
      #remove existing dir: else will get moved under it
      ${SUDOCMD} rm -rfv /var/vcap/store/${dir}
      ${SUDOCMD} mv -v ${SrcDir} /var/vcap/store/
    else
      echo "$(date): symlinking empty: ${dir}"
      ${SUDOCMD} mkdir -pv -m 755 /var/vcap/store/${dir}
    fi
    ${SUDOCMD} ln -sv /var/vcap/store/${dir} ${SrcDir}
  done

  #install Kubernetes related packages (cri-dockerd)
  echo "$(date): installing Kubernetes related packages"
  ${SUDOCMD} ${CASPIDA_UPGRADE_UTILS_DIR}/install_kubernetes_utils.sh ${TOP_DIR}/${KUBERNETES_DIR}
  status=$?
  if [[ $status -ne 0 ]]; then
    echo "$(date): failed installing kubernetes related packages"
    return $status
  fi

  # start up docker and the kubelet
  echo "$(date): starting docker & kubelet"
  ${SUDOCMD} systemctl daemon-reload
  ${SUDOCMD} service docker start
  ${SUDOCMD} service cri-docker start
  ${SUDOCMD} service kubelet start

  return $status
}

load_default_images() {
  PKG_DIR=$1
  status=0

  TOP_DIR=${PKG_DIR}/containers
  if [ ! -d ${TOP_DIR} ]; then
    TOP_DIR=${PKG_DIR}/tar # try the old way
  fi

  # load the images
  for file in ${TOP_DIR}/containerization_images/*.tar
  do
    filename=$(basename $file)

    echo "$(date): loading image: $file"
    if [[ $file == *":uba-impala:"* ]]; then
      # uba-impala is an exported container image and needs the docker import cmd
      sha_hash=$(${SUDOCMD} docker import $file)
      ((status+=$?))
      hash=$(echo $sha_hash | cut -d ":" -f 2)
    else
      ${SUDOCMD} docker load < $file
      ((status+=$?))
      hash=$(echo $filename | cut -d":" -f1)
    fi

    if [[ ${status} -ne 0 ]]; then
      echo "$(date): failed to load $file"
      break
    fi

    orig_name=$(echo $filename | cut -d":" -f2)
    version_str=$(echo $filename | cut -d":" -f3)

    name=${orig_name//^//}
    version=${version_str//.tar/}
    ${SUDOCMD} docker tag ${hash} ${name}:${version}
    ((status+=$?))
  done

  if [[ ${status} -ne 0 ]]; then
    echo "$(date): loading images failed"
    return ${status}
  fi

  return $status
}

usage() {
  echo "usage: $0 [ -m ] [ -i ] <packages_dir>"
  echo "  -m : indicates its a docker master node [default]"
  echo "  -i : only loads default docker images [used when docker + kubernetes are already installed]"
}

MasterNode="true"
OnlyInstallImages="false"

while getopts "mih" arg; do
  case ${arg} in
    i)
      OnlyInstallImages="true"
      ;;
    m)
      MasterNode="true" # default
      ;;
    h)
      usage
      exit 1
     ;;
  esac
done

shift $((OPTIND - 1))
DIR=$1
if [ -z ${DIR} ]; then
  echo "missing dir: needs the directory containing the packages as an argument"
  usage
  exit 1
fi

if [ ! -d ${DIR} ]; then
  echo "directory not found: ${DIR}"
  exit 1
fi

runningAs=`whoami`
if [[ "${CASPIDA_USER}" =~ [\<%\"] || "${CASPIDA_GROUP}" =~ '[\<%\"]' ]]; then
  CASPIDA_USER="caspida" # called before setup:
  CASPIDA_GROUP="caspida"
fi

if [ ${runningAs} != "${CASPIDA_USER}" ]; then
  echo "running as: ${runningAs}"
  echo "run this script as ${CASPIDA_USER}, exiting"
  exit 2;
fi

if [[ "${OnlyInstallImages}" == "true" ]]; then
  # Remove old kubernetes packages to save space
  msg="removing old kubernetes packages"
  echo "$(date): ${msg}"
  remove_old_kubernetes_images ${DIR}
  status=$?
  if [[ $status -eq 0 ]]; then
    echo "$(date): ${msg}: successful"
  else
    echo "$(date): ${msg}: failed"
    exit 3
  fi

  msg="loading default docker % kubernetes images"
  echo "$(date): ${msg}"
  load_default_images ${DIR}
  status=$?

  if [[ $status -eq 0 ]]; then
    echo "$(date): ${msg}: successful"
  else
    echo "$(date): ${msg}: failed"
  fi
  exit $status
fi

msg="uninstalling older docker & kubernetes packages"
echo "$(date): ${msg}"
remove_docker_kube_packages
status=$?
if [[ $status -eq 0 ]]; then
  echo "$(date): ${msg}: successful"
else
  echo "$(date): ${msg}: failed"
  exit 3
fi

msg="installing docker & kubernetes packages"
echo "$(date): ${msg}"
install_docker_kubernetes ${DIR}
status=$?
if [[ $status -eq 0 ]]; then
  echo "$(date): ${msg}: successful"
else
  echo "$(date): ${msg}: failed"
  exit 3
fi

msg="removing old kubernetes packages"
echo "$(date): ${msg}"
remove_old_kubernetes_images ${DIR}
status=$?
if [[ $status -eq 0 ]]; then
  echo "$(date): ${msg}: successful"
else
  echo "$(date): ${msg}: failed"
  exit 3
fi

if [[ "${MasterNode}" == "true" ]]; then
  msg="loading default docker images"
  echo "$(date): ${msg}"
  load_default_images ${DIR}
  status=$?
  if [[ $status -eq 0 ]]; then
    echo "$(date): ${msg}: successful"
  else
    echo "$(date): ${msg}: failed"
    exit 4
  fi
else
  echo "$(date): non-master node, loading default docker images skipped"
fi

# keep the service stopped: setup-containerization will start them as required
${SUDOCMD} service kubelet stop
${SUDOCMD} service cri-docker stop
${SUDOCMD} service docker stop

${SUDOCMD} systemctl disable kubelet
${SUDOCMD} systemctl disable docker

exit 0
