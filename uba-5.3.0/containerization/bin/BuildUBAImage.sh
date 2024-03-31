#!/bin/bash

DIR=/opt/caspida/bin
source ${DIR}/CaspidaCommonEnv.sh
source ${DIR}/CaspidaFunctions

# remove directories we create for docker
function rm_temp_directories() {
  rm -rf ./bin ./lib ./conf ./content ./local ./system
}

# check for required files
for file in ${CASPIDA_LIBS_HOME}/${CASPIDA_SECURITY_JAR}
do
  if [[ ! -f ${file} ]]; then
    echo "missing ${file}: aborting"
    exit 2;
  fi
done

SrcDir=UBA-Base
BASEDIR=/opt/caspida/containerization/docker/${SrcDir}
WorkDir=${TMPDIR}/${SrcDir} # /var/vcap/sys/tmp/caspida/UBA-Base

rm -rf ${WorkDir}
cp -Rv ${BASEDIR} ${WorkDir}

# change to workdir to build the image: may not have space on /opt/caspida
cd ${WorkDir}

UBA_DEPS_IMAGE=ubuntu-splunkuba-deps
UBA_DEPS_IMAGE_VER=2023.07.17

# first check if we have the image that has ubuntu + our_dependencies
baseImage=$(${SUDOCMD} docker images ${UBA_DEPS_IMAGE}:${UBA_DEPS_IMAGE_VER} -q)
if [[ -z ${baseImage} ]]; then
  echo "$(date): could not to find ${UBA_DEPS_IMAGE}:${UBA_DEPS_IMAGE_VER}, attempting to build it"
  ${SUDOCMD} /usr/bin/docker build -t ${UBA_DEPS_IMAGE}:${UBA_DEPS_IMAGE_VER} \
     -f Dockerfile-uba-deps .
  status=$?

  if [[ ${status} -ne 0 ]]; then
    echo "$(date): attempt to build ${UBA_DEPS_IMAGE}:${UBA_DEPS_IMAGE_VER} failed, aborting"
    exit 2
  fi
else
  echo "$(date): using ${baseImage} for ${UBA_DEPS_IMAGE}:${UBA_DEPS_IMAGE_VER}"
fi

# get the userid & groupid of caspida user
caspida_userid=$(id -u ${CASPIDA_USER})
caspida_groupid=$(id -g ${CASPIDA_GROUP})

# check if the uid/gid for caspida is the same on all node: check all nodes not just the
# container workers
numnodes=`echo "$caspidaclusternodes" | awk -F "," '{ print NF }'`
if [[ ${numnodes} -gt 1 ]]; then
  for node in ${caspidaclusternodes//,/ }
  do
    echo "$(date): checking for ${CASPIDA_USER} uid/gid on node: ${node}"
    timeout -k 120s -s 9 120s ssh ${node} "(
        id=\$(id -u ${CASPIDA_USER}) ;
        gid=\$(id -g ${CASPIDA_USER}) ;
        if [[ \$id != ${caspida_userid} ]]; then
          echo "  node=${node}: user=${CASPIDA_USER} id=\${id} is different than the id=${caspida_userid} on master node";
          exit 2;
        fi

        if [[ \$gid != ${caspida_groupid} ]]; then
          echo "  node=${node}: group=${CASPIDA_GROUP} gid=\${gid} is different than the gid=${caspida_groupid} on master node";
          exit 2;
        fi

        exit 0;
      )"

    status=$?
    if [[ $status -ne 0 ]]; then
      echo "uid/gid comparison for ${CASPIDA_USER} failed on ${node}, aborting"
      exit 3
    fi
  done
fi

# Now build the uba image
echo "$(date): building ubabase image"
cp -r /opt/caspida/bin ./

mkdir -pv ./lib
cp ${CASPIDA_LIBS_HOME}/${CASPIDA_SECURITY_JAR} ./lib

cp -r /opt/caspida/conf ./
cp -r /opt/caspida/content ./
cp -r /etc/caspida/local ./

# if the directories dont have "+x" then in the Docker image these directories come up
# with "???" and no permissions for anybody
chmod -R 755 bin conf content local lib

# some system wide stuff
mkdir -pv system
# keep it as a symlink
cp -Pv /etc/localtime system

# following tries thrice to build ubaimage.
# if not forces stop all docker processes and restarts docker and gives one final try
count=0
MaxRetry=4
while [[ ${count} -lt ${MaxRetry} ]]; do
  if [[ ${count} -eq 3 ]]; then
    echo "$(date): $count attempts to build ubabase image failed, running docker_hardstop"
    docker_hardstop
    echo "$(date): starting docker"
    ${SUDOCMD} service docker start
  fi
  echo "$(date): attempt to build, retry=$count"
  ${SUDOCMD} /usr/bin/docker build -t ubabase \
    --build-arg UBA_DEPS_IMAGE=${UBA_DEPS_IMAGE} --build-arg UBA_DEPS_IMAGE_VER=${UBA_DEPS_IMAGE_VER} \
    --build-arg CASPIDA_USER=${CASPIDA_USER} --build-arg CASPIDA_USERID=${caspida_userid} \
    --build-arg CASPIDA_GROUP=${CASPIDA_GROUP} --build-arg CASPIDA_GROUPID=${caspida_groupid} \
    -f Dockerfile .
  status=$?
  if [[ ${status} -eq 0 ]]; then
    echo "$(date): attempt to build ubabase image successful"
    break
  fi
  ((count++))
done

rm -rf ${WorkDir}
exit ${status}
