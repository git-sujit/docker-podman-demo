#!/bin/bash

usage() {
  echo "usage: $0 <packages_dir>"
  echo "  Ex: $0 /home/caspida/Splunk-UBA-<version>-Packages-RHEL-<version>"
}

CASPIDA_DIR=/opt/caspida
CASPIDA_BIN_DIR=${CASPIDA_DIR}/bin

source ${CASPIDA_BIN_DIR}/uba_upgrade_common.sh

UBA_VER="5.3.0"

# override the variable PLATFORM
if [ -f /etc/os-release ]; then
  cat /etc/os-release | grep -q "Red Hat" && PLATFORM="Red Hat"
  cat /etc/os-release | grep -q "Oracle Linux" && PLATFORM="OEL"
  cat /etc/os-release | grep -q "CentOS" && PLATFORM="CentOS"
  cat /etc/os-release | grep -q "Ubuntu" && PLATFORM="Ubuntu"
else
  [ -f /etc/redhat-release ] && cat /etc/redhat-release | grep -q "Red Hat" && PLATFORM="Red Hat"
  [ -f /etc/oracle-release ] && cat /etc/oracle-release | grep -q "Oracle Linux" && PLATFORM="OEL"
  [ -f /etc/centos-release ] && cat /etc/centos-release | grep -q "CentOS" && PLATFORM="CentOS"
  [ -f /etc/lsb-release ] && cat /etc/lsb-release | grep -q "Ubuntu" && PLATFORM="Ubuntu"
fi

is_valid_uba_version() {
  echo "$(date): Checking Splunk UBA version"
  if [ -f "/opt/caspida/conf/version.properties" ]; then
    ubaver=$(grep release-number /opt/caspida/conf/version.properties | cut -d "=" -f 2)
  fi
  if [[ -z ${ubaver} ]]; then
    echo "$(date): Unable to find Splunk UBA version, aborting"
    exit 1
  fi
  echo "$(date): Found Splunk UBA version: "$ubaver
  if [ "$(printf '%s\n' "$UBA_VER" "$ubaver" | sort -V | head -n1)" = "$UBA_VER" ]; then
    return 1
  else
    return 0
  fi
}

validate_uba_os_versions() {
  is_valid_uba_version
  if [ $? -eq 1 ]; then
    is_valid_os_version
  fi
}

validate_uba_os_versions

INSTALLPATH="$1"
if [[ -z "${INSTALLPATH}" ]]; then
  echo "missing dir: needs the directory containing the packages as an argument"
  usage
  exit 2
fi

if [[ ! -d ${INSTALLPATH} ]]; then
  echo "specified directory not found: ${INSTALLPATH}"
  exit 3
fi

CASPIDAHOME=/home/caspida
VCAPSTOREDIR=/var/vcap/store
VCAPSYSLOGDIR=/var/vcap/sys/log
UBAUPGRADEDIR=/opt/caspida/upgrade
VARLOGDIR=/var/log
LOG=$VCAPSYSLOGDIR/caspida/install.log
ETCCASPIDADIR=/etc/caspida
CASPIDACONFDIR=/opt/caspida/conf
OPTCASPIDAINITD=/opt/caspida/etc/init.d
SPARKVER=spark-3.2.1-bin-hadoop3.2
KAFKAVER=kafka_2.12-3.4.0
EXTRACONFDIR=$INSTALLPATH/extra_conf
EXTRAPACKAGESDIR=$INSTALLPATH/extra_packages
SPARKTGZ=$EXTRAPACKAGESDIR/tar/${SPARKVER}.tgz
KAFKATGZ=$EXTRAPACKAGESDIR/tar/${KAFKAVER}.tgz
RELOAD4JDIR=$EXTRAPACKAGESDIR/tar/reload4j
SUDO=sudo
INSTALL_SCRIPT_PATH=/opt/caspida/bin/installer/redhat

source ${INSTALL_SCRIPT_PATH}/create_impala_shell.sh

_runcommand() {
  for command in "${@}"
  do
    eval ${command}
    if [ $? -ne 0 ]; then
      echo "Error in running ${command}, verify and re-run the INSTALL again"
      exit 1
    fi
  done
}

_makelink() {

  unset dstLink
  if [[ -h $3 ]]; then
    dstLink="true"
  fi

  command="${@}"
  eval ${command}

  for sourceLink in $2
  do
    s=`basename ${sourceLink}`
    if [[ "${dstLink}" = "true" ]]; then
      linkStr=$3/${s}
    elif [[ ! -h $3  &&  -d $3 ]]; then
      s=`basename ${sourceLink}`
      linkStr=$3/${s}
    else
      linkStr=$3
    fi

    echo "checking if link exists for ${linkStr}"
    readlink ${linkStr}
    if [ $? -ne 0 ]; then
      echo "Problem creating symlink source=${sourceLink} destination=${3}"
      exit 2
    fi
    echo "link exists ${sourceLink} ${linkStr}"
  done
}

echo "$(date): Starting $0 $@"

echo "#----------------------------"
echo "# $(date): Check caspida home"
echo "#----------------------------"
echo ~caspida | awk '{ print $1 }'| grep "/home/caspida"
if [ $? -ne 0 ]; then
    echo "Set /home/caspida as home directory for caspida user and try again."
    exit 3
fi

echo "#--------------------------"
echo "# $(date): Create Directory"
echo "#--------------------------"

id | grep root > /dev/null 2>&1
if [ $? -eq 0 ]; then
  SUDO=
fi

umask 0022

[ -e ~caspida/.bash_profile ] || ( touch ~caspida/.bash_profile && 
 chown caspida:caspida ~caspida/.bash_profile )

[ -e ~caspida/.bash_profile ] || ( touch ~caspida/.bashrc && 
 chown caspida:caspida ~caspida/.bash_profile )

( grep -q 'umask' ~caspida/.bash_profile &&
  sed -i -e 's/umask.*/umask 0022/' ~caspida/.bash_profile ) || 
  sed -i -e '$ a\umask 0022' ~caspida/.bash_profile

( grep -q 'umask' ~caspida/.bashrc &&
  sed -i -e 's/umask.*/umask 0022/' ~caspida/.bashrc ) || 
  sed -i -e '$ a\umask 0022' ~caspida/.bashrc

echo "***************************"
echo " $(date): VCAP DATA STORAGE"
echo "***************************"

$SUDO mkdir -p $VCAPSTOREDIR
for subdir in caspida hadoop hadoop-hdfs hadoop-mapreduce hadoop-yarn kafka postgresql redis timeseries 
do
    i=0
    unset cmdArr
    cmdArr[((i++))]="$SUDO mkdir -p $VCAPSTOREDIR/$subdir"
    cmdArr[((i++))]="$SUDO chmod 755 $VCAPSTOREDIR/$subdir"
    _runcommand "${cmdArr[@]}"
done 

$SUDO ls -alt $VCAPSTOREDIR/*

echo "*******************************"
echo " $(date): VCAP SYSLOG DIRECTORY"
echo "*******************************"

i=0
unset cmdArr
cmdArr[((i++))]="$SUDO mkdir -p $VCAPSYSLOGDIR"
cmdArr[((i++))]="$SUDO chmod 755 $VCAPSYSLOGDIR"
cmdArr[((i++))]="$SUDO rm -vf /etc/docker/daemon.json"
cmdArr[((i++))]="$SUDO rm -rvf /var/log/caspida"
cmdArr[((i++))]="$SUDO mkdir -p $VCAPSYSLOGDIR/caspida"
cmdArr[((i++))]="$SUDO chmod 755 $VCAPSYSLOGDIR/caspida"
cmdArr[((i++))]="$SUDO chown caspida:caspida $VCAPSYSLOGDIR/caspida"
_runcommand "${cmdArr[@]}"

currentdate=`date "+%Y-%m-%d-%H_%M_%S"`
exec > >(tee -a $LOG) 2>&1

# set the umask & print it
# print the current umask
echo "$(date): Running $0 $@"
echo "$(date): current umask=$(umask), id=$(id)"


echo "$(date): Starting $0 $@"
sleep 5
check_runc=$(sudo rpm -qa | grep runc)
if [[ $? -eq 0 ]]; then
	$SUDO yum -y  remove runc
fi
check_podman=$(sudo rpm -qa | grep podman)
if [[ $? -eq 0 ]]; then
	$SUDO yum -y remove podman
fi

# install base dependency packages
$SUDO rpm -Uvh --nodeps --force $INSTALLPATH/base_deps_list/rhel/*.rpm
if [ $? -ne 0 ]; then
    echo "Unable to install base packages. Correct the errors and try again..."
    exit 4
fi
echo "END"
sleep 5

# install python 3.8 packages
tar xfz $EXTRAPACKAGESDIR/tar/python3-pkgs.tgz -C $EXTRAPACKAGESDIR/tar
$SUDO rpm -ivh $EXTRAPACKAGESDIR/tar/python3-pkgs/*.rpm --force
if [ $? -ne 0 ]; then
    echo "Unable to install python3 packages. Correct the errors and try again..."
    exit 5
fi

i=0
unset cmdArr
cmdArr[((i++))]="rpm -q python3-six"
cmdArr[((i++))]="rpm -q python3-dateutil"
cmdArr[((i++))]="rpm -q python3-pysocks"
cmdArr[((i++))]="rpm -q python3-urllib3"
cmdArr[((i++))]="rpm -q python3-requests"
cmdArr[((i++))]="rpm -q python3-pytz"
cmdArr[((i++))]="rpm -q python3-chardet"
cmdArr[((i++))]="rpm -q python3-idna"
cmdArr[((i++))]="rpm -q python3-influxdb"
_runcommand "${cmdArr[@]}"

# Set python path to python3.8
$SUDO alternatives --set python /usr/bin/python3.8
$SUDO alternatives --set python3 /usr/bin/python3.8

for subdir in zookeeper hive hive-hcatalog impala hadoop-hdfs hadoop-mapreduce hadoop-yarn kafka postgresql redis influxdb
do
    i=0
    unset cmdArr
    cmdArr[((i++))]="$SUDO rm -rvf /var/log/$subdir"
    cmdArr[((i++))]="$SUDO mkdir -p $VCAPSYSLOGDIR/$subdir"
    cmdArr[((i++))]="$SUDO chmod 755 $VCAPSYSLOGDIR/$subdir"
    _runcommand "${cmdArr[@]}"
done

i=0
unset cmdArr
cmdArr[((i++))]="$SUDO mkdir -m 755 -p /var/vcap/packages"
cmdArr[((i++))]="$SUDO chown caspida:caspida /var/vcap/packages"
cmdArr[((i++))]="$SUDO rm -vf $ETCCASPIDADIR/conf"
cmdArr[((i++))]="$SUDO mkdir -p $ETCCASPIDADIR"
_runcommand "${cmdArr[@]}"

_makelink "$SUDO ln -sfv" "$VCAPSYSLOGDIR/*" "$VARLOGDIR"
_makelink "$SUDO ln -sfv" "$CASPIDACONFDIR" "$ETCCASPIDADIR"
_makelink "$SUDO ln -sfv" "$OPTCASPIDAINITD/*" "/etc/init.d"


echo "#-------------------------------"
echo "# $(date): Install base packages"
echo "#-------------------------------"

line="******************\n"
echo $PWD

for dir in $INSTALLPATH/base_packages $INSTALLPATH/base_packages/openssl $EXTRAPACKAGESDIR/rpm/*
do
  if [[ ${dir} =~ kubernetes || ${dir} =~ docker ]]; then
    echo "${dir} will be installed during install_containerization.sh below"
    continue
  fi

  STRING=`ls $dir/*.rpm`
  if [[ ${dir} =~ "ruby" ]]; then
    PKGS=${STRING}
  else
    echo
    echo $(date): Checking the list of initial base packages before install : $STRING
    echo
    already_installed_newer=`$SUDO rpm -Uvh --test $STRING 2>&1 | grep "already installed" | grep "which is newer"`
    echo 
    PKGS=""
    for rpmname in $STRING
    do
      # get the rpm from string that has the following pattern /xyz/abc/i.rpm
      i=`echo $rpmname | awk -F "/" '{ print $NF }' | awk -F ".rpm" '{ print $1 }'`

      # Exception for java-cup
      echo $i | grep java_cup > /dev/null 2>&1
      if [ $? -eq 0 ]; then
        i="java_cup"
      fi

      echo $already_installed_newer | grep $i  > /dev/null 2>&1
      if [ $? -eq 0 ]; then
        echo $rpmname is already installed and newer
      else
        PKGS="${PKGS} ${rpmname}"
      fi
    done
  fi

  if [[ ${dir} =~ "ruby" ]]; then
    $SUDO rpm -F $PKGS
  elif [ ! -z "$PKGS" ]; then
    echo $(date): Installing $PKGS with --replacepkgs and --replacefiles
    $SUDO rpm -Uvh --replacepkgs --replacefiles $PKGS
  fi

  if [ $? -ne 0 ]; then
    echo "$(date): Failed to install base packages, correct the errors and try again. Exiting[2]..."
    exit 6
  fi
done

# Passed -M flag to restrict the useradd command from creating a home directory for impala user
$SUDO useradd -M impala
$SUDO usermod -a -G hive impala
$SUDO usermod -a -G hdfs impala
### Create impala log directory
$SUDO mkdir -p /var/log/impala
$SUDO chown impala:impala /var/log/impala

# creating impala-shell command
create_impala_shell

echo "#------------------------"
echo "#$(date): Zookeeper 3.8.1"
echo "#------------------------"

cd $INSTALLPATH/extra_packages/tar
  $SUDO tar xzf apache-zookeeper-3.8.1-bin.tar.gz -C /usr/lib
cd -

i=0
unset cmdArr
cmdArr[((i++))]="$SUDO rm -rvf /usr/lib/zookeeper" # remove the zookeeper directory if exist
cmdArr[((i++))]="$SUDO mv /usr/lib/apache-zookeeper-3.8.1-bin /usr/lib/zookeeper" # rename the extrected directory
cmdArr[((i++))]="$SUDO rm -rvf /usr/lib/zookeeper/lib/jline-0.9.94.jar /usr/lib/zookeeper/lib/netty-3.10.6.Final.jar" # remove 3.4.14 libs
cmdArr[((i++))]="$SUDO rm -rvf /usr/lib/zookeeper/lib/logback-classic-1.2.10.jar /usr/lib/zookeeper/lib/logback-classic-1.2.10.LICENSE.txt" # remove conflicted binding
cmdArr[((i++))]="$SUDO rm -rvf /usr/lib/zookeeper/zookeeper.jar" # remove old symlink
cmdArr[((i++))]="$SUDO rm -rvf /usr/lib/zookeeper/contrib" # remove 3.4.14 contrib
cmdArr[((i++))]="$SUDO rm -rfv /usr/lib/zookeeper/conf"
_runcommand "${cmdArr[@]}"

_makelink "$SUDO ln -sfv" "/usr/lib/zookeeper/lib/zookeeper-3.8.1.jar" "/usr/lib/zookeeper/zookeeper.jar"
_makelink "$SUDO ln -sfv" "/etc/zookeeper/conf" "/usr/lib/zookeeper"

echo "#--------------------------"
echo "# $(date): patch hive 2.3.6 with guava 32.0.1"
echo "#--------------------------"
i=0
unset cmdArr
cmdArr[((i++))]="$SUDO rm -rvf /usr/lib/hive/lib/guava-14.0.1.jar" # remove older conflicting guava jar
cmdArr[((i++))]="$SUDO cp -v $EXTRAPACKAGESDIR/jar/guava-32.0.1-jre.jar /usr/lib/hive/lib/" # update to guava 32
_runcommand "${cmdArr[@]}"

echo "#--------------------------"
echo "# $(date): patch hadoop 3.2.4 with guava 32.0.1"
echo "#--------------------------"
i=0
unset cmdArr
# remove older guava jar
cmdArr[((i++))]="$SUDO rm -rvf /usr/lib/hadoop/lib/guava-27.0-jre.jar"
cmdArr[((i++))]="$SUDO rm -rvf /usr/lib/hadoop/client/guava-27.0-jre.jar"
cmdArr[((i++))]="$SUDO rm -rvf /usr/lib/hadoop/client/guava.jar"
cmdArr[((i++))]="$SUDO rm -rvf /usr/lib/hadoop-hdfs/lib/guava-27.0-jre.jar"
cmdArr[((i++))]="$SUDO cp -v $EXTRAPACKAGESDIR/jar/guava-32.0.1-jre.jar /usr/lib/hadoop/lib/"
cmdArr[((i++))]="$SUDO ln -sfv /usr/lib/hadoop/lib/guava-32.0.1-jre.jar /usr/lib/hadoop/client/guava-32.0.1-jre.jar"
cmdArr[((i++))]="$SUDO ln -sfv /usr/lib/hadoop/lib/guava-32.0.1-jre.jar /usr/lib/hadoop/client/guava.jar"
cmdArr[((i++))]="$SUDO cp -v $EXTRAPACKAGESDIR/jar/guava-32.0.1-jre.jar /usr/lib/hadoop-hdfs/lib/"
_runcommand "${cmdArr[@]}"

echo "#--------------------------"
echo "# $(date): patch hbase 2.2.6 with guava 32.0.1"
echo "#--------------------------"
i=0
unset cmdArr
cmdArr[((i++))]="$SUDO rm -rvf /usr/lib/hbase/lib/guava-27.0-jre.jar" # remove old guava jar
cmdArr[((i++))]="$SUDO cp -v $EXTRAPACKAGESDIR/jar/guava-32.0.1-jre.jar /usr/lib/hbase/lib/" # update to guava 32
_runcommand "${cmdArr[@]}"

echo "#-------------------------"
echo "#$(date): ruby gems"
echo "#-------------------------"
$SUDO gem install --force --local $EXTRAPACKAGESDIR/gem/*.gem
if [ $? -ne 0 ]; then
  echo "Failed to install Ruby gems. Exiting."
  exit 7
fi

echo "#-----------------------------"
echo "# $(date): Initialize postgres"
echo "#-----------------------------"
RHEL_BASE_DIR=/usr/pgsql
RHEL_DATA_DIR=/var/lib/pgsql
VERSION=15

i=0
unset cmdArr
cmdArr[((i++))]="$SUDO rm -rvf $RHEL_DATA_DIR"
cmdArr[((i++))]="$SUDO mkdir -p $RHEL_DATA_DIR/$VERSION"
cmdArr[((i++))]="$SUDO chown postgres:postgres $RHEL_DATA_DIR/$VERSION"
cmdArr[((i++))]="$SUDO chown postgres:postgres $VCAPSYSLOGDIR/postgresql"
cmdArr[((i++))]="$SUDO chmod 700 $RHEL_DATA_DIR/$VERSION"
_runcommand "${cmdArr[@]}"

$SUDO -u postgres ${RHEL_BASE_DIR}-${VERSION}/bin/initdb -D ${RHEL_DATA_DIR}/${VERSION}/data
if [ $? -ne 0 ]; then
  echo "Failed to initialize postgresql, correct the errors reported in the log and try again. Exiting..."
  exit 8
fi

echo "#-------------------------------"
echo "# $(date): Disable X11Forwarding"
echo "#-------------------------------"
$SUDO grep -q "X11Forwarding yes" /etc/ssh/sshd_config && sudo sed -i "s/X11Forwarding yes/X11Forwarding no/" /etc/ssh/sshd_config
if [ $? -ne 0 ]; then
  echo "$(date): X11 Forwarding already disabled"
else
  $SUDO service sshd reload
fi

echo "#--------------------------------------"
echo "# $(date): Install extra packages (tar)"
echo "#--------------------------------------"
tar xfz $EXTRAPACKAGESDIR/tar/pexpect-3.1.tar.gz -C $EXTRAPACKAGESDIR/tar
(cd $EXTRAPACKAGESDIR/tar/pexpect-3.1 && $SUDO python setup.py install)
if [ $? -ne 0 ]; then
  echo "$(date): Unable to install python-pexpect packages. Exiting..."
  exit 9
fi

tar xfz $EXTRAPACKAGESDIR/tar/python-evtx-0.5.1.tar.gz -C $EXTRAPACKAGESDIR/tar
( cd $EXTRAPACKAGESDIR/tar/python-evtx-0.5.1 && $SUDO python setup.py install)
if [ $? -ne 0 ]; then
  echo "$(date): Unable to install python-evtx packages. Exiting..."
  exit 10
fi

$SUDO tar xfz $EXTRAPACKAGESDIR/tar/node-v18.15.0-linux-x64.tar.gz -C /usr/local --strip-components 1
if [ $? -ne 0 ]; then
  echo "$(date): Unable to install nodejs packages. Exiting..."
  exit 11
fi

i=0
unset cmdArr
cmdArr[((i++))]="$SUDO mkdir -p /var/vcap/packages"
cmdArr[((i++))]="$SUDO rm -rvf /var/vcap/packages/spark"
cmdArr[((i++))]="$SUDO tar xfz $SPARKTGZ -C /var/vcap/packages"
cmdArr[((i++))]="$SUDO chown -R caspida:caspida /var/vcap/packages/spark*"
cmdArr[((i++))]="$SUDO chmod -R 755 /var/vcap/packages/$SPARKVER"
cmdArr[((i++))]="$SUDO rm -rvf /usr/share/kafka"
cmdArr[((i++))]="$SUDO tar xfz $KAFKATGZ -C /usr/share"
cmdArr[((i++))]="$SUDO rm -rvf /usr/share/kafka/site-docs/"
_runcommand "${cmdArr[@]}"

_makelink "$SUDO ln -sfv" "/var/vcap/packages/$SPARKVER" "/var/vcap/packages/spark"
_makelink "$SUDO ln -sfv" "/usr/share/$KAFKAVER" "/usr/share/kafka"

i=0
unset cmdArr
cmdArr[((i++))]="$SUDO chown -R caspida:caspida /usr/share/kafka"
_runcommand "${cmdArr[@]}"

_makelink "$SUDO ln -sfv" "/var/vcap/sys/log/kafka" "/usr/share/kafka/logs"

echo "#-------------------------"
echo "# $(date): Update Spark"
echo "#-------------------------"

i=0
unset cmdArr
cmdArr[((i++))]="$SUDO cp -v /opt/caspida/conf/spark/* /var/vcap/packages/spark/conf/"
cmdArr[((i++))]="$SUDO chown caspida:caspida /var/vcap/packages/spark/conf/*"

cmdArr[((i++))]="perl -pi -e  's/#SPARK_WORKER_OPTS/SPARK_WORKER_OPTS/g' /var/vcap/packages/spark/conf/spark-env.sh"
# edit spark config
cmdArr[((i++))]="perl -pi -e  's/SPARK_EXECUTOR_MEMORY=.*\$/SPARK_EXECUTOR_MEMORY=2G/g' /var/vcap/packages/spark/conf/spark-env.sh"
cmdArr[((i++))]="perl -pi -e  's/#SPARK_WORKER_OPTS/SPARK_WORKER_OPTS/g' /var/vcap/packages/spark/conf/spark-env.sh"
_runcommand "${cmdArr[@]}"

echo "#---------------------------------------------"
echo "# $(date): Installing docker-ce and kubernetes"
echo "#---------------------------------------------"
$UBAUPGRADEDIR/utils/install_containerization.sh $EXTRAPACKAGESDIR
if [[ $? -ne 0 ]]; then
  echo "Failed to install containerization, exiting..."
  exit 12
fi

echo "#---------------------------------------------------------------"
echo "# $(date): Set up Hadoop, Influxdb, Impala, Hive, Zookeeper conf"
echo "#---------------------------------------------------------------"
i=0
unset cmdArr
cmdArr[((i++))]="$SUDO cp -vr /etc/hadoop/conf.empty /etc/hadoop/conf.uba"
cmdArr[((i++))]="$SUDO alternatives --install /etc/hadoop/conf hadoop-conf /etc/hadoop/conf.uba 99"
cmdArr[((i++))]="$SUDO cp -vr $EXTRACONFDIR/hadoop/* /etc/hadoop/conf/."
cmdArr[((i++))]="$SUDO chown root:hadoop /etc/hadoop/conf/core-site.xml /etc/hadoop/conf/hdfs-site.xml"
cmdArr[((i++))]="$SUDO chmod 644 /etc/hadoop/conf/core-site.xml /etc/hadoop/conf/hdfs-site.xml"

cmdArr[((i++))]="$SUDO cp -v $EXTRACONFDIR/influxdb/* /etc/influxdb/."
cmdArr[((i++))]="$SUDO chmod 755 /etc/influxdb/influxdb.conf"

cmdArr[((i++))]="$SUDO mkdir -p /etc/impala/conf/"
cmdArr[((i++))]="$SUDO cp -vr $EXTRACONFDIR/impala/*.xml /etc/impala/conf/."
cmdArr[((i++))]="$SUDO chown root:root /etc/impala/conf/core-site.xml /etc/impala/conf/hdfs-site.xml /etc/impala/conf/hive-site.xml"
cmdArr[((i++))]="$SUDO chmod 644 /etc/impala/conf/core-site.xml /etc/impala/conf/hdfs-site.xml /etc/impala/conf/hive-site.xml"

cmdArr[((i++))]="$SUDO cp -v $EXTRACONFDIR/hive/core-site.xml $EXTRACONFDIR/hive/hdfs-site.xml $EXTRACONFDIR/hive/hive-site.xml /etc/hive/conf/"
cmdArr[((i++))]="$SUDO chown root:root /etc/hive/conf/hive-site.xml"
cmdArr[((i++))]="$SUDO chmod 644 /etc/hive/conf/hive-site.xml"

cmdArr[((i++))]="$SUDO cp -v $EXTRACONFDIR/zookeeper/zoo.cfg /etc/zookeeper/conf/"
cmdArr[((i++))]="$SUDO cp -v $EXTRACONFDIR/zookeeper/configuration.xsl $EXTRACONFDIR/zookeeper/log4j.properties /etc/zookeeper/conf/"
cmdArr[((i++))]="$SUDO chown root:root /etc/zookeeper/conf/zoo.cfg"
cmdArr[((i++))]="$SUDO chmod 644 /etc/zookeeper/conf/zoo.cfg"
cmdArr[((i++))]="$SUDO mkdir -p /var/lib/zookeeper"
cmdArr[((i++))]="$SUDO chown -R zookeeper:zookeeper /var/lib/zookeeper"
cmdArr[((i++))]="$SUDO chmod 755 /var/lib/zookeeper"
cmdArr[((i++))]="$SUDO chown -R root:root /usr/lib/zookeeper"
_runcommand "${cmdArr[@]}"

_makelink "$SUDO ln -sfv" "/etc/localtime" "/usr/share/zoneinfo"

$SUDO service zookeeper-server stop
$SUDO service zookeeper-server init --force
$SUDO service zookeeper-server start
sleep 1
$SUDO service zookeeper-server status
if [ $? -ne 0 ]; then
  echo "$(date): Failed to start zookeeper-server, correct the errors reported in the log and try again. Exiting..."
  exit 13
fi
$SUDO service zookeeper-server stop

echo "#---------------------------------"
echo "#$(date): Install and set up redis"
echo "#---------------------------------"

$SUDO yum --disablerepo=* localinstall ${EXTRAPACKAGESDIR}/rpm/redis/*.rpm --allowerasing -y
if [[ $? -ne 0 ]]; then
  echo "Failed to install redis, exiting..."
  exit 14
fi


echo "#---------------------------------------------"
echo "# $(date): Replace log4j and apply mitigations"
echo "#---------------------------------------------"

i=0
unset cmdArr

#Replace log4j 1.x jars with reload4j jar
cmdArr[((i++))]="$SUDO cp -v $RELOAD4JDIR/reload4j-1.2.21.jar /usr/lib/hadoop/lib"
cmdArr[((i++))]="$SUDO rm -vf /usr/lib/hadoop/lib/log4j-1.2.17.jar"
cmdArr[((i++))]="$SUDO rm -vf /usr/lib/hadoop/client/log4j-1.2.17.jar"
cmdArr[((i++))]="$SUDO rm -vf /usr/lib/hadoop/client/log4j.jar"

cmdArr[((i++))]="$SUDO cp -v $RELOAD4JDIR/reload4j-1.2.21.jar /usr/lib/hadoop-hdfs/lib/"
cmdArr[((i++))]="$SUDO rm -vf /usr/lib/hadoop-hdfs/lib/log4j-1.2.17.jar"

cmdArr[((i++))]="$SUDO cp -v $RELOAD4JDIR/reload4j-1.2.21.jar /usr/lib/zookeeper/lib/"
cmdArr[((i++))]="$SUDO rm -vf /usr/lib/zookeeper/lib/log4j-1.2.17.jar"
cmdArr[((i++))]="$SUDO rm -vf /usr/lib/zookeeper/lib/log4j-1.2.17.LICENSE.txt"

cmdArr[((i++))]="$SUDO cp -v $RELOAD4JDIR/reload4j-1.2.21.jar /usr/lib/hbase/lib/client-facing-thirdparty/"
cmdArr[((i++))]="$SUDO rm -vf /usr/lib/hbase/lib/client-facing-thirdparty/log4j-1.2.17.jar"

cmdArr[((i++))]="$SUDO cp -v $RELOAD4JDIR/reload4j-1.2.21.jar /var/vcap/packages/spark/jars/"
cmdArr[((i++))]="$SUDO rm -vf /var/vcap/packages/spark/jars/log4j-1.2.17.jar"

#Replace slf4j-log4j 1.x jars with slf4j-reload4j jars
cmdArr[((i++))]="$SUDO cp -v $RELOAD4JDIR/slf4j-reload4j-1.7.36.jar /usr/lib/hadoop/lib/"
cmdArr[((i++))]="$SUDO rm -vf /usr/lib/hadoop/lib/slf4j-log4j12-1.7.25.jar"

cmdArr[((i++))]="$SUDO cp -v $RELOAD4JDIR/slf4j-api-1.7.36.jar /usr/lib/hadoop/lib/"
cmdArr[((i++))]="$SUDO rm -vf /usr/lib/hadoop/lib/slf4j-api-1.7.25.jar"

cmdArr[((i++))]="$SUDO cp -v $RELOAD4JDIR/slf4j-reload4j-1.7.36.jar /usr/lib/hbase/lib/client-facing-thirdparty/"
cmdArr[((i++))]="$SUDO rm -vf /usr/lib/hbase/lib/client-facing-thirdparty/slf4j-log4j12-1.7.25.jar"

cmdArr[((i++))]="$SUDO cp -v $RELOAD4JDIR/slf4j-reload4j-1.7.36.jar /usr/lib/zookeeper/lib/"
cmdArr[((i++))]="$SUDO rm -vf /usr/lib/zookeeper/lib/slf4j-log4j12-1.7.25.jar"

cmdArr[((i++))]="$SUDO cp -v $RELOAD4JDIR/slf4j-reload4j-1.7.36.jar /var/vcap/packages/spark-3.2.1-bin-hadoop3.2/jars/"
cmdArr[((i++))]="$SUDO rm -vf /var/vcap/packages/spark-3.2.1-bin-hadoop3.2/jars/slf4j-log4j12-1.7.30.jar"

# UBA-16760: Remove the jars that comes with hadoop-3.2.4, as we provide updated jars from install packages
cmdArr[((i++))]="$SUDO rm -vf /usr/lib/hadoop/lib/slf4j-api-1.7.35.jar"
cmdArr[((i++))]="$SUDO rm -vf /usr/lib/hadoop/lib/slf4j-reload4j-1.7.35.jar"

#Apply log4j 2.x mitigation for hive 2.3.6
# Check if JndiLookup.class exists. If so, apply remediation.
jar tvf /usr/lib/hive/lib/log4j-core-*.jar | grep "org/apache/logging/log4j/core/lookup/JndiLookup.class"
if [ $? -eq 0 ]; then
  cmdArr[((i++))]="echo \"org/apache/logging/log4j/core/lookup/JndiLookup.class exists, removing...\""
  cmdArr[((i++))]="$SUDO zip -q -d /usr/lib/hive/lib/log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class;"
else
  cmdArr[((i++))]="echo \"org/apache/logging/log4j/core/lookup/JndiLookup.class has already been removed from /usr/lib/hive/lib/ jars.\""
fi
jar tvf /usr/lib/hive/jdbc/hive-jdbc* | grep "org/apache/logging/log4j/core/lookup/JndiLookup.class"
if [ $? -eq 0 ]; then
  cmdArr[((i++))]="echo \"org/apache/logging/log4j/core/lookup/JndiLookup.class exists, removing...\""
  cmdArr[((i++))]="$SUDO zip -q -d /usr/lib/hive/jdbc/hive-jdbc* org/apache/logging/log4j/core/lookup/JndiLookup.class"
else
  cmdArr[((i++))]="echo \"org/apache/logging/log4j/core/lookup/JndiLookup.class has already been removed from /usr/lib/hive/jdbc/ jars.\""
fi

_runcommand "${cmdArr[@]}"

#reset hadoop log4j symlinks
_makelink "$SUDO ln -sfv /usr/lib/hadoop/lib/reload4j-1.2.21.jar /usr/lib/hadoop/client/reload4j-1.2.21.jar"
_makelink "$SUDO ln -sfv /usr/lib/hadoop/lib/reload4j-1.2.21.jar /usr/lib/hadoop/client/reload4j.jar"

i=0
unset cmdArr
cmdArr[((i++))]="$SUDO rm -rvf /var/vcap/store/redis /var/vcap/store/pgsql /var/lib/redis"
cmdArr[((i++))]="$SUDO mv /var/lib/pgsql /var/vcap/store/"
cmdArr[((i++))]="$SUDO chown postgres:postgres /var/vcap/store/pgsql"
cmdArr[((i++))]="$SUDO mkdir -p /var/vcap/store/redis"
cmdArr[((i++))]="$SUDO chown redis:redis /var/vcap/store/redis"
cmdArr[((i++))]="$SUDO usermod -a -G redis caspida"
cmdArr[((i++))]="$SUDO rm -rvf /var/lib/kafka"
cmdArr[((i++))]="$SUDO rm -rvf /var/lib/hadoop-yarn"
cmdArr[((i++))]="$SUDO rm -rvf /var/lib/hadoop-hdfs"
cmdArr[((i++))]="$SUDO rm -rvf /var/lib/hadoop-mapreduce"
cmdArr[((i++))]="$SUDO rm -rvf /usr/lib/hive/lib/postgresql-jdbc4.jar"
_runcommand "${cmdArr[@]}"

_makelink "$SUDO ln -sfv" "/usr/share/java/postgresql-jdbc.jar" "/usr/lib/hive/lib/postgresql-jdbc4.jar"
_makelink "$SUDO ln -sfv" "/var/vcap/store/pgsql" "/var/lib/pgsql"
_makelink "$SUDO ln -sfv" "/var/vcap/store/redis" "/var/lib/redis"
_makelink "$SUDO ln -sfv" "/var/vcap/store/kafka" "/var/lib/kafka"
_makelink "$SUDO ln -sfv" "/var/vcap/store/hadoop-yarn" "/var/lib/hadoop-yarn"
_makelink "$SUDO ln -sfv" "/var/vcap/store/hadoop-hdfs" "/var/lib/hadoop-hdfs"
_makelink "$SUDO ln -sfv" "/var/vcap/store/hadoop-mapreduce" "/var/lib/hadoop-mapreduce"

$SUDO chkconfig --list | \
      egrep 'hadoop|hive|impala|postgres|redis|zookeeper|influxdb' | \
      awk '{ print $1 }' > /tmp/serv.txt

for i in `cat /tmp/serv.txt`
do
  echo $i
  $SUDO chkconfig $i --levels 2345 off
done
$SUDO rm /tmp/serv.txt

echo "#----------------------------------------------"
echo "# $(date): Replacing protobuf-java jar in spark"
echo "#----------------------------------------------"

i=0
unset cmdArr

#Replace protobuf-java 2.5.0 jars with protobuf-java 3.21.12 jar
cmdArr[((i++))]="$SUDO cp -v $EXTRAPACKAGESDIR/jar/protobuf-java-3.21.12.jar /var/vcap/packages/spark/jars/"
cmdArr[((i++))]="$SUDO rm -vf /var/vcap/packages/spark/jars/protobuf-java-2.5.0.jar"
_runcommand "${cmdArr[@]}"

i=0
unset cmdArr
cmdArr[((i++))]="$SUDO chmod -R 755 /opt/caspida"
cmdArr[((i++))]="$SUDO chown -R caspida:caspida /opt/caspida"
_runcommand "${cmdArr[@]}"

i=0
unset cmdArr
echo "$(date): Running CreateCaspidaSecurityJar.py"
cmdArr[((i++))]="python /opt/caspida/bin/CreateCaspidaSecurityJar.py"
cmdArr[((i++))]="$SUDO chown caspida:caspida /opt/caspida/lib/CaspidaSecurity.jar"
cmdArr[((i++))]="$SUDO mkdir -p /etc/caspida/local/conf"
cmdArr[((i++))]="$SUDO chmod -R 755 /etc/caspida"
cmdArr[((i++))]="$SUDO chown -R caspida:caspida /etc/caspida/local"
cmdArr[((i++))]="$SUDO mkdir -p /var/vcap/sys/run"
cmdArr[((i++))]="$SUDO chmod 755 /var/vcap/sys/run"
cmdArr[((i++))]="cp -v /opt/caspida/conf/deployment/templates/local_conf/uba-site.properties /etc/caspida/local/conf/"
_runcommand "${cmdArr[@]}"

echo "$(date): $0 completed...."
