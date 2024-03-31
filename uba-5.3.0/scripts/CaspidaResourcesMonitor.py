#!/usr/bin/python3

#
# Copyright 2017-2019 Splunk, Inc.
#


import json
import sys
import shlex
import os
import types
import platform
import signal
import time
import re
from typing import List

import pexpect
import subprocess
from subprocess import Popen
from subprocess import PIPE
import socket
import requests
import traceback

from optparse import OptionParser
from optparse import Option

# Thread
import threading
import queue
import CaspidaResourcesLib
from CaspidaResourcesLib import *
from CaspidaResourcesProfiles import checkProfiles, mergeStatus, printJsonProfiles, updateGroupRepeatFailureCount, \
    fixGroupRepeatFailureCount, setGroupRunning

curr_path = os.getcwd()
scriptpath, scriptname = os.path.split(sys.argv[0])
(SCNAME, junk) = scriptname.split('.')

PLATFORM = os.environ["PLATFORM"]
is_containerized = readProp("system.usecontainers")
db_standby_enabled = readProp("persistence.datastore.rdbms.standby.enabled")
splunk_forwarder_enabled = readProp("splunk.forwarder.enabled")
if not splunk_forwarder_enabled:
    splunk_forwarder_enabled = false
REDIS_PORT = 6379
INFLUX_PORT = 8086

# Hardisk watermark to notify that HD is nearly full
DISK_USAGE_THRESHOLD = int(readProp("system.disk.usage.high.watermark"))
# Disk usage watermark to start jobs stopped with reason: "NoResources"
DISK_USAGE_NORMAL_THRESHOLD = int(readProp("system.disk.usage.low.watermark"))

BACKUP_DISK_DIR = readProp("backup.filesystem.directory.restore")
BACKUP_DISK_USAGE_HIGH_WATERMARK = int(readProp("backup.filesystem.usage.high.watermark"))
BACKUP_DISK_USAGE_LOW_WATERMARK = int(readProp("backup.filesystem.usage.low.watermark"))

USESUDO = getSudo()
USERNAME = getUser()
UIHTTPSPORT = getUIHttpsPort()

# unset HISTFILE so we don't munge the ~caspida/.bash_history file with our commands
os.environ["HISTFILE"] = ""

# since we only connect to localhost/cluster-nodes, make sure we dont try to go through a proxy
os.environ["http_proxy"] = ""
os.environ["https_proxy"] = ""


class MultiOptions(Option):
    ACTIONS = Option.ACTIONS + ("extend",)
    STORE_ACTIONS = Option.STORE_ACTIONS + ("extend",)
    TYPED_ACTIONS = Option.TYPED_ACTIONS + ("extend",)
    ALWAYS_TYPED_ACTIONS = Option.ALWAYS_TYPED_ACTIONS + ("extend",)

    def take_action(self, action, dest, opt, value, values, parser):
        if action == "extend":
            listvalue = value
            values.ensure_value(dest, []).append(listvalue)
        else:
            Option.take_action(self, action, dest, opt, value, values, parser)


def main(ptr_tbl, c_path, s_name):
    """ Routine used to process options from command line """
    instruction = "usage: %prog [options] arg"
    progversion = "%prog 1.0"
    list = scriptname.split('.')
    intro = "The %prog utility is used to generate datasource json file ( %prog -w 1  -l [ log directory ]  -x [debug]"
    optparser = OptionParser(option_class=MultiOptions, usage=instruction, version=progversion, description=intro)
    default_name = c_path + '/' + list[0] + ".log"
    default_json = c_path + '/' + list[0] + ".json"
    fixoption = NOFIX + "|" + FIXALL + "|" + FIXCONF

    optparser.add_option("-C", "--configuration", action="store_true", default=False, dest="config",
                         help="Turn on configuration check  default=off")
    optparser.add_option("-M", "--minute ", default=MINUTE, dest="minute", help="MINUTE by default=" + str(MINUTE))
    optparser.add_option("-O", "--oldform ", action="store_true", default=False, dest="oldform",
                         help="Old format by default=False")
    optparser.add_option("-a", "--action", default=NOFIX, dest="action",
                         help="options[" + fixoption + "]  issue(s), default=" + NOFIX)
    optparser.add_option("-c", "--connect", action="store_true", default=False, dest="redis",
                         help="turn on Redis connection to port " + str(REDIS_PORT) + ", by default=Off ")
    optparser.add_option("-L", "--resourceslog", default="/var/log/caspida/monitor/resourcesMonitor.out",
                         dest="resourcesMonout",
                         help="resourcesMon.out : default /var/lib/caspida/monitor/resourcesMon.out")
    optparser.add_option("-e", "--emailtest", action="store_true", default=False, dest="email",
                         help="Test single Email by default=Off ")
    optparser.add_option("-f", "--filename", action="extend", dest="filename",
                         help=" location of caspida.properties, by default=" + SITE_PROP + " & " + DEFAULT_PROP)
    optparser.add_option("-l", "--log", dest="logdir", help=" log directory path ( Default:" + c_path + ")")
    optparser.add_option("-n", "--notoverwrite", action="store_false", default=True, dest="overwrite",
                         help=" use to not overwrite the result file default=Overwrite ")
    optparser.add_option("-j", "--json", default=JSONENTRY, dest="jsonentry",
                         help=" number or entry per Good/Bad status json file  default=" + str(JSONENTRY))
    optparser.add_option("-r", "--result", default=None, dest="resultfile",
                         help="resultfile filename(default:" + default_name + ")")
    optparser.add_option("-s", "--syslog", default=NOSYSLOG, dest="syslog",
                         help="prefix name of syslog (e.g caspida ) , default=" + NOSYSLOG)
    optparser.add_option("-t", "--thread", default=NUM_OF_THREADS, dest="threadnum",
                         help="Number of threads used for launching the status query  default=" + str(NUM_OF_THREADS))
    optparser.add_option("-u", "--user", default=USERNAME, dest="username", help=" username  default=" + USERNAME)
    optparser.add_option("-w", "--waitime", default=0, dest="period",
                         help="time period to check the Caspida Process  in minutes : default= (0:no time period)")
    optparser.add_option("-x", "--debug", default=0, dest="debug", help="debug level : default=0 ")

    (options, args) = optparser.parse_args()
    if len(sys.argv) < 1:
        mesg = len(sys.argv)
        print("incorrect number of arguments %d" % mesg)
        optparser.error(mesg)
        optparser.print_help()
    ptr_tbl["minute"] = int(options.minute)
    if options.minute > 0:
        minute = changeMinute(ptr_tbl, int(options.minute))
        print(" Minute cycle is set to ", ptr_tbl["minute"])

    # Log Directory
    if options.logdir is None:
        options.logdir = c_path + '/'
    # Result file
    if options.resultfile is None:
        list = s_name.split('.')
        options.resultfile = options.logdir + '/' + list[0] + ".log"
    else:
        options.resultfile = options.logdir + '/' + options.resultfile

    if int(options.threadnum) < 1:
        msg = "Error: Thread number should not be less than 1 "
        print(msg)
        os._exit(1)

    # Check for auto and nofix

    if re.match(fixoption, options.action) is None:
        msg = " Incorrect Action type selected   " + options.action + "-- available selection is : " + fixoption
        print(msg)
        optparser.error(msg)
        optparser.print_help()
    ptr_tbl["debug"] = int(options.debug)

    if options.filename is None:
        ptr_tbl["filename"].append(DEFAULT_PROP)
        ptr_tbl["filename"].append(SITE_PROP)
    else:
        LEN = len(options.filename)
        for index in range(0, LEN):
            ptr_tbl["filename"].append(options.filename[index])
    ptr_tbl["action"] = options.action
    ptr_tbl["logdir"] = options.logdir
    ptr_tbl["syslog"] = options.syslog
    ptr_tbl["resultfile"] = options.resultfile
    ptr_tbl["period"] = options.period
    if "false" in USESUDO:
        ptr_tbl["username"] = "root"
    else:
        ptr_tbl["username"] = options.username
    ptr_tbl["resourcesMonout"] = options.resourcesMonout
    ptr_tbl["overwrite"] = options.overwrite
    ptr_tbl["threadnum"] = int(options.threadnum)
    ptr_tbl["jsonentry"] = int(options.jsonentry)
    ptr_tbl["redis"] = options.redis
    ptr_tbl["oldform"] = options.oldform
    ptr_tbl["configcheck"] = options.config
    ptr_tbl["email"] = options.email
    return options


ZOOKEEPER_HOST = getFirstServiceHost("zookeeper")
KAFKA_HOST = getFirstServiceHost("kafka")
JOBMANAGER_HOST = readProp("jobmanager.restServerUrl")
UI_HOST = getFirstServiceHost("uiServer")
SPARK_MASTER_HOST = getFirstServiceHost("spark-master")
if UIHTTPSPORT:
    UI_HOST = UI_HOST + ":" + UIHTTPSPORT
print("UI_HOST is " + UI_HOST)


def manageLicenses():
    rc = PASS
    fname = sys._getframe().f_code.co_name
    headers = {'Authorization': "Bearer " + JMRestToken}

    try:
        # Check if License is valid
        license_get = requests.get(JOBMANAGER_HOST + "/licenses/get", headers=headers, verify=False)
        if len(license_get.content) != 0 and license_get.status_code != 404:
            try:
                license_get_json = license_get.json()
                # Get the datasources
                datasources_get = requests.get(JOBMANAGER_HOST + "/datasources/", headers=headers, verify=False)
                datasources_get_json = datasources_get.json()
                if license_get_json['status'] != "Valid":
                    print("CaspidaResourcesMonitor: License Not Valid")
                    for ds_info in datasources_get_json:
                        if ds_info['type'] != "System" and ds_info['status'] == "Processing":
                            print("Setting Suspended Status for Datasource %s " % (ds_info['name']))
                            requests.put(
                                JOBMANAGER_HOST + "/datasources/setStatus?id=" + ds_info['id'] + "&status=Suspended",
                                headers=headers, verify=False)
                else:
                    print("CaspidaResourcesMonitor: License Valid")
                    for ds_info in datasources_get_json:
                        if ds_info['type'] != "System" and ds_info['status'] == "Suspended":
                            print("Setting Processing Status for Datasource %s " % (ds_info['name']))
                            requests.put(
                                JOBMANAGER_HOST + "/datasources/setStatus?id=" + ds_info['id'] + "&status=Processing",
                                headers=headers, verify=False)
            except ValueError:
                print(fname, ": Non JSON response")
                rc = FAIL
        else:
            print(fname, ": No response or 404 response")
            rc = FAIL
    except:
        print(fname, ": Connection refused")
        rc = FAIL
    return rc


def platformCheck(ptr_tbl, svc_name, dst_ip, user):
    rc = PASS
    fname = sys._getframe().f_code.co_name
    msg = fname + "=" + svc_name
    if ptr_tbl["debug"] > 1:
        print(msg)
    rc = getServiceStatus(ptr_tbl, svc_name, dst_ip, user)
    return rc


def platform_start(ptr_tbl, dst_ip, user):
    rc = PASS
    fname = sys._getframe().f_code.co_name
    print(fname)
    return rc


def platform_stop(ptr_tbl, dst_ip, user):
    rc = PASS
    fname = sys._getframe().f_code.co_name
    print(fname)
    return rc


def genericCheck(ptr_tbl, svc_name, dst_ip, user):
    rc = PASS
    fname = sys._getframe().f_code.co_name
    msg = fname + "=" + svc_name
    if ptr_tbl["debug"] > 1:
        print(msg)
    try:
        if not ptr_tbl["caspida_info"][dst_ip]["services"][svc_name]["initial"]:
            print("serviceName=", svc_name, " is not initialized  for ", dst_ip)
            return rc
    except:
        return rc
    rc = getServiceStatus(ptr_tbl, svc_name, dst_ip, user)
    return rc


def genericStart(ptr_tbl, svc_name, dst_ip, user):
    rc = PASS
    fname = sys._getframe().f_code.co_name
    msg = fname + "=" + svc_name
    if ptr_tbl["debug"] > 1:
        print(msg)
    return rc


def genericStop(ptr_tbl, svc_name, dst_ip, user):
    rc = PASS
    fname = sys._getframe().f_code.co_name
    msg = fname + "=" + svc_name
    if ptr_tbl["debug"] > 1:
        print(msg)
    return rc


# -----------------------------------------------------------
# Section where routines were used for specific function
# -------------------------------------------------------------

def sparkMasterCheck(ptr_tbl, srv_name, dst_ip, data):
    rc = PASS
    fname = sys._getframe().f_code.co_name
    llist = data.split("\n")
    log = ""
    found = False
    LEN = len(llist)
    info = {}
    master_count = 0
    LOG = ""
    for line in llist:
        line = line.replace("\S", "")
        line = line.replace("\r", "")
        line = removeExcessSpace(line)
        pattern = "master\.Master"
        if re.search(pattern, line):
            master_count += 1
    if master_count < 1:
        rc = FAIL
        LOG += " Error : master.Master=" + str(master_count)
    if rc == FAIL:
        msg = fname + ":" + LOG + "\n"
        print(fname + LOG)
        printLog(ptr_tbl, msg)
    return rc, log


def sparkWorkerCheck(ptr_tbl, srv_name, dst_ip, data):
    rc = PASS
    fname = sys._getframe().f_code.co_name
    llist = data.split("\n")
    log = ""
    found = False
    LEN = len(llist)
    info = {}
    worker_count = 0
    LOG = ""
    for line in llist:
        line = line.replace("\S", "")
        line = line.replace("\r", "")
        line = removeExcessSpace(line)
        pattern = "worker\.Worker"
        if re.search(pattern, line):
            worker_count += 1
    if worker_count < 1:
        rc = FAIL
        LOG += " Error : worker.Worker=" + str(worker_count)
    if rc == FAIL:
        msg = fname + ":" + LOG + "\n"
        print(fname + LOG)
        printLog(ptr_tbl, msg)
    return rc, log


def sparkHistoryCheck(ptr_tbl, srv_name, dst_ip, data):
    rc = PASS
    fname = sys._getframe().f_code.co_name
    llist = data.split("\n")
    log = ""
    found = False
    LEN = len(llist)
    info = {}
    history_count = 0
    LOG = ""
    for line in llist:
        line = line.replace("\S", "")
        line = line.replace("\r", "")
        line = removeExcessSpace(line)
        pattern = "history\.History"
        if re.search(pattern, line):
            history_count += 1
    if history_count < 1:
        rc = FAIL
        LOG += " Error : history.History=" + str(history_count)
    if rc == FAIL:
        msg = fname + ":" + LOG + "\n"
        print(fname + LOG)
        printLog(ptr_tbl, msg)
    return rc, log


def sparkJobCheck(ptr_tbl, srv_name, dst_ip, data):
    """
    Used to check if the following master.MASTER , worker.WORKER and curl localhost:8080/api/v1/applications
    """
    rc = PASS
    fname = sys._getframe().f_code.co_name
    llist = data.split("\n")
    log = ""
    found = False
    LEN = len(llist)
    info = {}
    LOG = ""
    for line in llist:
        line = line.replace("\S", "")
        line = line.replace("\r", "")
        line = removeExcessSpace(line)
        pattern = "Connection refused"
        if re.search(pattern, line):
            rc = FAIL
            LOG = line
            print(fname + LOG)
            printLog(ptr_tbl, LOG)
    if LEN == 0:
        rc = FAIL
        LOG = "nodata:" + data
        print(fname + LOG)
        printLog(ptr_tbl, LOG)
    return rc, log


class DiskUtilizationArgs:
    """
    Disk utilization method arguments
    """
    def __init__(self, func_name: str, ptr_tbl: any, srv_name: str, disk_type: str, cmd_output: str, dst_ip: str,
                 low_threshold: int, high_threshold: int, additional_warning: str, stop_ds: bool, invert_status: any,
                 prop: str):
        """
        :param func_name:  Name of the function
        :param ptr_tbl: service info object
        :param srv_name: service name
        :param disk_type: Disk Type e.g. 'system' or 'backup' for display purpose
        :param cmd_output: output of the command
        :param dst_ip: Node IP address
        :param low_threshold: Lowest watermark value for warning
        :param high_threshold: highest watermark value for critical case
        :param additional_warning: Additional warning message to append.
        :param stop_ds: True/False, if you want to stop the data sources
        :param invert_status: bitwise invert for STATUS_CRITICAL or STATUS_WARNING
        :param prop: Cluster view property name
        """
        self.func_name = func_name
        self.ptr_tbl = ptr_tbl
        self.srv_name = srv_name
        self.disk_type = disk_type
        self.cmd_output = cmd_output
        self.dst_ip = dst_ip
        self.low_threshold = low_threshold
        self.high_threshold = high_threshold
        self.additional_warning = additional_warning
        self.stop_ds = stop_ds
        self.auth_token = f"Authorization: Bearer {JMRestToken}"
        self.invert_status = invert_status
        self.prop = prop


def get_disk_details(cmd_output: str):
    """
    Matches the df -kh commands pattern to extract the disks and its details
    :param cmd_output: Output of the command
    :return: List of disks and its necessary details like usage in GB and percentage, name, total usage, mounted dir
    """
    disks = []
    pattern = r'^(/dev/[a-zA-Z0-9]+)\s+(\d+(?:\.\d+)?[KMGTP]?)\s+(\d+(?:\.\d+)?[KMGTP]?)\s+(\d+(?:\.\d+)?[KMGTP]?)\s+(\d+)%\s+(/[a-zA-Z0-9]+)$'
    lines = cmd_output.strip().split('\n')

    for line in lines:
        if "Filesystem" in line or "%" not in line:
            continue
        match = re.match(pattern, line)
        if match:
            disk_name = match.group(1)
            disk_total = match.group(2)
            disk_usage = match.group(3)
            disk_usage_percent = int(match.group(5).replace("%", ""))
            mounted_on = match.group(6)
            disks.append({
                "disk_name": disk_name,
                "disk_total": f"{disk_total}B",
                "disk_usage": f"{disk_usage}B",
                "disk_usage_percent": disk_usage_percent,
                "mounted_on": mounted_on
            })
    return disks


def check_disk_utilization(args: DiskUtilizationArgs):
    rc_status = PASS
    log = ""
    error_log = ""

    ptr_tbl = args.ptr_tbl
    srv_name = args.srv_name
    disk_type = args.disk_type
    func_name = args.func_name
    cmd_output = args.cmd_output
    dst_ip = args.dst_ip
    low_threshold = args.low_threshold
    high_threshold = args.high_threshold
    additional_warning = args.additional_warning
    stop_ds = args.stop_ds
    auth_token = args.auth_token
    invert_status = args.invert_status

    service_object = ptr_tbl["caspida_info"][dst_ip]["services"][srv_name]
    service_object["status"] &= ~invert_status

    for disk in get_disk_details(cmd_output):
        disk_name = disk["disk_name"]
        disk_total = disk["disk_total"]
        disk_usage = disk["disk_usage"]
        disk_usage_percent = disk["disk_usage_percent"]
        mounted_on = disk["mounted_on"]

        log_timestamp = time.strftime('%Y-%m-%dT%H:%M:%S%Z')
        ptr_alert = service_object["alert"]
        if disk_usage_percent > low_threshold:
            # identify if the usage is crossing over high watermark based on which certain messages/status may differ.
            is_critical = disk_usage_percent > high_threshold

            if stop_ds and is_critical:
                stop_ds_cmd = (f'curl -kH "{auth_token}" -G --data-urlencode '
                               f'"message=Stopped by ResourcesMon: out of disk space in {dst_ip}" '
                               f'{JOBMANAGER_HOST}/datasources/stopAll?stoppedFor=NoResources')

                (rc, msg, err) = run_command(stop_ds_cmd, Shell=False)
                printLog(ptr_tbl, msg)

            threshold_ref = high_threshold if is_critical else low_threshold
            print((
                f"{log_timestamp} {'CRITICAL' if is_critical else 'WARNING'} DISK USAGE: {disk_usage_percent}% "
                f"higher than threshold: {threshold_ref}% "
                f"at {dst_ip} mounted on {mounted_on}{additional_warning}"
            ))
            # setting status based on criticality and watermark reference.
            service_object["status"] = STATUS_CRITICAL if is_critical else STATUS_WARNING
            rc_status = FAIL
            if ptr_alert["severity"] == 0:
                # scheduling alert to be sent
                disk_ref = f"{disk_name}[Mounted on dir: {mounted_on}]"
                alert_category = ALERT_CRITICAL if is_critical else ALERT_WARNING
                subject = (
                    f"{ALERT_SEVERITY[alert_category]}: Utilization of disk({disk_ref}) on"
                    f"Splunk UBA host({dst_ip}) is above {threshold_ref}%"
                )
                initEmailProcess(ptr_tbl, dst_ip, srv_name, ALERT_CRITICAL, subject)
                print(f"{func_name}: subject={subject}")
            error_log += (
                f'"Low disk space on {disk_type} disk {disk_name}: '
                f'{disk_usage} of {disk_total} used ({disk_usage_percent}% used)"'
            )
        else:
            if disk_name in ptr_alert["subject"] and disk_usage_percent < low_threshold:
                if stop_ds:
                    (rc, msg, cmd_err) = run_command("/opt/caspida/bin/CaspidaJobUtils.py -S NoResources")
                    printLog(ptr_tbl, msg)
                print(f"{func_name} Disk utilization back to normal.")
                resetEmailProcess(ptr_tbl, dst_ip, srv_name)
        log += f"{disk_name}:{disk_usage}({disk_usage_percent}%) "
    service_object["system"][args.prop] = str(log)
    return rc_status, error_log


def backup_disk_usage(ptr_tbl, srv_name, dst_ip, cmd_output):
    """
    Monitors the backup disk usage provided the output from df -kh <disk_name> command
    :param ptr_tbl: Service info object
    :param srv_name: Service name
    :param dst_ip: Node IP Address
    :param cmd_output: Output of the related command
    :return: Status and error logs as tuple
    """
    return check_disk_utilization(DiskUtilizationArgs(
        func_name=sys._getframe().f_code.co_name,
        invert_status=STATUS_WARNING,
        ptr_tbl=ptr_tbl,
        srv_name=srv_name,
        dst_ip=dst_ip,
        cmd_output=cmd_output,
        disk_type="backup",
        prop="backupDiskUtilization",
        low_threshold=BACKUP_DISK_USAGE_LOW_WATERMARK,
        high_threshold=BACKUP_DISK_USAGE_HIGH_WATERMARK,
        stop_ds=False,
        additional_warning=""
    ))


def sys_disk_usage(ptr_tbl, srv_name, dst_ip, cmd_output):
    """
    Monitors the system disk usage provided the output from df -kh <disk_name> command
    :param ptr_tbl: Service info object
    :param srv_name: Service name
    :param dst_ip: Node IP Address
    :param cmd_output: Output of the related command
    :return: Status and error logs as tuple
    """
    return check_disk_utilization(DiskUtilizationArgs(
        func_name=sys._getframe().f_code.co_name,
        invert_status=STATUS_CRITICAL,
        ptr_tbl=ptr_tbl,
        srv_name=srv_name,
        dst_ip=dst_ip,
        cmd_output=cmd_output,
        disk_type="system",
        prop="diskUtilization",
        low_threshold=DISK_USAGE_NORMAL_THRESHOLD,
        high_threshold=DISK_USAGE_THRESHOLD,
        stop_ds=True,
        additional_warning=", All Jobs are STOPPED."
    ))


def sysCpuNum(ptr_tbl, srv_name, dst_ip, data):
    rc = FAIL
    llist = data.split("\n")
    fname = sys._getframe().f_code.co_name
    log = ""
    found = False
    for line in llist:
        line = line.replace("\r", "")
        if re.match("^\d+", line):
            found = True
            rc = PASS
            ptr_tbl["caspida_info"][dst_ip]["services"][srv_name]["system"]["numberOfCpu"] = int(line)
            break
    if not found:
        line = 0
    ptr_tbl["caspida_info"][dst_ip]["services"][srv_name]["system"]["numberOfCpu"] = int(line)
    log = "CPU #=" + str(line)
    return rc, log


def sysCpuUsage(ptr_tbl, srv_name, dst_ip, data):
    rc = PASS
    fname = sys._getframe().f_code.co_name
    log = ""
    errorlog = ""
    cpu_usage = 200
    ptr_tbl["caspida_info"][dst_ip]["services"][srv_name]["status"] &= ~STATUS_WARNING
    ptr_alert = ptr_tbl["caspida_info"][dst_ip]["services"][srv_name]["alert"]
    output = removeExcessSpace(data.strip()).split(" ")
    if output:
        try:
            cpu_usage = float(output[0])
        except ValueError:
            cpuusage = "missing mpstat"
            rc = FAIL
    log += str(cpu_usage) + "%"
    if rc == PASS:
        ptr_tbl["caspida_info"][dst_ip]["services"][srv_name]["system"]["cpuUtilization"] = float(cpu_usage)
    else:
        ptr_tbl["caspida_info"][dst_ip]["services"][srv_name]["system"]["cpuUtilization"] = float(0.00)
    if cpu_usage > CPU_USAGE_WATERMARK:
        print(fname, " WARNING CPU USAGE = ", cpu_usage)
        ptr_tbl["caspida_info"][dst_ip]["services"][srv_name]["status"] &= STATUS_WARNING
        rc = FAIL
        if ptr_alert["severity"] == 0:
            subject = ALERT_SEVERITY[
                          ALERT_WARNING] + ": CPU utilization of Splunk UBA host(" + dst_ip + ") is above " + str(
                CPU_USAGE_WATERMARK) + "%"
            print(fname, ":subject=", subject)

    errorlog += str(cpu_usage) + "% "
    print(fname, errorlog)
    if rc == FAIL:
        errorlog = "  \"High CPU usage : " + errorlog + "\""
        print(fname, "rc FAIL")

    ptr_tbl["caspida_info"][dst_ip]["services"][srv_name]["system"]["cpuUtilization"] = str(log)
    return rc, errorlog


def sysDmidecode(ptr_tbl, srv_name, dst_ip, data):
    rc = PASS
    fname = sys._getframe().f_code.co_name
    llist = data.split("\n")
    log = ""
    found = False
    LEN = len(llist)
    ptr_system = ptr_tbl["caspida_info"][dst_ip]["services"][srv_name]["system"]
    for line in llist:
        line = line.replace("\S", "")
        line = line.replace("\r", "")
        line = removeExcessSpace(line)
        pattern = 'Manufacturer:'
        if re.search(pattern, line):
            found = True
            llist = line.split(":")
            if "manufacturer" in ptr_system:
                ptr_system["manufacturer"] = llist[1]
            else:
                print("Warning:" + fname + " Manufacturer key is not found ")
            if log == "":
                log = line
            else:
                log += " " + line
        pattern = 'Product Name:'
        if re.search(pattern, line):
            found = True
            llist = line.split(":")
            if "productName" in ptr_system:
                ptr_system["productName"] = llist[1]
            else:
                print("Warning:" + fname + " productName key is not found ")
            if log == "":
                log = line
            else:
                log += " " + line
        pattern = 'Version:'
        if re.search(pattern, line):
            found = True
            llist = line.split(":")
            if "version" in ptr_system:
                ptr_system["version"] = llist[1]
            else:
                print("Warning:" + fname + " version key is not found ")
            if log == "":
                log = line
            else:
                log += " " + line
        pattern = 'Serial Number:'
        if re.search(pattern, line):
            found = True
            llist = line.split(":")
            if "serialNumber" in ptr_system:
                ptr_system["serialNumber"] = llist[1]
            else:
                print("Warning:" + fname + " serialNumber key is not found ")
            if log == "":
                log = line
            else:
                log += " " + line
    if not found:
        log = "none"
    return rc, log


def load_average(ptr_tbl, srv_name, dst_ip, data):
    fname = sys._getframe().f_code.co_name
    load_avg_info = data.strip().split("\n")
    if not load_avg_info:
        ptr_system["loadAverage"] = "Unknown"
        print("Warning: " + fname + " could not get load average")
        return FAIL, "load average not found"
    load_avg = load_avg_info[0].strip()
    log = ""
    rc = PASS
    ptr_system = ptr_tbl["caspida_info"][dst_ip]["services"][srv_name]["system"]
    if load_avg:
        ptr_system["loadAverage"] = load_avg
        log = load_avg
    else:
        msg = "Warning: " + fname + " could not get load average"
        print(msg)
        log = "load average not found"
        ptr_system["loadAverage"] = "Unknown"
        rc = FAIL
    return rc, log


def sysOs(ptr_tbl, srv_name, dst_ip, data):
    rc = PASS
    fname = sys._getframe().f_code.co_name
    llist = data.split("\n")
    log = ""
    osname = ""
    found = False
    LEN = len(llist)
    try:
        if LEN > 1:
            for line in llist:
                if "DESCRIPTION" in line:
                    osname = line.split("=")[1].strip().replace("\"", "")
                elif "release" in line:
                    osname = line.strip()
        else:
            osname = llist[0].strip()
    except IndexError:
        osname = "unknown"
        print(fname + ":Error in string" + str(llist))
    ptr_system = ptr_tbl["caspida_info"][dst_ip]["services"][srv_name]["system"]
    if "os" in ptr_system:
        ptr_system["os"] = osname
        log = osname
    else:
        msg = "Warning:" + fname + " os key is not found "
        print(msg)
        log = "NoOs"
        ptr_system["os"] = "Unknown"
    return rc, log


def sysMem(ptr_tbl, srv_name, dst_ip, data):
    rc = PASS
    fname = sys._getframe().f_code.co_name
    llist = data.split("\n")
    log = ""
    found = False
    LEN = len(llist)
    ptr_system = ptr_tbl["caspida_info"][dst_ip]["services"][srv_name]["system"]
    for line in llist:
        line = line.replace("\S", "")
        line = line.replace("\r", "")
        line = removeExcessSpace(line)
        line = line.replace(" ", "")
        pattern = 'MemTotal'
        if re.match(pattern, line):
            found = True
            llist = line.split(":")
            temp = llist[1].replace("kB", "")
            temp = int(temp) * 1024
            ptr_system["memoryTotal"] = temp
            if log == "":
                log = line
            else:
                log += " " + line
        pattern = 'MemFree'
        if re.match(pattern, line):
            found = True
            llist = line.split(":")
            temp = llist[1].replace("kB", "")
            temp = int(temp) * 1024
            ptr_system["memoryFree"] = temp
            if log == "":
                log = line
            else:
                log += " " + line
        pattern = 'Shmem'
        if re.match(pattern, line):
            found = True
            llist = line.split(":")
            temp = llist[1].replace("kB", "")
            temp = int(temp) * 1024
            ptr_system["sharedMemory"] = temp
            if log == "":
                log = line
            else:
                log += " " + line
        pattern = 'MemAvailable'
        if re.match(pattern, line):
            found = True
            llist = line.split(":")
            temp = llist[1].replace("kB", "")
            temp = int(temp) * 1024
            ptr_system["memoryAvailable"] = temp
            if log == "":
                log = line
            else:
                log += " " + line
    if not found:
        log = "none"
    return rc, log


def sys_disk_space(ptr_tbl, srv_name, dst_ip, cmd_output):
    """
    Monitors the system vcap disk usages to show on cluster node view
    :param ptr_tbl: Service info object
    :param srv_name: Service name
    :param dst_ip: Node IP Address
    :param cmd_output: Output of the related command
    :return: Status and error logs as tuple
    """
    result = PASS
    log = ""
    found = False
    ptr_system = ptr_tbl["caspida_info"][dst_ip]["services"][srv_name]["system"]
    for disk in get_disk_details(cmd_output):
        mounted_dir = disk["mounted_on"]
        disk_usage = disk["disk_usage"]
        log += f"{mounted_dir}:{disk_usage} "
        found = True
    if not found:
        log = "none"
    ptr_system["usedVcapSpace"] = str(log)
    return result, log


def getServiceIpAddr(ptr_tbl, svc_name):
    for ipaddr in ptr_tbl["caspida_info"]:
        if svc_name in ptr_tbl["caspida_info"][ipaddr]["services"]:
            return ipaddr
    return None


def deleteServiceKey(ptr_tbl, svc_name, old_ip, ip_list):
    if len(ip_list) != 0:
        if old_ip not in ip_list:
            if old_ip in ptr_tbl["caspida_info"]:
                if svc_name in ptr_tbl["caspida_info"][old_ip]["services"]:
                    info = ptr_tbl["caspida_info"][old_ip]["services"][svc_name]
                    del ptr_tbl["caspida_info"][old_ip]["services"][svc_name]
    return None


def impalaDB(ptr_tbl, svc_name, dst_ip, data):
    fname = sys._getframe().f_code.co_name
    rc = PASS
    log = fname + ":"
    llog = ""
    rc = PASS
    msg = ""
    ptr_info = ptr_tbl["caspida_info"][dst_ip]["services"][svc_name]
    llist = data.split("\n")
    found_error = False
    msg = fname + ":Analytic DB is initialized"
    for line in llist:
        line = line.replace("\S", "")
        line = line.replace("\r", "")
        line = removeExcessSpace(line)
        pattern = "error"
        if re.search(pattern, line.lower()) is None:
            continue
        found_error = True
        rc = FAIL
        msg = line
    if found_error:
        print(fname + ":" + msg)
        printLog(ptr_tbl, fname + ":" + msg)
        msg = ""
    else:
        print(fname + ":" + msg)
    return rc, msg


def checkPortPidExist(ptr_tbl, svc_name, ip):
    fname = sys._getframe().f_code.co_name
    rc = PASS
    log = fname + ":"
    llog = ""
    rc = PASS
    found = False
    msg = ""
    ptr_info = ptr_tbl["caspida_info"][ip]["services"][svc_name]
    for pidentry in ptr_info["pid"]:
        if (ptr_info["pid"][pidentry]["status"] & STATUS_FOUND) != STATUS_FOUND:
            rc = FAIL
            msg += fname + ":service[" + svc_name + "]-- PID[" + str(pidentry) + "] is NOT found "
            print(msg)
        else:
            found = True
    if not found:
        rc = FAIL
        msg += fname + ":service[" + svc_name + "]-- NO PID is found "
        print(msg)
    return rc


def getPidPortStatus(ptr_tbl, svc_name, ip, data):
    fname = sys._getframe().f_code.co_name
    rc = PASS
    llist = data.split("\n")
    LEN = len(llist)
    log = fname + ":"
    llog = ""
    ptr_info = ptr_tbl["caspida_info"][ip]["services"][svc_name]
    for pidentry in ptr_info["pid"]:
        # Set pid status to NOT FOUND
        ptr_info["pid"][pidentry]["status"] &= ~STATUS_FOUND
    msg = ""
    found = False
    for line in llist:
        line = blankUnprintChar(line)
        line = line.replace("\S", "")
        line = line.replace("\r", "")
        tmp = fname + ":svName[" + svc_name + "]--LINE=" + line
        for port in ptr_tbl["sysservices"][svc_name]["port"]:
            if re.search(str(port), line):
                tmp = fname + ":1 svcName[" + svc_name + "]. port=" + str(port) + " line[" + line + "]"
                for pidentry in ptr_info["pid"]:
                    if re.search(str(pidentry), line):
                        found = True
                        tmp = fname + ":2 svcName[" + svc_name + "]. port=" + str(port) + "-- PID[" + str(
                            pidentry) + "] is found  -- line[" + line + "]"
                        ptr_info["pid"][pidentry]["status"] |= STATUS_FOUND
                        msg += "port[" + str(port) + "contain PID[" + str(pidentry) + "]"
                        if ptr_tbl["debug"]:
                            print(msg)
    msg2 = ""
    for pidentry in ptr_info["pid"]:
        if (ptr_info["pid"][pidentry]["status"] & STATUS_FOUND) != STATUS_FOUND:
            if not found:
                rc = FAIL
                tmp = fname + ":service[" + svc_name + "] --port[" + str(port) + "-- PID[" + str(
                    pidentry) + "] is NOT found "
                print(tmp)
                msg2 += "port[" + str(port) + "does not contain PID[" + str(pidentry) + "]"
            else:
                tmp = "==>Warning" + fname + ":service[" + svc_name + "] --port[" + str(port) + "-- PID[" + str(
                    pidentry) + "] is NOT found, it could be old PID "
                print(tmp)
    if rc == FAIL:
        print(msg2)
        msg = " "
    return rc, msg


def forceDisplay(ptr_tbl, svc_name):
    fname = sys._getframe().f_code.co_name
    for ip in ptr_tbl["caspida_info"]:
        ptr_tbl["caspida_info"][ip]["services"][svc_name]["status"] |= STATUS_PRINT
        ptr_info = ptr_tbl["caspida_info"][ip]["services"][svc_name]["system"]
        line = ""
        for key in ptr_info:
            line += key + "[" + ptr_info[key] + "]"
        ptr_tbl["caspida_info"][ip]["services"][svc_name]["error"] += line
        ptr_tbl["caspida_info"][ip]["services"][svc_name]["log"] += line
    return PASS


specialServices = {
    "System": {"backup": backup_disk_usage, "dev": sys_disk_space, "mem": sysMem, "nproc": sysCpuNum,
               "var": sys_disk_usage, "mpstat": sysCpuUsage, "release": sysOs, "dmidecode": sysDmidecode,
               "uptime": load_average},
    "tsdb": {},
    "spark-master": {"grep spark": sparkMasterCheck, "curl": sparkJobCheck},
    "spark-worker": {"grep spark": sparkWorkerCheck},
    "spark-history": {"grep spark": sparkHistoryCheck},
    "impala-server": {"impala-shell": impalaDB}
}

authToken = "Authorization: Bearer "
if len(JMRestToken) > 0:
    authToken += JMRestToken

# Note remove "mpstat" from system svstat
systemServices = {"System": {"group": "System", "svc": None, "pcmd": None, "pname": None,
                             "svcstat": ['nproc', 'cat /proc/meminfo | grep --color=never -i mem', 'df -kh /var/vcap',
                                         'df -kh | grep "^/dev/" | grep --color=never vcap',
                                         "mpstat | tail -1 | awk -F 'all' '{ print $2 }'", "cat /etc/lsb-release",
                                         "sudo dmidecode --type  system", "uptime | awk -F 'average: ' '{print $2}'",
                                         f'df -kh | grep --color=never "{BACKUP_DISK_DIR}" || true'],
                             "svcstop": [], "svcstart": []},
                  "zookeeper": {"group": "Zookeeper", "port": [2181], "svc": "zookeeper-server", "pcmd": None,
                                "pname": "zoo.cfg",
                                "svcstat": ['/opt/caspida/bin/utils/zookeeper_status_check.sh ' + ZOOKEEPER_HOST ],
                                "svcstop": [], "svcstart": []},

                  "hadoop-namenode": {"group": "Hadoop", "port": [9870], "svc": "hadoop-hdfs-namenode", "pcmd": None,
                                      "pname": 'hadoop-hdfs-namenode', "svcstat": [], "svcstop": [], "svcstart": []},
                  HD_DNODE: {"group": "Hadoop", "port": [9864], "svc": "hadoop-hdfs-datanode", "pcmd": None,
                             "pname": 'hadoop-hdfs-datanode', "svcstat": [], "svcstop": [], "svcstart": []},
                  "hadoop-snamenode": {"group": "Hadoop", "port": [], "svc": "hadoop-hdfs-secondarynamenode",
                                       "pcmd": None, "pname": 'hadoop-hdfs-secondarynamenode', "svcstat": [],
                                       "svcstop": [], "svcstart": []},
                  "tsdb": {"group": "Time Series DB", "port": [8086], "svc": "influxdb", "pcmd": None,
                           "pname": 'influxdb', "svcstat": [], "svcstop": [], "svcstart": []},

                  "redis-server": {"group": "Redis", "port": [6379], "svc": "redis-server", "pcmd": None,
                                   "pname": 'redis', "svcstat": [], "svcstop": [], "svcstart": []},
                  "redis-irserver": {"group": "Redis", "port": [6380], "svc": "redis-ir-server", "pcmd": None,
                                     "pname": 'redis', "svcstat": [], "svcstop": [], "svcstart": []},
                  "psql": {"group": "PostgreSQL", "port": [5432], "svc": "postgresql", "pcmd": None, "pname": '$PSQL',
                           "svcstat": [], "svcstop": [], "svcstart": []},
                  "psql-standby": {"group": "PostgreSQL Standby", "port": [5432], "svc": "postgresql", "pcmd": None,
                                   "pname": '$PSQL', "svcstat": [], "svcstop": [], "svcstart": []},
                  "kafka": {"group": "Kafka", "port": [9092], "svc": "kafka-server", "pcmd": None, "pname": 'kafka',
                            "svcstat": [
                                '/usr/share/kafka/bin/kafka-topics.sh --list --bootstrap-server ' + KAFKA_HOST + ':9092'],
                            "svcstop": [], "svcstart": []},
                  "jobmanager-restServer": {"group": "Job Manager", "port": [9002], "svc": "caspida-jobmanager",
                                            "pcmd": None, "pname": 'jobmanager', "svcstat": [
                          'curl -m 30' + ' -kH \"' + authToken + '\" ' + JOBMANAGER_HOST + '/remote/agents'],
                                            "svcstop": [], "svcstart": []},
                  "jobmanager-agents": {"group": "Job Agent", "port": [9002], "svc": "caspida-jobagent", "pcmd": None,
                                        "pname": 'jobmanager.CaspidaJobAgent', "svcstat": [], "svcstop": [],
                                        "svcstart": []},
                  "uiServer": {"group": "UBA UI", "port": [443], "svc": "caspida-ui", "pcmd": None, "pname": 'zplex',
                               "svcstat": ['curl -1 -k https://' + UI_HOST + ' > /dev/null 2>&1'], "svcstop": [],
                               "svcstart": []},
                  "spark-master": {"group": "Spark", "port": [], "svc": "spark-master", "pcmd": None,
                                   "pname": 'spark.deploy.master', "svcstat": ["ps aux | grep spark ",
                                                                               "curl " + SPARK_MASTER_HOST + ":8080/api/v1/applications"],
                                   "svcstop": [], "svcstart": []},
                  "spark-worker": {"group": "Spark", "port": [], "svc": "spark-worker", "pcmd": None,
                                   "pname": 'spark.deploy.worker', "svcstat": ["ps aux | grep spark "], "svcstop": [],
                                   "svcstart": []},
                  "spark-history": {"group": "Spark", "port": [], "svc": "spark-history", "pcmd": None,
                                    "pname": 'spark.deploy.history', "svcstat": ["ps aux | grep spark ",
                                                                                 "curl " + SPARK_MASTER_HOST + ":8080/api/v1/applications"],
                                    "svcstop": [], "svcstart": []},
                  "hive": {"group": "Hive Metastore", "port": [], "svc": "hive-metastore", "pcmd": None, "pname": None,
                           "svcstat": [], "svcstop": [], "svcstart": []},
                  "impala-statestore": {"group": "Impala", "port": [], "svc": "impala-state-store", "pcmd": None,
                                        "pname": None, "svcstat": [], "svcstop": [], "svcstart": []},
                  "impala-catalog": {"group": "Impala", "port": [], "svc": "impala-catalog", "pcmd": None,
                                     "pname": None, "svcstat": [], "svcstop": [], "svcstart": []},
                  "impala-server": {"group": "Impala", "port": [], "svc": "impala-server", "pcmd": None, "pname": None,
                                    "svcstat": ["impala-shell -d caspida -q \"show tables\""], "svcstop": [],
                                    "svcstart": []},
                  "analytics": {"group": "Analytics", "port": [], "svc": "caspida-analytics", "pcmd": None,
                                "pname": None, "svcstat": [], "svcstop": [], "svcstart": []},
                  "rule-offline-exec": {"group": "Offline Rule Executor", "port": [], "svc": "caspida-offlineruleexec",
                                        "pcmd": None, "pname": "offline.OfflineRuleExecutor", "svcstat": [],
                                        "svcstop": [], "svcstart": []},
                  "rule-realtime-exec": {"group": "Realtime Rule Executor", "port": [],
                                         "svc": "caspida-realtimeruleexec", "pcmd": None,
                                         "pname": "realtime.RealtimeRuleExecutor", "svcstat": [], "svcstop": [],
                                         "svcstart": []},
                  "output-connector": {"group": "Output Connector Server", "port": [], "svc": "caspida-outputconnector",
                                       "pcmd": None, "pname": "server.OutputConnectorServer", "svcstat": [],
                                       "svcstop": [], "svcstart": []},
                  "sysmonitor": {"group": "System Monitor", "port": [], "svc": "caspida-sysmon", "pcmd": None,
                                 "pname": "server.SystemMonitorServer", "svcstat": [], "svcstop": [], "svcstart": []},
                  "docker": {"group": "Docker", "port": [], "svc": "docker", "pcmd": None, "pname": 'dockerd',
                             "svcstat": [], "svcstop": [], "svcstart": []},
                  "kubelet": {"group": "Kubelet", "port": [], "svc": "kubelet", "pcmd": None, "pname": 'kubelet.conf',
                              "svcstat": [], "svcstop": [], "svcstart": []},
                  "spark-server": {"group": "Spark", "port": [], "svc": "spark-server", "pcmd": None,
                                   "pname": 'UbaSparkServer', "svcstat": [], "svcstop": [], "svcstart": []},
                  "splunk": {"group": "Splunk", "port": [], "svc": "splunkd", "pcmd": None, "pname": 'splunkd',
                             "svcstat": [], "svcstop": [], "svcstart": []}
                  }

stServices = {"System": {"propnames": ["all"], "status": 0, "desc": "system", "role": "system", "depend": [],
                         "fcheck": platformCheck, "fstart": platform_start, "fstop": platform_stop},
              "zookeeper": {"propnames": ["system.zkhosts"], "status": 0, "desc": "zookeeper-server", "role": "zk",
                            "depend": ["System"], "fcheck": genericCheck, "fstart": genericStart, "fstop": genericStop},
              "kafka": {"propnames": ["system.messaging.kafka.brokerlist"], "status": 0, "desc": "kafka-server",
                        "depend": ["System", "zookeeper"], "fcheck": genericCheck, "fstart": genericStart,
                        "fstop": genericStop},
              "hadoop-namenode": {"propnames": ["persistence.eventstore.location"], "status": 0,
                                  "desc": "hadoop-hdfs-namenode", "role": "hd-nnode", "depend": ["System", "zookeeper"],
                                  "fcheck": genericCheck, "fstart": genericStart, "fstop": genericStop},
              HD_DNODE: {"propnames": "hadoop.datanode.host", "status": 0, "desc": "hadoop-hdfs-datanode",
                         "role": HD_DNODE, "depend": ["System", "zookeeper"], "fcheck": genericCheck,
                         "fstart": genericStart, "fstop": genericStop},
              "hadoop-snamenode": {"propnames": None, "status": 0, "desc": "hadoop-hdfs-secondarynamenode",
                                   "role": "hd-snnode", "depend": ["System", "zookeeper"], "fcheck": genericCheck,
                                   "fstart": genericStart, "fstop": genericStop},
              "tsdb": {"propnames": ["persistence.datastore.tsdb.uri"], "status": 0, "desc": "influxdb", "role": "tsdb",
                       "depend": ["System"], "fcheck": genericCheck, "fstart": genericStart, "fstop": genericStop},
              "redis-server": {"propnames": ["persistence.redis.server"], "status": 0, "desc": "redis-server",
                               "role": "redis", "depend": ["System"], "fcheck": genericCheck, "fstart": genericStart,
                               "fstop": genericStop},
              "redis-irserver": {"propnames": ["identity.redis.server"], "status": 0, "desc": "redis-ir-server",
                                 "role": "redis-ir", "depend": ["System"], "fcheck": genericCheck,
                                 "fstart": genericStart, "fstop": genericStop},
              "psql": {"propnames": ["database.host"], "status": 0, "desc": "postgres", "role": "psql",
                       "depend": ["System"], "fcheck": genericCheck, "fstart": genericStart, "fstop": genericStop},
              "psql-standby": {"propnames": ["database.standby"], "status": 0, "desc": "postgres",
                               "role": "psql-standby", "depend": ["System"], "fcheck": genericCheck,
                               "fstart": genericStart, "fstop": genericStop},
              "jobmanager-restServer": {"propnames": None, "status": 0, "desc": "caspida-jobmanager",
                                        "role": "jobmanager",
                                        "depend": ["System", "zookeeper", "hadoop-namenode", HD_DNODE, "redis-server",
                                                   "redis-irserver", "psql"], "fcheck": genericCheck,
                                        "fstart": genericStart, "fstop": genericStop},
              "jobmanager-agents": {"propnames": None, "status": 0, "desc": "caspida-jobagent",
                                    "role": "jobmanager-agent", "depend": [], "fcheck": genericCheck,
                                    "fstart": genericStart, "fstop": genericStop},
              "uiServer": {"propnames": None, "status": 0, "desc": "caspida-ui", "role": "uiServer",
                           "depend": ["System", "zookeeper", "hadoop-namenode", HD_DNODE, "redis-server",
                                      "redis-irserver", "psql", "jobmanager.restServer"], "fcheck": genericCheck,
                           "fstart": genericStart, "fstop": genericStop},
              "spark-master": {"propnames": None, "status": 0, "desc": "spark-master", "role": "spark-master",
                               "depend": ["System"], "fcheck": genericCheck, "fstart": None, "fstop": None},
              "spark-worker": {"propnames": None, "status": 0, "desc": "spark-worker", "role": "spark-worker",
                               "depend": ["System"], "fcheck": genericCheck, "fstart": None, "fstop": None},
              "spark-history": {"propnames": None, "status": 0, "desc": "spark-history", "role": "spark-history",
                                "depend": ["System"], "fcheck": genericCheck, "fstart": None, "fstop": None},
              "hive": {"propnames": None, "status": 0, "desc": "hive-metastore", "role": "hive",
                       "depend": ["System", "psql"], "fcheck": genericCheck, "fstart": None, "fstop": None},
              "impala-statestore": {"propnames": None, "status": 0, "desc": "impala-state-store",
                                    "role": "impala-statestore",
                                    "depend": ["System", "psql", "hive", "hadoop-namenode", HD_DNODE],
                                    "fcheck": genericCheck, "fstart": None, "fstop": None},
              "impala-catalog": {"propnames": None, "status": 0, "desc": "impala-catalog", "role": "impala-catalog",
                                 "depend": ["System", "psql", "hive", "hadoop-namenode", HD_DNODE, "impala-statestore"],
                                 "fcheck": genericCheck, "fstart": None, "fstop": None},
              "impala-server": {"propnames": None, "status": 0, "desc": "impala-server", "role": "impala-server",
                                "depend": ["System", "psql", "hive", "hadoop-namenode", HD_DNODE, "impala-statestore",
                                           "impala-catalog"], "fcheck": genericCheck, "fstart": None, "fstop": None},
              "analytics": {"propnames": None, "status": 0, "desc": "caspida-analytics", "role": "analytics",
                            "depend": ["System"], "fcheck": genericCheck, "fstart": None, "fstop": None},
              "rule-offline-exec": {"propnames": None, "status": 0, "desc": "caspida-offlineruleexec",
                                    "role": "OfflineRuleExecutor", "depend": ["System"], "fcheck": genericCheck,
                                    "fstart": None, "fstop": None},
              "rule-realtime-exec": {"propnames": None, "status": 0, "desc": "caspida-realtimeruleexec",
                                     "role": "RealtimeRuleExecutor", "depend": ["System"], "fcheck": genericCheck,
                                     "fstart": None, "fstop": None},
              "output-connector": {"propnames": None, "status": 0, "desc": "caspida-outputconnector",
                                   "role": "OutputConnector", "depend": ["System"], "fcheck": genericCheck,
                                   "fstart": None, "fstop": None},
              "sysmonitor": {"propnames": None, "status": 0, "desc": "caspida-sysmon", "role": "Monitor",
                             "depend": ["System"], "fcheck": genericCheck, "fstart": None, "fstop": None},
              "docker": {"propnames": ["container.master.host", "container.worker.host"], "status": 0, "desc": "docker",
                         "role": "Docker", "depend": ["System"], "fcheck": genericCheck, "fstart": None, "fstop": None},
              "kubelet": {"propnames": ["container.master.host", "container.worker.host"], "status": 0,
                          "desc": "kubelet", "role": "Kubelet", "depend": ["System"], "fcheck": genericCheck,
                          "fstart": None, "fstop": None},
              "spark-server": {"propnames": None, "status": 0, "desc": "spark-server", "role": "spark-server",
                               "depend": ["System"], "fcheck": genericCheck, "fstart": None, "fstop": None},
              "splunk": {"propnames": None, "status": 0, "desc": "splunkd", "role": "splunkd", "depend": ["System"],
                         "fcheck": genericCheck, "fstart": None, "fstop": None}
              }


def getActiveServices(services, inactive_services_list):
    new_list_key = []
    new_list_val = []
    for k, v in list(services.items()):
        if k in inactive_services_list:
            continue
        elif is_containerized == "false" and (k == "docker" or k == "kubelet"):
            continue
        elif db_standby_enabled == "false" and k == "psql-standby":
            continue
        elif splunk_forwarder_enabled == "false" and k == "splunk":
            continue
        elif 'depend' in v:
            for inactiveK in set(inactive_services_list).intersection(v['depend']):
                del v["depend"][v['depend'].index(inactiveK)]
            new_list_key.append(k)
            new_list_val.append(v)
        else:
            new_list_key.append(k)
            new_list_val.append(v)
    new_list = list(zip(new_list_key, new_list_val))
    return dict(new_list)


def getInactiveServices():
    inactive_services_list = []
    with open("/etc/caspida/conf/caspida-sysMonitor-services.json") as f:
        data = json.load(f)
    is_standby = os.path.exists('/opt/caspida/conf/replication/properties/standby')
    my_key = "StandbyStatefulServices" if is_standby else "StatefulServices"
    for services in data[my_key]:
        for k, v in services.items():
            if v == "OFF":
                inactive_services_list.append(str(k))
    return inactive_services_list


def getContainerizedApps():
    containerized_apps_list = []
    if is_containerized == "true":
        containerized_apps = readProp("system.containerized.apps")
        apps_list = containerized_apps.split(",")
        if "ubastreamingmodels" in apps_list:
            containerized_apps_list.extend(("storm-nimbus", "storm-supervisor", "storm-ui", "worker", "worker-sup"))
        if "ubaanalytics" in apps_list:
            containerized_apps_list.append("analytics")
        if "ubaparsers" in apps_list:
            containerized_apps_list.append("redis-irserver")
    return containerized_apps_list


inactive_services = getInactiveServices()
# get the list of containerized apps and stop monitoring their corresponding services
inactive_services.extend(getContainerizedApps())

sysServices = getActiveServices(systemServices, inactive_services)
statefulServices = getActiveServices(stServices, inactive_services)

userTbl = {"logfile": None, "output": None, "template": False,
           "debug": 0, "result": [], "entries": [], "lastupdate": "",
           "perfnode_info": [], "script_info": [],
           "bypass": False, "entrycount": 0, "timewait": 0,
           "logdir": None, "inputFD": None, "resultFD": None,
           "caspida_info": {}, "caspida_json": {"CaspidaServices": []},
           "thread_exit": [0, 0, 0, 0], "jsongood": 0, "jsonbad": 0, "gfile": 1, "bfile": 1,
           "redis_info": {"port": REDIS_PORT, "update": False, "status": 8888, "notify": False, "serverip": "localhost",
                          "password": ""},
           "influx_info": {"port": INFLUX_PORT, "serverip": "localhost"},
           "sysservices": sysServices, "statefulservices": statefulServices,
           "scriptname": scriptname, "fixaction": 0, "sshpid": {},
           "epsalert": {},
           "recipients": [],
           "filename": []
           }


def cleanAllUnusedPids(ptr_tbl):
    fname = sys._getframe().f_code.co_name
    info = {}
    for pidentry in ptr_tbl["sshpid"]:
        if not ptr_tbl["sshpid"][pidentry]:
            info[pidentry] = False
    for pidentry in info:
        msg = fname + ":Delete pid[" + str(pidentry) + "]"
        del ptr_tbl["sshpid"][pidentry]
    return PASS


def killAllChild(ptr_tbl):
    fname = sys._getframe().f_code.co_name
    limit = len(ptr_tbl["sshpid"])
    for key in ptr_tbl["sshpid"]:
        if ptr_tbl["sshpid"][key]:
            # kill the pid
            print("Kill the pid ", key)
            try:
                os.kill(key, signal.SIGKILL)
            except OSError as error:
                msg = fname + ":" + str(error)
                print(msg)
    return PASS


def handler(signum, frame):
    print('Signal handler called with signal', signum)
    userTbl["thread_exit"][SVCFIX] = 1
    userTbl["thread_exit"][SVCSTATUS] = 1
    killAllChild(userTbl)
    ppid = os.getpid()
    msg = " Program with " + str(ppid) + " terminated\n"
    printLog(userTbl, msg)
    print(msg)
    try:
        userTbl["resultFD"].flush()
        userTbl["resultFD"].close()
    except:
        print("Output file already closed")
    os.kill(ppid, signal.SIGKILL)
    os._exit(0)


def parseAlertProperties(ptr_tbl):
    fname = sys._getframe().f_code.co_name
    LEN = len(ptr_tbl["filename"])
    for index in range(0, LEN):
        msg = fname + ": index[" + str(index) + "]=" + ptr_tbl["filename"][index]
        print(msg)
        printLog(ptr_tbl, msg)
        rc = parseSysMonitorParameters(ptr_tbl, ptr_tbl["filename"][index])
    return PASS


def readProperties(signum, frame):
    fname = sys._getframe().f_code.co_name
    msg = 'Read in Properties with signal=' + str(signum)
    print(msg)
    printLog(userTbl, msg)
    rc = parseAlertProperties(userTbl)
    return PASS


def serviceLaunch(task_name, task_queue, ptr_tbl, t_lock, thread_index):
    # global EXIT_THREAD
    fname = sys._getframe().f_code.co_name
    msg = fname + "="
    if ptr_tbl["debug"] > 1:
        print(msg)
    while ptr_tbl["thread_exit"][thread_index] == 0:
        t_lock.acquire()
        flag = task_queue.empty()
        if flag is False:
            function, dstip, svc_name = task_queue.get().split(":")
            if t_lock.locked(): t_lock.release()
            msg = "===>Taskname=" + fname + "-- function:" + function + " -- tname=" + task_name + " -- ServiceName=" + \
                  svc_name + " -- ip=" + dstip
            if ptr_tbl["debug"] > 0:
                print(msg)
            # since this utility is used specifically for a cluster with the same USER and password )
            user = ptr_tbl["username"]
            if statefulServices[svc_name][function]:
                rc = statefulServices[svc_name][function](ptr_tbl, svc_name, dstip, user)
            else:
                msg += "is not defined "
                print(msg)
        else:
            if t_lock.locked():
                t_lock.release()

        try:
            pass
            time.sleep(2)
        except KeyboardInterrupt as error:
            ppid = os.getppid()
            os.kill(ppid, signal.SIGTERM)
            os._exit(1)
    return PASS


class thread_proc(threading.Thread):
    def __init__(self, tId, tName, tQueue, ptrTbl, tlock, thread_index):
        threading.Thread.__init__(self)
        self.tId = tId
        self.tName = tName
        self.tQueue = tQueue
        self.userTbl = ptrTbl
        self.taskLock = tlock
        self.tindex = thread_index
        self._stopper = threading.Event()

    def run(self):
        rc = serviceLaunch(self.tName, self.tQueue, self.userTbl, self.taskLock, self.tindex)
        return rc

    def stopit(self):
        self._stopper.set()

    def stopped(self):
        return self._stopper.isSet()


def displayInput(ptr_tbl):
    """ Print input parameters """
    input_tbl = []
    date = time.strftime('%Y-%m-%dT%H:%M:%S%Z')
    ptr_tbl["startime"] = time.time()
    msg = "###############"
    input_tbl.append(msg)
    msg = "Start Time:" + date + "\n"
    LEN = len(ptr_tbl["filename"])
    for i in range(0, LEN):
        msg += "Caspida.properties file [" + str(i) + "]:" + ptr_tbl["filename"][i] + "\n"
        input_tbl.append(msg)
    msg = "Redis on/off:" + "OFF"
    if ptr_tbl["redis"]:
        msg = "Redis on/off:" + "ON"
    input_tbl.append(msg)
    msg = "Old Format :"
    if not ptr_tbl["oldform"]:
        msg += " off "
    else:
        msg += " On "
    input_tbl.append(msg)
    msg = "Fix Action  :  " + ptr_tbl["action"]
    input_tbl.append(msg)
    msg = "Syslog : " + ptr_tbl["syslog"]
    input_tbl.append(msg)
    msg = "Function will be called  in minutes  : " + str(ptr_tbl["period"])
    input_tbl.append(msg)
    msg = "Result will be saved in outputfile: " + ptr_tbl["resultfile"]
    input_tbl.append(msg)
    msg = "Debug level  is set : " + str(ptr_tbl["debug"])
    input_tbl.append(msg)
    msg = "Directory where logs will be saved to: " + (ptr_tbl["logdir"])
    input_tbl.append(msg)
    msg = "Number of seconds per minute : " + (str(ptr_tbl["minute"]))
    input_tbl.append(msg)
    ppid = os.getpid()
    msg = "Current PID : " + (str(ppid))
    input_tbl.append(msg)
    print(msg)
    msg = "###############"
    input_tbl.append(msg)
    lim = len(input_tbl)
    for line in input_tbl:
        if ptr_tbl["debug"] > 0:
            print(line)
        printLog(ptr_tbl, line)

    return PASS


def verifyPidExisting(ptr_tbl, ip, svc_name, proc_name, buf):
    fname = sys._getframe().f_code.co_name
    pids = []
    print_flag = 0
    for line in buf.split("\n"):
        pp = ""
        res = re.findall("(\d+) (.*)", line)
        if res:
            pp = int(res[0][0])
            if proc_name in res[0][1]:
                pids.append(pp)
    msg = fname + ":svcName[" + svc_name + "]PIDS[" + str(pids) + "]"
    if ptr_tbl["debug"] > 0:
        print(msg)
    if not pids:
        msg = fname + ":Warning svcName[" + svc_name + "] NO PIDS[" + str(pids) + "]"
        print(msg)
        printLog(ptr_tbl, msg)
        return FAIL, pids
    # Need to update PID
    limit = len(pids)
    TIME = time.time()
    for index in range(0, limit):
        msg = fname + ":svcName[" + svc_name + "]PIDS[" + str(pids[index]) + "]"
        if print_flag == 1:
            print(msg)
        if pids[index] in ptr_tbl["caspida_info"][ip]["services"][svc_name]["pid"]:
            ptr_tbl["caspida_info"][ip]["services"][svc_name]["pid"][pids[index]]['start'] = TIME
            ptr_tbl["caspida_info"][ip]["services"][svc_name]["pid"][pids[index]]["status"] = STATUS_CHECKED
        else:
            ptr_tbl["caspida_info"][ip]["services"][svc_name]["pid"][pids[index]] = {}
            ptr_tbl["caspida_info"][ip]["services"][svc_name]["pid"][pids[index]]['start'] = TIME
            ptr_tbl["caspida_info"][ip]["services"][svc_name]["pid"][pids[index]]["status"] = STATUS_CHECKED
    minute = 60
    info = {}
    limit = 5 * minute
    for pidentry in ptr_tbl["caspida_info"][ip]["services"][svc_name]["pid"]:
        diff_time = int(TIME - ptr_tbl["caspida_info"][ip]["services"][svc_name]["pid"][pidentry]["start"])
        if diff_time != 0:
            ptr_tbl["caspida_info"][ip]["services"][svc_name]["pid"][pidentry]["status"] &= ~STATUS_CHECKED
        if diff_time > limit:
            # remove expired PID
            min_diff = int(diff_time / minute)
            msg = fname + ":svcName=" + str(svc_name) + "--ip[" + ip + "]--pid[" + str(
                pidentry) + "] -- Refresh Timeout in minutes not updated [" + str(min_diff) + "]"
            print("Warning:" + msg)
            printLog(ptr_tbl, msg)
            info[pidentry] = min_diff
    for pidentry in info:
        msg = fname + ":Delete old PID of svcName=" + str(svc_name) + "--ip[" + ip + "]--pid[" + str(
            pidentry) + "] -- diffTime in minutes [" + str(min_diff) + "]"
        if print_flag == 1:
            print(msg)
        printLog(ptr_tbl, msg)
        del ptr_tbl["caspida_info"][ip]["services"][svc_name]["pid"][pidentry]
    return PASS, pids


def getServiceStatus(ptr_tbl, svc_name, dst_ip, user):
    fname = sys._getframe().f_code.co_name
    service_name = sysServices[svc_name]["svc"]
    proc_cmd = sysServices[svc_name]["svcstat"]
    proc_name = sysServices[svc_name]["pname"]
    proc_cmd_name = sysServices[svc_name]["pcmd"]
    cmd_timeout = EXPECT_TIMEOUT

    if "false" in USESUDO:
        limit = len(proc_cmd)
        for index in range(0, limit):
            command = proc_cmd[index]
            if "sudo" in command:
                command = command.replace("sudo", "")
            proc_cmd[index] = command
    msg = "SrcName=" + str(svc_name) + " service_name=" + str(service_name) + " proc_cmd=" + str(
        proc_cmd) + " proc_name=" + str(proc_name) + " proc_cmd_name=" + str(proc_cmd_name)
    if ptr_tbl["debug"] > 0:
        print(msg)

    ptr_info = ptr_tbl["caspida_info"][dst_ip]["services"][svc_name]
    ptr_info["status"] |= STATUS_CHECKED
    RC = PASS
    log = svc_name + " "
    logdetails = svc_name + " "
    error_log = ""
    impala_services = ["impala-server", "impala-catalog", "impala-state-store"]
    # skip "sudo service <service_name> status" checks for splunk and spark, they are not init.d processes
    # only pid exists? check will happen for these processes at a later step
    if (service_name
            and not ("spark" in service_name or "splunk" in service_name)):
        if service_name in impala_services:
            cmd = "docker container exec impala service %s status | cat" % service_name
        else:
            cmd = "service %s status | cat" % service_name
        if "false" not in USESUDO:
            cmd = "sudo " + cmd
        cmd_list = [cmd]
        if (dst_ip.strip() == "localhost") or \
                (dst_ip.strip() == "127.0.0.1") or (myIP == dst_ip):
            (rc, msg, err) = run_command(cmd)
            # Check the return code. If the retuen code is not 0, append err to msg to perform checks below
            if rc != 0:
                msg += err
        else:
            (rc, msg) = ssh_cli(ptr_tbl, dst_ip, user, cmd_timeout, cmd_list)
        RUN = "running|active \(running\)|active \(exited\)"
        DEAD = "inactive\s\(dead\)|Active:\sfailed"
        STOP = "not running"
        if (re.search(STOP, msg)) or (
                re.search(DEAD, msg) and re.search("(not-found|not be found)", msg) is None):
            RC = FAIL
            status = " not responding "
            if error_log == "":
                error_log = "Service: "
            error_log += status
        elif re.search(RUN, msg):
            status = " is running -- "
        else:
            status = " is running -- "
        log = "Check Service: " + svc_name + status
        logdetails = log + "\n" + msg + ("*" * 30) + "\n"
    if proc_name:
        if "redis" in svc_name:
            port = sysServices[svc_name]["port"][0]
            cmd = "ps ax -o pid= -o args= | grep --color=never  -v grep | grep -e " + proc_name + " | grep " + str(port)
        else:
            cmd = "ps ax -o pid= -o args= | grep --color=never  -v grep | grep -e " + proc_name
        cmd_list = [cmd]
        if (dst_ip.strip() == "localhost") or \
                (dst_ip.strip() == "127.0.0.1") or (myIP == dst_ip):
            (rc, msg, err) = run_command(cmd)
        else:
            (rc, msg) = ssh_cli(ptr_tbl, dst_ip, user, cmd_timeout, cmd_list)
        (rc, PIDS) = verifyPidExisting(ptr_tbl, dst_ip, svc_name, proc_name, msg)
        if rc == PASS:
            if service_name != "":
                if service_name:
                    status = " PID(s):" + str(PIDS)
                elif proc_cmd_name:
                    status = proc_cmd_name + " PID(s):" + str(PIDS)
        else:
            RC = FAIL
            status = "not responding"
            # if there is error, do not add more messages
            if error_log == "":
                error_log = "Service: " + status
        log += "-- Check PIDs:" + status
        logdetails += log + "\n" + msg + ("*" * 30) + "\n"
    if proc_cmd:
        limit = len(proc_cmd)
        msgdetails = ""
        localmsg = ""
        msg = ""
        for index in range(0, limit):
            cmd_list = []
            CMD = proc_cmd[index]
            # for the case of lsof then add the PID
            if re.search(r"lsof", CMD):
                result = ""
                for key in ptr_tbl["caspida_info"][dst_ip]["services"][svc_name]["pid"]:
                    result = CMD + " -Pnp " + str(key) + " | grep --color=never -i listen ;" + result
                CMD = result
            localmsg += "==>CMD: " + CMD
            if ptr_tbl["debug"] > 0:
                print("====>PROC_CMD  actual", str(CMD))
            cmd_list.append(CMD)
            start = time.time()
            if (dst_ip.strip() == "localhost") or \
                    (dst_ip.strip() == "127.0.0.1") or (myIP == dst_ip) \
                    or "curl" in CMD:
                (rc, OUTPUT, err) = run_command(CMD)
                OUTPUT = OUTPUT + "\n" + "ReturnCode=" + str(rc)
            else:
                (rc, OUTPUT) = ssh_cli(ptr_tbl, dst_ip, user, cmd_timeout, cmd_list)
            end = time.time()
            diff = end - start
            temp = fname + ": time[" + str(diff) + "] CMD=" + str(cmd_list) + "--rc=" + str(rc)
            llist = OUTPUT.split("\n")
            LEN = len(llist)
            rc = ""
            for x in range(0, LEN):
                if re.search("^ReturnCode=", llist[x]):
                    rc = llist[x]
                    break
            if re.match(r"ReturnCode=0", rc):
                exitcode = 0
            else:
                # do not add more messages
                if error_log == "":
                    error_log = "Service: not responding "
                if service_name:
                    msg = service_name + ":" + str(cmd_list) + "-- failed "
                else:
                    msg = "System:" + str(cmd_list) + "-- failed"
                print(msg)
                printLog(ptr_tbl, msg)
                exitcode = 1
            # the following codes are used for special case

            if (svc_name in specialServices) and (exitcode != 1):
                for key in specialServices[svc_name]:
                    if re.search(key, CMD):
                        status = "Special Services=" + key
                        (rc, msg) = specialServices[svc_name][key](ptr_tbl, svc_name, dst_ip, OUTPUT)
                        if ptr_tbl["debug"]:
                            print("SPECIAL SERVICE____" + msg)
                        if rc == FAIL:
                            status = str(msg)
                            error_log += f'{status}\n'
                            status += "--Error DATA=" + OUTPUT
                            RC = FAIL
                        localmsg += status
            # non special case
            else:
                status = ""
                if exitcode:
                    RC = FAIL
                    if service_name:
                        status = "Check " + service_name + " Failed with error code: " + str(rc)
                    elif proc_cmd_name:
                        status = "Check " + proc_cmd_name + " Failed with error code: " + str(rc)
                    print(status)
                else:
                    if proc_cmd_name:
                        status = "Checking " + str(proc_cmd_name) + " - running"
            localmsg += "\n" + status
            msgdetails += "\n CMD=" + CMD + " " + msg + "--Result=" + msg
        log += "-- Check special cmd: " + localmsg
        logdetails += msgdetails + "\n" + msg + ("*" * 30) + "\n"

    # The following section is that if PID exists, status should be running for
    # Hadoop,hbase and tsdb
    if RC == PASS:
        if re.match(WORKER, svc_name) is None:
            ptr_info["status"] |= RUNNING
            # reset Email process
            if re.match(r"System", svc_name) is None:
                rc = resetEmailProcess(ptr_tbl, dst_ip, svc_name)
    else:
        ptr_info["status"] &= ~RUNNING

    if re.match(WORKER, svc_name) is None:
        if ptr_info["error"] == "":
            ptr_info["error"] = error_log

    ptr_info["log"] = log
    ptr_info["logdetails"] = logdetails
    if ptr_tbl["debug"] > 1:
        print(ptr_info["log"])
    return PASS


def getServiceName(ptr_tbl, dst_ip, svc_key):
    fname = sys._getframe().f_code.co_name
    user = ptr_tbl["username"]
    if "Ubuntu" in PLATFORM:
        if svc_key in ptr_tbl["sysservices"]:
            if "PSQL" in ptr_tbl["sysservices"][svc_key]["pname"]:
                postgres_version = getPostgresVersion()
                ptr_tbl["sysservices"][svc_key]["pname"] = "bin/postgres"
                ptr_tbl["sysservices"][svc_key]["svc"] = "postgresql@" + postgres_version + "-main"
    else:
        if svc_key in ptr_tbl["sysservices"]:
            if "PSQL" in ptr_tbl["sysservices"][svc_key]["pname"]:
                postgres_version = getPostgresVersion()
                ptr_tbl["sysservices"][svc_key]["pname"] = "/usr/pgsql-" + postgres_version
                ptr_tbl["sysservices"][svc_key]["svc"] = "postgresql-" + postgres_version
                # not found force to use ubuntu


def changeSvcServiceField(ptr_tbl, svc_key, ipaddr):
    fname = sys._getframe().f_code.co_name
    if svc_key in ptr_tbl["sysservices"]:
        match = "psql|psql-standby"
        if re.match(match, svc_key):
            getServiceName(ptr_tbl, ipaddr, svc_key)
            print("psql name changed")
    return PASS


def changeOSReleaseCmd(ptr_tbl):
    fname = sys._getframe().f_code.co_name
    if "Ubuntu" not in PLATFORM:
        if "System" in ptr_tbl["sysservices"]:
            cmd_list = ptr_tbl["sysservices"]["System"]["svcstat"]
            for index in range(len(cmd_list)):
                if "lsb-release" not in cmd_list[index]:
                    continue
                cmd_list[index] = cmd_list[index].replace("lsb", "redhat")
    return PASS


def getSvcNameIP(ptr_tbl, svc_name):
    serverip = getLocalHost(ptr_tbl)
    fname = sys._getframe().f_code.co_name
    for ip in ptr_tbl["caspida_info"]:
        for SVC in ptr_tbl["caspida_info"][ip]["services"]:
            if re.match(SVC, svc_name):
                msg = fname + ":svcname=" + svc_name + " -- ip=%s" % ip
                print(msg)
                return ip
    return serverip


def setupEpsParameters(ptr_tbl, pattern, line):
    rc = PASS
    fname = sys._getframe().f_code.co_name
    if re.search(pattern, line):
        llist = line.split("=")
        print(fname, " recipient list ", len(llist), " -- ", str(llist))
        try:
            key = "frequency"
            if re.search(key, line):
                ptr_tbl["epsalert"][key] = llist[1]
            key = "enable"
            if re.search(key, line):
                ptr_tbl["epsalert"][key] = llist[1]
            key = "watermark"
            if re.search(key, line):
                ptr_tbl["epsalert"][key] = llist[1]
        except IndexError:
            ptr_tbl["epsalert"][pattern] = "0"
            msg = fname + ":String \" " + line + "\" has NULL entry "
            printLog(ptr_tbl, msg)
            print(msg)
            rc = FAIL
    return rc


def parseSysMonitorParameters(ptr_tbl, file_name):
    fname = sys._getframe().f_code.co_name
    try:
        fn = open(file_name, "r")
    except IOError as err:
        msg = "Error: Could not read File " + file_name + " errno=" + str(err.errno) + " strerror=" + str(err.strerror)
        print(msg)
        printLog(ptr_tbl, msg)
        exit(1)
    # readall in buffer
    buf = fn.readlines()
    fn.close()
    rc = PASS
    for line in buf:
        if re.match(r"^#", line):
            continue
        line = removeExcessSpace(line)
        line = line.replace(" ", "")
        line = line.replace("\n", "")
        # search for property name found in caspida properties file
        pattern = "alert.email.lists"
        if re.search(pattern, line):
            ptr_tbl["recipients"] = []
            llist = line.split("=")
            print(fname, " recipient list ", len(llist), " -- ", str(llist))
            info = []
            try:
                ll = llist[1].split(",")
                for entry in ll:
                    if re.match(r"\b", entry):
                        ptr_tbl["recipients"].append(entry)
            except IndexError:
                ptr_tbl["recipients"] = []
            msg = fname + ":Email recipients=" + str(ptr_tbl["recipients"])
            printLog(ptr_tbl, msg)
            print(msg)
        rc = setupEpsParameters(ptr_tbl, "alert.email.eps.alert.watermark", line)
        rc = setupEpsParameters(ptr_tbl, "alert.email.eps.alert.enable", line)
        rc = setupEpsParameters(ptr_tbl, "alert.email.eps.alert.frequency", line)
    ptr_tbl["epsalert"]["lasttrigger"] = 0
    for key in ptr_tbl["epsalert"]:
        msg = "key(" + key + ")=" + str(ptr_tbl["epsalert"][key])
        print(msg)
        printLog(ptr_tbl, msg)
    return rc


def parseSingleFileCaspidaProperties(ptr_tbl):
    fname = sys._getframe().f_code.co_name
    for svckey in statefulServices:
        if svckey == "splunk":
            ip_list = get_cluster_ip_list()
        else:
            property_names = statefulServices[svckey]["propnames"]
            ip_list = getServiceHostIP(svckey)
        if svckey == "System":
            changeOSReleaseCmd(ptr_tbl)

        if len(ip_list) == 0:
            if property_names is None:
                continue
            for propertyName in property_names:
                prop_ip_list = getServiceHostIP(propertyName)
                if not prop_ip_list:
                    continue
                for ip in prop_ip_list:
                    if ip in ip_list:
                        continue
                    ip_list.append(ip)

        for IP in ip_list:
            changeSvcServiceField(ptr_tbl, svckey, IP)
            if "127.0.0.1" in IP or "0.0.0.0" in IP:
                IP = getLocalHost(ptr_tbl)
            if (IP in ptr_tbl["caspida_info"]) is False:
                ptr_tbl["caspida_info"][IP] = {}
            if ("services" in ptr_tbl["caspida_info"][IP]) is False:
                ptr_tbl["caspida_info"][IP]["services"] = {}
            ptr_info = ptr_tbl["caspida_info"][IP]["services"]
            if (svckey in ptr_info) is False:
                ptr_info[svckey] = {}
            if svckey == "System":
                ptr_info[svckey] = initSystemInfo()
            else:
                ptr_info[svckey] = initCaspidaInfo(ptr_tbl)
    rc = parseAlertProperties(ptr_tbl)
    return rc


def setupMissingServices(ptr_tbl):
    """ This routine is used to update the caspida_info table after all IP addresses were updated ( e.g systems ) """
    fname = sys._getframe().f_code.co_name
    # Set up entry which contain "all"
    for svckey in statefulServices:
        property_names = statefulServices[svckey]["propnames"]
        if property_names is None:
            continue
        for propertyName in property_names:
            if re.search(r"all\b", propertyName):
                for ip in ptr_tbl["caspida_info"]:
                    ptr_info = ptr_tbl["caspida_info"][ip]["services"]
                    if (svckey in ptr_info) is False:
                        ptr_info[svckey] = {}
                        if svckey == "System":
                            ptr_info[svckey] = initSystemInfo()
                        else:
                            ptr_info[svckey] = initCaspidaInfo(ptr_tbl)
    rc = PASS
    return rc


def saveStatefulServices(ptr_tbl):
    input = json.loads(statefulServices)
    data = json.dumps(input, indent=2)
    printLog(ptr_tbl, data)
    return PASS


def beautifyJson(ptr_tbl, jsonfd):
    output = ""
    if ptr_tbl["debug"] > 0:
        print(output)
    ordering = {'ServiceGroup': 0, 'Status': 1, 'LastUpdated': 2, 'Error': 3, 'Details': 4}
    f_out = {}
    jsonfd.write("{\n")
    for ENTRY in ptr_tbl["caspida_json"]:
        jsonfd.write("\t\"" + ENTRY + ":\"[\n")
        f_out[ENTRY] = []
        limit = len(ptr_tbl["caspida_json"][ENTRY])
        jsonfd.write("{\n")
        for index in range(0, limit):
            line = ptr_tbl["caspida_json"][ENTRY][index]
            info = {}
            for k in sorted(list(line.keys()), key=lambda k: ordering[k]):
                jsonfd.write("\t\t\"" + k + "\":" + json.dumps({k: line[k]}))
            f_out[ENTRY].append(info)
        jsonfd.write("}\n")
    jsonfd.write("}\n")


def saveCaspidaInfoTbl(ptr_tbl):
    rc = PASS
    date = time.strftime('%Y-%m-%dT%H:%M:%S%Z')
    printLog(ptr_tbl, date)
    for ip in ptr_tbl["caspida_info"]:
        print(date)
        msg = "IP=" + ip + " -- Role:"
        for svckey in ptr_tbl["caspida_info"][ip]["services"]:
            msg += svckey + ", "
        printLog(ptr_tbl, msg)
        print(msg)

        for svckey in ptr_tbl["caspida_info"][ip]["services"]:
            ptr_info = ptr_tbl["caspida_info"][ip]["services"][svckey]
            status = ptr_info["status"]
            msg = "Service[" + svckey + "] Status: "
            if status & STATUS_CHECKED:
                msg += "Checked "
            if status & RUNNING:
                msg += ", Running "
            else:
                msg += ",Stopped "
            if status & FIXED:
                msg += ", Fixed "
            printLog(ptr_tbl, msg)
            print(msg)
            msg = str(ptr_info["log"])
            if ptr_tbl["debug"]:
                print(msg)
            msg = str(ptr_info["logdetails"])
            printLog(ptr_tbl, msg)
            if ptr_tbl["debug"]:
                print(msg)
    if ptr_tbl["redis_info"]["update"]:
        rc = saveCaspidaJsonFile(ptr_tbl)
    return rc


def serviceFix(ptr_tbl):
    rc = PASS
    for ip in ptr_tbl["caspida_info"]:
        for svckey in ptr_tbl["caspida_info"][ip]:
            if (ptr_tbl["caspida_info"][ip]["services"][svckey]["status"] & RUNNING) == RUNNING:
                # find status of each ip
                cmd = "fstart:" + ip + ":" + svckey
    return rc


def serviceStatus(ptr_tbl):
    fname = sys._getframe().f_code.co_name
    rc = PASS
    queue_max = 0
    # calculate the maximum queue jobs
    for ip in ptr_tbl["caspida_info"]:
        for svckey in ptr_tbl["caspida_info"][ip]["services"]:
            queue_max += 1
    if queue_max < 1:
        msg = "ERROR!!!there is no service initialized for query "
        printLog(ptr_tbl, msg)
        return FAIL

    myqueue = queue.Queue(queue_max)
    myqueue.queue.clear()
    ppid = os.getpid()
    tlock = threading.Lock()
    t_tbl = []
    tlock.acquire()
    threadnum = ptr_tbl["threadnum"]
    # fill up all jobs queue
    for ip in ptr_tbl["caspida_info"]:
        for svckey in ptr_tbl["caspida_info"][ip]["services"]:
            cmd = "fcheck:" + str(ip) + ":" + str(svckey)
            myqueue.put(cmd)
    tlock.release()
    ptr_tbl["thread_exit"][SVCSTATUS] = 0
    # the following loop use the number of thread given by user or default value NUM_OF_THREADS  and it is used
    # depending how much thread will be used by this util
    for ccount in range(0, threadnum):
        tt = thread_proc(ccount, "Name-" + str(ccount), myqueue, ptr_tbl, tlock, SVCSTATUS)
        tt.start()
        t_tbl.append(tt)
    # Wait for job queues
    start = time.time()
    watermark1 = (EXPECT_TIMEOUT * len(ptr_tbl["statefulservices"])) + 100
    watermark2 = watermark1 + 100
    while myqueue.empty() is not True:
        end = time.time()
        total = int(end - start)
        if total > watermark1:
            if tlock.locked():
                tlock.release()
        if total > watermark2:
            print(fname, "Clear Queue ")
            myqueue.queue.clear()
            time.sleep(2)
            break
        time.sleep(2)
        pass

    ptr_tbl["thread_exit"][SVCSTATUS] = 1
    for tt in t_tbl:
        tt.join()
    end = time.time()
    diff = end - start
    myqueue.task_done()
    msg = fname + ": Processing time [" + str(diff) + "]"
    print(msg)
    return rc


def convertAction(ptr_tbl):
    fname = sys._getframe().f_code.co_name
    msg = "Process Fixing action :" + ptr_tbl["action"]
    if ptr_tbl["action"] == FIXALL:
        ptr_tbl["fixaction"] = FIX_ALL
        return (PASS, msg)
    if ptr_tbl["action"] == FIXCONF:
        ptr_tbl["fixaction"] = FIX_CONFIG
        return (PASS, msg)
    if ptr_tbl["action"] == NOFIX:
        ptr_tbl["fixaction"] = FIX_ALL
        return PASS, msg
    msg = "Error Fixing action :" + ptr_tbl["action"] + "is not recognized "
    print(msg)
    exit(1)
    return FAIL, msg


def testEmailAlert(ptr_tbl):
    fname = sys._getframe().f_code.co_name
    llen = len(ptr_tbl["recipients"])
    if llen < 1:
        print(fname, ": Recipient list is NULL")
        return FAIL

    rc = PASS
    srv_name = "System"
    dstip = getLocalHost(ptr_tbl)
    ptr_alert = ptr_tbl["caspida_info"][dstip]["services"][srv_name]["alert"]
    ptr_alert["severity"] = ALERT_WARNING
    ptr_alert["subject"] = ALERT_SEVERITY[ALERT_WARNING] + ": Disk Usage of host(" + dstip + ") is above " + str(
        DISK_USAGE_THRESHOLD) + "%"
    ptr_alert["message"] = "Please contact IT for support"
    data = {}
    (rc, data) = buildJsonData(ptr_tbl, dstip, srv_name)
    rc = send_email_alert(ptr_tbl, data)
    return rc


def generateEmailAlert(ptr_tbl):
    fname = sys._getframe().f_code.co_name
    # ignore if recipients list is Null
    llen = len(ptr_tbl["recipients"])
    rc = PASS
    time.sleep(10)
    flag_debug = 0
    if llen < 1:
        print(fname, ": Recipient list is NULL")
        return FAIL
    for ip in ptr_tbl["caspida_info"]:
        if flag_debug == 1:
            print(fname, ":ip[", ip, "]")
        for srvName in ptr_tbl["caspida_info"][ip]["services"]:
            ptr_alert = ptr_tbl["caspida_info"][ip]["services"][srvName]["alert"]
            if flag_debug == 1:
                print(fname, ":[", ip, "]--SrvName", srvName, "-- Severity", ptr_alert["severity"])
            if ptr_alert["severity"] > ALERT_NONE:
                if ptr_alert["retryCount"] < ALERT_RETRY_LIMIT:
                    # set to warning
                    ptr_alert["retryCount"] += 1
                    data = {}
                    (rc, data) = buildJsonData(ptr_tbl, ip, srvName)
                    msg = fname + ": retrycount[" + str(ptr_alert["retryCount"]) + "]=" + str(data)
                    if flag_debug == 1:
                        print(msg)
                    printLog(ptr_tbl, msg)
                    rc = send_email_alert(ptr_tbl, data)
    return rc


# -------------------
# Main body
# -------------------
if __name__ == "__main__":
    rc = main(userTbl, curr_path, scriptname)
if not os.path.exists(userTbl["logdir"]):
    cmd = " mkdir -p  " + userTbl["logdir"]
    rc = os.system(cmd)

# Set the signal Handler
signal.signal(signal.SIGTERM, handler)
signal.signal(signal.SIGUSR1, readProperties)

# -----------------
# Create Result File
# ----------------
resultfile = userTbl["resultfile"]
try:
    if userTbl["overwrite"]:
        # overwriting
        MODE = "w"
    else:
        # appending
        MODE = "a"
    resultFN = open(resultfile, MODE)
except IOError as err:
    print("Error: Could not write to result File \'%s\'  -- %s %s " % (resultfile, err.errno, err.strerror))
    exit(1)
userTbl["resultFD"] = resultFN

# ------
# Check for availability of Caspida properties files
# ----
LEN = len(userTbl["filename"])
rc = PASS
for index in range(0, LEN):
    filename = userTbl["filename"][index]
    if os.path.isfile(filename) is False:
        msg = "Error:\"" + filename + "\" is not found "
        print(msg)
        userTbl["resultFD"].write(msg + "\n")
        rc = FAIL
# ---
if rc == FAIL:
    exit(1)

# --------
# isRemote
# --------
myIP = getLocalHost(userTbl).strip()
print(myIP)

# -----------------
# Display Input parameters
# ----------------
rc = displayInput(userTbl)
rc = printJsonProfiles(userTbl)
(rc, msg) = convertAction(userTbl)

if rc == FAIL:
    print(msg)
    printLog(userTbl, msg + "\n")
    exit(0)

parseSingleFileCaspidaProperties(userTbl)
userTbl["redis_info"]["serverip"] = getFirstServiceHost("redis-server")
userTbl["redis_info"]["password"] = getRedisPwd()
userTbl["influx_info"]["serverip"] = getFirstServiceHost("tsdb")
ppid = os.getpid()
LOOP = 1
UBA_NODES = list(userTbl["caspida_info"].keys())

# Get container worker nodes
if is_containerized == 'true':
    container_worker_nodes = get_container_worker_nodes()
    if container_worker_nodes:
        populate_container_worker_nodes(userTbl, container_worker_nodes)

if userTbl["redis"]:
    rc = redisRegister(userTbl)
    rc = register_influx(userTbl)

date = time.strftime('%Y-%m-%dT%H:%M:%S%Z')
userTbl["lastupdate"] = date

if userTbl["email"]:
    rc = testEmailAlert(userTbl)
    os._exit(0)

rc = serviceStatus(userTbl)
rc = resetRedis(userTbl)
rc = setupMissingServices(userTbl)
# --------------------------------------------
# Initialize group for each cluster Host
# -------------------------------------------
rc = initClusterGroups(userTbl)
rc = setGroupRunning(userTbl)
rc = cleanCaspidaInfoTbl(userTbl, ALLTYPES)
if userTbl["configcheck"]:
    (rc, msg) = checkProfiles(userTbl)
userTbl["resultFD"].close()
start = time.time()
status_log_timer_start = time.time()

while LOOP:
    try:
        # -----------------
        # Create Result File
        # ----------------
        resultfile = userTbl["resultfile"]
        try:
            # appending
            MODE = "a"
            resultFN = open(resultfile, MODE)
        except IOError as err:
            print("Error: Could not write to result File \'%s\'  -- %s %s " % (resultfile, err.errno, err.strerror))
        userTbl["resultFD"] = resultFN

        # Licensing is Disabled till 2.2.0. Uncomment the line below to enable
        rc = manageLicenses()
        rc = rotateResultFile(userTbl, RESULT_FILESIZE)
        rc = rotateCaspidaout(userTbl, CASPIDAOUT_FILESIZE)
        date = time.strftime('%Y-%m-%dT%H:%M:%S%Z')
        userTbl["lastupdate"] = date
        # initializing Caspida Info Table
        # all the steps must be executed in sequence
        rc = cleanCaspidaInfoTbl(userTbl, SVCTYPES)
        rc = cleanAllUnusedPids(userTbl)
        rc = serviceStatus(userTbl)
        rc = updateGroupRepeatFailureCount(userTbl)
        if userTbl["configcheck"]:
            rc = mergeStatus(userTbl)
        rc = updateRedis(userTbl)
        rc = saveCaspidaInfoTbl(userTbl)
        rc = fixGroupRepeatFailureCount(userTbl)
        rc = cleanAllUnusedPids(userTbl)
        if userTbl["configcheck"]:
            rc = forceDisplay(userTbl, "System")
        # ---------------------
        # force to update GUI  for every 15 minutes
        # ---------------------
        end = time.time()
        total = int(end - start)
        limit = POSTING_SCHED * userTbl["minute"]
        print("total=", total, " limit=", limit)
        if total > limit:
            if userTbl["configcheck"]:
                (rc, msg) = checkProfiles(userTbl)
                rc = mergeStatus(userTbl)
            if userTbl["debug"]:
                rc = printProfCaspidaInfoTbl(userTbl)
            start = time.time()
            userTbl["redis_info"]["update"] = True
            msg = "update GUI at: " + date
            print(msg)
            userTbl["resultFD"].write(msg + "\n")
            userTbl["resultFD"].flush()
        if userTbl["redis"]:
            # generate email alert
            rc = generateEmailAlert(userTbl)
            rc = postRedis(userTbl)
            rc = epsAlertTrigger(userTbl)
        else:
            # resetRedisupdate
            userTbl["redis_info"]["update"] = False
        # check if its time to periodically log status
        seconds_since_last_status_log = end - status_log_timer_start
        hrs_since_last_status_log = seconds_since_last_status_log / (60 * 60)
        if hrs_since_last_status_log > STATUS_LOG_INTERVAL_HRS:
            print("Time to update service status in status log")
            log_all_service_status(userTbl)
            status_log_timer_start = time.time()
        userTbl["resultFD"].close()
        period = userTbl["period"]
        if period == 0:
            break
        sTime = 30
        if userTbl["debug"] > 1:
            print("wait for ", sTime, " sec")
        time.sleep(sTime)
    except KeyboardInterrupt as error:
        exitflag = 1
        os.kill(ppid, signal.SIGTERM)
        os._exit(1)
    except Exception:
        print("ERROR: ", traceback.format_exc())
        print(time.strftime('%Y-%m-%dT%H:%M:%S%Z'), " Restarting service checks...")

print("Program ended")
os._exit(0)
