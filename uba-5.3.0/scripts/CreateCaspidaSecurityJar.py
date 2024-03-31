#!/usr/bin/python3

##
# Copyright (C) 2014-2015 - Caspida Inc., All rights reserved.
# This is Caspida proprietary and confidential material and its use
# is subject to license terms.
##

import os, sys, shutil
import re, glob
import shlex
import subprocess
import datetime
from subprocess import Popen, PIPE

CASPIDA_COMMON_ENV="CaspidaCommonEnv.sh"

# ex: look for -version in test-jar-1.0.0.jar, test-1.1.jar, test-2-1.2.3.jar"
VersionPattern = re.compile("-\d+\.")

# Compares two versions
# Assumes x and y are lists e.g., x=[1,2,3], y=[0,4,2]
def compare(x, y):
   if x[0] < y[0]:
      return -1
   elif x[0] == y[0]:
      if x[1] < y[1]:
         return -1
      elif x[1] == y[1]:
         if x[2] < y[2]:
            return -1
         elif x[2] == y[2]: 
            return 0
         else: 
            return 1
      else:
          return 1        
   else:
      return 1

def get_int(s):
  val = 0
  try:
    val = int(s)
  except Exception: # ignore
    val = 0;

  return val
# END get_int

# example
# in: hello-algo-1.0.1.jar
# out: [1,0,1]
def get_version(jar_name):
   match = VersionPattern.search(jar_name)
   idx = -1 if match == None else match.start()
   versionStr = "0.0.0" if idx == -1 else jar_name[idx+1:]

   versionArr = [ ]
   res = versionStr.split(".")
   for i in range(0, 3):
     v = get_int(res[i]) if len(res) > i else 0
     versionArr.append(v)
   # end for

   return versionArr

# removes the version from the jar name and gets just the name
#   ex: In: hello-algo-1-2.0.1.jar, out= hello-algo-1
def get_name_without_version(jar_name):
   match = VersionPattern.search(jar_name)
   idx = -1 if match == None else match.start()
   name = jar_name if idx == -1 else jar_name[:idx]
   #print "get_name_without_version: returning: " + name
   return name

def pair_compare(x,y):
   return compare(x[0],y[0])

import itertools
def get_only_latest_version_jars(jar_list):
   nameToPathMap = { } # key - name, value = full_path
   for jar in jar_list:
     basename = os.path.basename(jar)
     nameToPathMap[basename] = jar

   jar_names = list(nameToPathMap.keys())
   res = []
   for k, g in itertools.groupby(sorted(jar_names), get_name_without_version):
      ll = [(get_version(x),x) for x in list(g)]
      s = sorted(ll, key = lambda ele: pair_compare, reverse = True)
      highest_version_jar = s[0][1]
      res.append(nameToPathMap[highest_version_jar])
      #print "appending: %s -> %s" % (highest_version_jar, nameToPathMap[highest_version_jar])
   return res
# END get_only_latest_version_jars

def run_command(cmd):
  try:
    args = shlex.split(cmd)
    proc = Popen(args, stdout=PIPE, stderr=PIPE)
    out, err = proc.communicate()
    exitcode = proc.returncode
    return exitcode, out, err
  except OSError:
    print("Failed to run %s" %(cmd))
    return exitcode, out, err

def get_filepaths(directory):
  file_paths = []
  for root, dirs, files in os.walk(directory):
    for filename in files:
      filepath = os.path.join(root, filename)
      file_paths.append(filepath)
    return file_paths 


def generate_latest_fileversion(fullFilePaths):
   return get_only_latest_version_jars(fullFilePaths)

# look if we are running inside a container: aufs has issues with long filenames
# in container, we copy over the CaspidaPlatform-x.x.x.jar to dest & run jar -uvf on it
def is_running_in_container():
  inContainer = False
  filename = "/proc/1/cgroup"
  try:
    for line in open(filename):
      if ":/docker" in line:
        inContainer = True
        break
  except Exception as err:
    print("failed to read file: %s, err=%s" % (filename, err))
    inContainer = False

  return inContainer
# END is_running_in_container

def generateCaspidaSecurityJar(latestFiles, destJar, assumeContainer):
  CASPIDA_BASE_DIR = os.environ['CASPIDA_BASE_DIR']
  CASPIDA_LIB_DIR = os.environ['CASPIDA_LIB_DIR']

  CASPIDA_CLASSES = CASPIDA_BASE_DIR + '/' + "classes"
  CASPIDA_PLATFORM_JAR = CASPIDA_LIB_DIR + '/' + os.environ['CASPIDA_PLATFORM_JAR']

  cmd = 'bash -c "rm -rf ' + CASPIDA_CLASSES + ' ' + destJar + ' && mkdir -p ' + CASPIDA_CLASSES + '"'
  exitcode, out, err = run_command(cmd)
  if exitcode != 0:
    print("Failed to generate %s, out=%s, err=%s" %(destJar, out, err))
    return -1

  # the default command to extract jar into CASPIDA_CLASSES
  cmd = 'bash -c "cd ' + CASPIDA_CLASSES + ' && jar xf'

  # The CASPIDA_PLATFORM_JAR contains lot of files with long filenames creating problems
  # in docker container (see UBA-4686). So for the containers: just copy the jar & update
  # with the extracted content jars
  # assumeContainer = True, skips the is_running_in_container check & does a jar update
  #   this is faster on some of our VMs which have slow disks..
  inContainer = True if assumeContainer else is_running_in_container();
  if inContainer:
    print("%s: Running in container, copying jar & updating" % (datetime.datetime.now()))
    try:
      shutil.copyfile(CASPIDA_PLATFORM_JAR, destJar)
    except Exception as err:
      print("Failed to copy file %s to %s, %s" %(CASPIDA_PLATFORM_JAR, destJar, err))
      return -1
  else:
    print("Extracting %s" %(CASPIDA_PLATFORM_JAR))
    runCmd = cmd + " " + CASPIDA_PLATFORM_JAR + '"'
    exitcode, out, err = run_command(runCmd)
    if exitcode != 0:
      print("Failed to generate %s, out=%s, err=%s" %(destJar, out, err))
      return -1

  # for the content jars, extract as usual & update the destJar
  for jarFile in latestFiles:
    runCmd = cmd + " " + jarFile + '"'
    print("Extracting %s" %(jarFile))
    exitcode, out, err = run_command(runCmd)
    if exitcode != 0:
      print("Failed to generate %s, out=%s, err=%s" %(destJar, out, err))
      return -1

  msg = "Updating" if inContainer else "Creating"
  print("%s %s" %(msg, destJar))

  # update in container, create in the rest
  jarOption = "u" if inContainer else "c"
  cmd = 'bash -c "cd ' + CASPIDA_CLASSES + ' && jar ' + jarOption + 'fM ' + destJar + ' ."'
  exitcode, out, err = run_command(cmd)
  if exitcode != 0:
    print("Failed to generate %s, out=%s, err=%s" %(destJar, out, err))
    return -1

  cmd = 'bash -c "rm -rf ' + CASPIDA_CLASSES + '/*"'
  exitcode, out, err = run_command(cmd)
  return 0;

def source_environment(envFile):
  print(envFile)
  cmd = 'bash -c "source ' + envFile + ' && env "'
  exitcode, out, err = run_command(cmd)
  for line in out.splitlines():
    line = line.decode()
    (key, _, value) = line.partition("=")
    os.environ[key] = value

# returns an array of files matching the pattern
def get_files(pattern):
  return glob.glob (pattern);

####
# adds in the latestFiles, CaspidaPlatform-x.x.x.jar into destJar
# also used by /opt/caspida/bin/subscription/install-subscription-content.py
####
def create_security_jar(outputJarName, assumeContainer):
  contentDir = os.environ['CASPIDA_CONTENT_DIR']
  pattern = contentDir + "/*/lib/*.jar"; #/opt/caspida/content/*/lib/*.jar
  fullFilePaths = get_files(pattern);

  latestFiles = generate_latest_fileversion(fullFilePaths)
  status = generateCaspidaSecurityJar(latestFiles, outputJarName, assumeContainer)
  return status
  #print "files=%s" % (latestFiles);
  #return 0
# END create_security_jar

def main():
  script = sys.argv[0];
  scriptDir = os.path.dirname(os.path.realpath(script))
  caspidaCommonEnvFile = scriptDir + '/' + CASPIDA_COMMON_ENV
  source_environment(caspidaCommonEnvFile)
  print("%s: Running %s" %(datetime.datetime.now(), script))

  CASPIDA_LIB_DIR = os.environ['CASPIDA_LIB_DIR']
  CASPIDA_SECURITY_JAR = os.path.join(CASPIDA_LIB_DIR, os.environ['CASPIDA_SECURITY_JAR'])

  # -c : assumes its a container
  assumeContainer = True if len(sys.argv) > 1 and sys.argv[1] == "-c" else False
  create_security_jar(CASPIDA_SECURITY_JAR, assumeContainer)

if __name__ == "__main__":
  main()
