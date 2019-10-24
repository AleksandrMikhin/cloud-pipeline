#!/bin/bash

# Copyright 2017-2019 EPAM Systems, Inc. (https://www.epam.com/)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

check_free_disc_space() {
    # Verify free disk space is enough for committing a docker image
    local free_disc_space_kb=`df -k --output=avail /ebs | tail -n1` #Kb
    local container_size_b=$(docker inspect ${CONTAINER_ID} -s --format "{{.SizeRw}}")  # Bytes
    local container_size_kb=$((${container_size_b} / 1024))            # Kb

    if (( ${container_size_kb} > ${free_disc_space_kb} )); then
        pipe_log_warn "[WARN] Free disk space ${free_disc_space_kb}Kb is not enough for committing current container will result into ~${container_size_kb}Kb (${container_size_b}b) of data." "$TASK_NAME"
        exit 126
    fi
}

stop_service() {
    local _SERVICE_NAME=$1
    service ${_SERVICE_NAME} stop &> /dev/null || systemctl stop ${_SERVICE_NAME} &> /dev/null
}

download_file() {
    local _FILE_URL=$1
    wget -q --no-check-certificate -O ${_FILE_URL} 2>/dev/null || curl -s -k -O ${_FILE_URL}
    _DOWNLOAD_RESULT=$?
    return "$_DOWNLOAD_RESULT"
}

commit_file_and_stop_docker() {
    pipe_log_info "[INFO] Start commiting pipeline run" "$TASK_NAME"
    commit_hook ${CONTAINER_ID} "pre" false true ${PRE_COMMIT_COMMAND}

    commit_file ${NEW_IMAGE_NAME}
    check_last_exit_code $? "[ERROR] Error occured while committing temporary container" \
                            "[INFO] Temporary container was successfully committed with name: ${NEW_IMAGE_NAME}" \
                            "exit 126"

    export tmp_container=`docker run --entrypoint "/bin/sleep" -d ${NEW_IMAGE_NAME} 1d`

    commit_hook ${tmp_container} "post" false true ${POST_COMMIT_COMMAND}

    pipe_exec "docker commit ${tmp_container} ${NEW_IMAGE_NAME} > /dev/null" "$TASK_NAME"
    check_last_exit_code $? "[ERROR] Error occured while committing container" \
                            "[INFO] Container was successfully committed with name: $NEW_IMAGE_NAME" \
                            "exit 126"

    pipe_exec "docker logs ${CONTAINER_ID}" "${DEFAULT_TASK_NAME}"
    check_last_exit_code $? "[ERROR] Error occurred while retrieving logs from docker container ${CONTAINER_ID}" \
                            "[INFO] Docker container logs were successfully retrieved." \
                            "exit 126"

    stop_service kubelet
    kubeadm reset
    stop_service docker
    check_last_exit_code $? "[ERROR] Error occured while stopping docker service" \
                            "[INFO] Docker service was successfully stopped"
    # CNI tear down
    rm -rf /var/lib/cni/
    rm -rf /var/lib/kubelet/*
    rm -rf /var/log/pods/*

    ifconfig cni0 down
    ifconfig flannel.1 down

    ip link delete cni0
    ip link delete flannel.1

    pipe_log_success "[INFO] Commit pipeline run and stop docker service tasks succeeded" "$TASK_NAME"

}

export API=${1}
export API_TOKEN=${2}
PAUSE_DISTRIBUTION_URL=${3}
DISTRIBUTION_URL=${4}
export RUN_ID=${5}
export CONTAINER_ID=${6}
TIMEOUT=${7}
export NEW_IMAGE_NAME=${8}
export DEFAULT_TASK_NAME=${9}
export PRE_COMMIT_COMMAND=${10}
export POST_COMMIT_COMMAND=${11}

export TASK_NAME="PausePipelineRun"
export CP_PYTHON2_PATH=python
export RUNS_ROOT='/runs'

export COMMON_REPO_DIR="$(pwd)/pipe-common"
export SCRIPTS_DIR="$(pwd)/commit-run-scripts"


mkdir $SCRIPTS_DIR
_DOWNLOAD_RESULT=0
cd $SCRIPTS_DIR
download_file "${PAUSE_DISTRIBUTION_URL}common_commit_initialization.sh"

_DOWNLOAD_RESULT=$?
if [ "$_DOWNLOAD_RESULT" -ne 0 ];
then
    pipe_log_fail "[ERROR] Common commit script downloads failed. Exiting." $TASK_NAME
    echo "[ERROR] Common commit script downloads failed. Exiting"
    exit "$_DOWNLOAD_RESULT"
fi
chmod +x $SCRIPTS_DIR/*

. $SCRIPTS_DIR/common_commit_initialization.sh

install_pip

mkdir $COMMON_REPO_DIR
cd $COMMON_REPO_DIR
install_pipeline_code
cd ..

check_free_disc_space

commit_file_and_stop_docker
