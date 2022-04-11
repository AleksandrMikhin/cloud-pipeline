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

_SERVICES_TO_INSTALL="$CP_SERVICES_LIST"
_ERASE_DATA="$CP_ERASE_DATA"

# Export docker registry where all containers are stored
export CP_DOCKER_DIST_SRV=${CP_DOCKER_DIST_SRV}

sudo chmod +x $DEPLOY_DIR/pipectl && \
sudo -E $DEPLOY_DIR/pipectl install \
    -env CP_DOCKER_DIST_SRV=${CP_DOCKER_DIST_SRV} \
    -env CP_AWS_KMS_ARN="$CP_AWS_KMS_ARN" \
    -env CP_PREF_CLUSTER_SSH_KEY_NAME="$CP_PREF_CLUSTER_SSH_KEY_NAME" \
    -env CP_PREF_CLUSTER_INSTANCE_SECURITY_GROUPS="$CP_PREF_CLUSTER_INSTANCE_SECURITY_GROUPS" \
    -env CP_PREF_STORAGE_TEMP_CREDENTIALS_ROLE="$CP_PREF_STORAGE_TEMP_CREDENTIALS_ROLE" \
    -env CP_CLUSTER_SSH_KEY="$DEPLOY_DIR/$CP_PREF_CLUSTER_SSH_KEY_NAME" \
    -env CP_DEPLOYMENT_ID="$CP_DEPLOYMENT_ID" \
    -env CP_KUBE_MIN_DNS_REPLICAS=3 \
    -env CP_KUBE_SERVICES_TYPE="ingress" \
    -env CP_GITLAB_EXTERNAL_PORT=${CP_AWS_GITLAB_EXTERNAL_PORT} \
    -env CP_GITLAB_INTERNAL_PORT=${CP_AWS_GITLAB_INTERNAL_PORT} \
    -env CP_GITLAB_EXTERNAL_HOST="${CP_AWS_GITLAB_EXTERNAL_HOST}" \
    -env CP_GITLAB_INTERNAL_HOST="${CP_AWS_GITLAB_INTERNAL_HOST}" \
    -env CP_GITLAB_EXTERNAL_URL="${CP_AWS_GITLAB_EXTERNAL_URL}" \
    -env CP_GITLAB_SSO_ENDPOINT_ID="${CP_AWS_GITLAB_SSO_ENDPOINT_ID}" \
    -env CP_GITLAB_IDP_CERT_PATH="${CP_AWS_GITLAB_IDP_CERT_PATH}" \
    -env CP_IDP_EXTERNAL_HOST="${CP_AWS_IDP_EXTERNAL_HOST}" \
    -env CP_IDP_EXTERNAL_PORT=${CP_AWS_IDP_EXTERNAL_PORT} \
    -env CP_IDP_INTERNAL_PORT=${CP_AWS_IDP_INTERNAL_PORT} \
    -s cp-notifier \
    -env CP_NOTIFIER_SMTP_SERVER_HOST="$CP_NOTIFIER_SMTP_SERVER_HOST" \
    -env CP_NOTIFIER_SMTP_SERVER_PORT="$CP_NOTIFIER_SMTP_SERVER_PORT" \
    -env CP_NOTIFIER_SMTP_FROM="$CP_NOTIFIER_SMTP_FROM" \
    -env CP_NOTIFIER_SMTP_USER="$CP_NOTIFIER_SMTP_USER" \
    -env CP_NOTIFIER_SMTP_PASS="$CP_NOTIFIER_SMTP_PASS" \
    -env CP_DEFAULT_ADMIN_EMAIL="$CP_DEFAULT_ADMIN_EMAIL" \
    -s cp-gitlab-reader \
    -s cp-api-srv \
    -env CP_API_SRV_EXTERNAL_PORT=${CP_AWS_API_SRV_EXTERNAL_PORT} \
    -env CP_API_SRV_INTERNAL_PORT=${CP_AWS_API_SRV_INTERNAL_PORT} \
    -env CP_API_SRV_EXTERNAL_HOST="${CP_AWS_API_SRV_EXTERNAL_HOST}" \
    -env CP_API_SRV_INTERNAL_HOST="${CP_AWS_API_SRV_INTERNAL_HOST}" \
    -env CP_API_SRV_IDP_CERT_PATH="${CP_AWS_API_SRV_IDP_CERT_PATH}" \
    -env CP_PREF_UI_PIPELINE_DEPLOYMENT_NAME="${CP_AWS_PREF_UI_PIPELINE_DEPLOYMENT_NAME}" \
    -env CP_PREF_STORAGE_SYSTEM_STORAGE_NAME="$CP_PREF_STORAGE_SYSTEM_STORAGE_NAME" \
    -env CP_API_SRV_SSO_ENDPOINT_ID="${CP_AWS_API_SRV_SSO_ENDPOINT_ID}" \
    -env CP_HA_DEPLOY_ENABLED="${CP_AWS_HA_ENABLED:-true}" \
    -env CP_CLOUD_REGION_FILE_STORAGE_HOSTS="$CP_CLOUD_REGION_FILE_STORAGE_HOSTS" \
    -s cp-docker-registry \
    -env CP_DOCKER_EXTERNAL_PORT=${CP_AWS_DOCKER_EXTERNAL_PORT} \
    -env CP_DOCKER_INTERNAL_PORT=${CP_AWS_DOCKER_INTERNAL_PORT} \
    -env CP_DOCKER_EXTERNAL_HOST="${CP_AWS_DOCKER_EXTERNAL_HOST}" \
    -env CP_DOCKER_INTERNAL_HOST="${CP_AWS_DOCKER_INTERNAL_HOST}" \
    -env CP_DOCKER_STORAGE_ROOT_DIR="/docker-pub/" \
    -env CP_DOCKER_STORAGE_TYPE="$CP_DOCKER_STORAGE_TYPE" \
    -env CP_DOCKER_STORAGE_CONTAINER="$CP_DOCKER_STORAGE_CONTAINER" \
    -s cp-edge \
    -env CP_EDGE_EXTERNAL_PORT=${CP_AWS_EDGE_EXTERNAL_PORT} \
    -env CP_EDGE_INTERNAL_PORT=${CP_AWS_EDGE_INTERNAL_PORT} \
    -env CP_EDGE_EXTERNAL_HOST="${CP_AWS_EDGE_EXTERNAL_HOST}" \
    -env CP_EDGE_INTERNAL_HOST="${CP_AWS_EDGE_INTERNAL_HOST}" \
    -env CP_EDGE_WEB_CLIENT_MAX_SIZE=0 \
    -env CP_EDGE_SSL_PROTOCOLS="TLSv1 TLSv1.1 TLSv1.2" \
    -s cp-docker-comp \
    -env CP_DOCKER_COMP_WORKING_DIR="/cloud-pipeline/docker-comp/wd" \
    -s cp-dav \
    -env CP_DAV_AUTH_URL_PATH="${CP_DAV_AUTH_URL_PATH}" \
    -env CP_DAV_MOUNT_POINT="${CP_DAV_MOUNT_POINT}" \
    -env CP_DAV_SERVE_DIR="${CP_DAV_SERVE_DIR}" \
    -env CP_DAV_URL_PATH="${CP_DAV_URL_PATH}" \
    -s cp-git-sync \
    -s cp-sensitive-proxy \
    -s cp-billing-srv \
    -env CP_BILLING_DISABLE_GS="true" \
    -env CP_BILLING_DISABLE_AZURE_BLOB="true" \
    -env CP_BILLING_CENTER_KEY="billing-group" \
    -s cp-share-srv \
    -s cp-monitoring-srv \
    -s cp-dts-tunnel \
    -m \
    --external-host-dns \
    -demo
