#!/bin/bash
# Copyright 2021 EPAM Systems, Inc. (https://www.epam.com/)
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
cd  $CP_GITLAB_READER_HOME/gitreader/gitreader
openssl x509 -pubkey -noout -in $CP_API_SRV_CERT_DIR/jwt.key.x509  > $CP_GITLAB_READER_HOME/pub-jwt-key.pem
export CP_API_JWT_PUB_KEY=$CP_GITLAB_READER_HOME/pub-jwt-key.pem
mkdir -p ${CP_GITLAB_READER_LOG_DIR:-"/var/log/cp-git-reader/"}
_LOG_FILE=${CP_GITLAB_READER_LOG_DIR:-"/var/log/cp-git-reader/"}"uwsgi-git-reader.log"
uwsgi --socket 0.0.0.0:8080 --protocol http -w wsgi_starter:app -M -p ${CP_GITLAB_READER_WORKER_COUNT:-2} --logto $_LOG_FILE


