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


class GitListing:

    def __init__(self, git_objects, page, page_size):
        self.git_objects = git_objects
        self.page = page
        self.page_size = page_size

    def to_json(self):
        return {
            "listing": [x.to_json() for x in self.git_objects],
            "page": self.page,
            "page_size": self.page_size
        }
