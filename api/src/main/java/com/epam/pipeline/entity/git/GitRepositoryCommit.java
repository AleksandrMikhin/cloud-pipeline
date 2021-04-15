/*
 * Copyright 2021 EPAM Systems, Inc. (https://www.epam.com/)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.epam.pipeline.entity.git;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import java.util.Date;

/**
 * Represents Gitlab repository commit
 */
@Data
public class GitRepositoryCommit {

    @JsonProperty("commit")
    private String commit;

    @JsonProperty("commit_message")
    private String commitMessage;

    @JsonProperty("author")
    private String author;

    @JsonProperty("author_email")
    private String authorEmail;

    @JsonProperty("commit_date")
    private Date commitDate;
}
