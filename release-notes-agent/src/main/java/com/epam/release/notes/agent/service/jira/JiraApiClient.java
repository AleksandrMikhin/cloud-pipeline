/*
 * Copyright 2021 EPAM Systems, Inc. (https://www.epam.com/)
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.epam.release.notes.agent.service.jira;

import com.epam.release.notes.agent.entity.jira.JiraIssue;
import com.epam.release.notes.agent.entity.jira.JiraRequest;
import com.epam.release.notes.agent.service.RestApiClient;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.List;

import static java.lang.String.format;

/**
 * A class responsible for getting entities from the Jira.
 */
@Component
public class JiraApiClient implements RestApiClient {

    private static final String ACCEPT_HEADER = "application/json";

    private final JiraApi jiraApi;

    public JiraApiClient(@Value("${jira.base.url}") final String jiraBaseUrl,
                         @Value("${jira.auth.token}") final String jiraToken,
                         @Value("${pipeline.client.connect.timeout}") final long connectTimeout,
                         @Value("${pipeline.client.read.timeout}") final long readTimeout) {
        this.jiraApi = createApi(jiraBaseUrl, format("Bearer %s", jiraToken), JiraApi.class, connectTimeout,
                readTimeout, ACCEPT_HEADER);
    }

    /**
     * Returns {@link JiraIssue} by JQL query
     *
     * @param jiraRequest {@link JiraRequest} a request consisting of a JQL query
     * @return Jira issues
     */
    public List<JiraIssue> getIssue(final JiraRequest jiraRequest) {
        return execute(jiraApi.getIssues(jiraRequest)).getJiraIssues();
    }
}
