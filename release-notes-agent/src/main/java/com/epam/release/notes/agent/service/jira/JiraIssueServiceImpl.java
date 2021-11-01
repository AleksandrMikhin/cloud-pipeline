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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import static java.lang.String.format;

@Service
public class JiraIssueServiceImpl implements JiraIssueService {

    public static final String ID = "id";
    public static final String SUMMARY = "summary";
    public static final String DESCRIPTION = "description";
    public static final String KEY = "key";

    @Autowired
    private JiraApiClient jiraApiClient;

    @Value("${jira.base.url}")
    private String jiraBaseUrl;

    @Value("${jira.version.custom.field.id}")
    private String jiraVersionCustomFieldId;

    @Value("${jira.github.custom.field.id}")
    private String jiraGithubCustomFieldId;

    @Override
    public List<JiraIssue> fetchIssue(final String version) {
        final JiraRequest jiraRequest = JiraRequest.builder()
                .jql(format("cf[%s]~%s", jiraVersionCustomFieldId, version))
                .fields(Arrays.asList(ID, KEY, SUMMARY, DESCRIPTION, format("customfield_%s", jiraGithubCustomFieldId)))
                .build();
        return jiraApiClient.getIssue(jiraRequest).stream()
                .peek(issue -> {
                    issue.setVersion(version);
                    issue.buildUrl(jiraBaseUrl);
                })
                .collect(Collectors.toList());
    }
}
