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
package com.epam.release.notes.agent.cli;

import com.epam.release.notes.agent.entity.action.Action;
import com.epam.release.notes.agent.entity.github.GitHubIssue;
import com.epam.release.notes.agent.entity.jira.JiraIssue;
import com.epam.release.notes.agent.entity.version.IssueSourcePriority;
import com.epam.release.notes.agent.entity.version.Version;
import com.epam.release.notes.agent.entity.version.VersionStatus;
import com.epam.release.notes.agent.entity.version.VersionStatusInfo;
import com.epam.release.notes.agent.service.action.ActionServiceProvider;
import com.epam.release.notes.agent.service.github.GitHubService;
import com.epam.release.notes.agent.service.jira.JiraIssueService;
import com.epam.release.notes.agent.service.version.ApplicationVersionService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.shell.standard.ShellComponent;
import org.springframework.shell.standard.ShellMethod;

import java.util.Collections;
import java.util.List;

import static java.lang.String.format;

@Slf4j
@ShellComponent
public class ReleaseNotesNotifier {

    private final ApplicationVersionService applicationVersionService;
    private final GitHubService gitHubService;
    private final JiraIssueService jiraIssueService;
    private final ActionServiceProvider actionServiceProvider;
    private final IssueSourcePriority sourcePriority;

    public ReleaseNotesNotifier(final ApplicationVersionService applicationVersionService,
                                final GitHubService gitHubService,
                                final JiraIssueService jiraIssueService,
                                final ActionServiceProvider actionServiceProvider,
                                @Value("${release.notes.agent.issue.source.priority:NONE}")
                                final IssueSourcePriority sourcePriority) {
        this.applicationVersionService = applicationVersionService;
        this.gitHubService = gitHubService;
        this.jiraIssueService = jiraIssueService;
        this.actionServiceProvider = actionServiceProvider;
        this.sourcePriority = sourcePriority;
    }

    @ShellMethod(
            key = "send-release-notes",
            value = "Grabs release notes from GitHub and Jira sources, and sends information to specified users.")
    public void sendReleaseNotes() {

        final Version old = applicationVersionService.loadPreviousVersion();
        final Version current = applicationVersionService.fetchCurrentVersion();

        final VersionStatus versionStatus = applicationVersionService.getVersionStatus(old, current);
        if (versionStatus == VersionStatus.NOT_FOUND) {
            applicationVersionService.storeVersion(current);
            return;
        } else if (versionStatus == VersionStatus.NOT_CHANGED) {
            log.info(format(
                    "The current API version %s has not changed.", current.toString()));
            return;
        }
        log.info(format(
                "Creating release notes report. Old current: %s, new current: %s.",
                old.getSha(), current.getSha()));
        final List<GitHubIssue> gitHubIssues = gitHubService.fetchIssues(current.getSha(), old.getSha());
        final List<JiraIssue> jiraIssues = jiraIssueService.fetchIssues(current.toString());
        log.debug(format("There are: %s github and %s jira issues to process.",
                gitHubIssues.size(), jiraIssues.size()));
        final VersionStatusInfo versionStatusInfo = VersionStatusInfo.builder()
                        .oldVersion(old.toString())
                        .newVersion(current.toString())
                        .jiraIssues(jiraIssues)
                        .gitHubIssues(gitHubIssues)
                        .versionStatus(versionStatus)
                        .sourcePriority(sourcePriority)
                        .build();
        performAction(Collections.singletonList(Action.POST), versionStatusInfo);
        applicationVersionService.storeVersion(current);
    }

    private void performAction(final List<Action> actions, final VersionStatusInfo versionStatusInfo) {
        actions.stream()
                .map(action -> actionServiceProvider.getActionService(action.getName()))
                .forEach(service -> service.process(versionStatusInfo));
    }
}
