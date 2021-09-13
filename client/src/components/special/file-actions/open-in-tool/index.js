/*
 * Copyright 2017-2021 EPAM Systems, Inc. (https://www.epam.com/)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

import React from 'react';
import PropTypes from 'prop-types';
import {inject, observer} from 'mobx-react';
import {computed} from 'mobx';
import classNames from 'classnames';
import {
  message,
  Popover,
  Tabs,
  Button,
  Row,
  Icon
} from 'antd';
import ToolsSelector from './tools-selector';
import OpenToolInfo from './open-tool-info';
import FileTools from './file-tools';
import ToolImage from '../../../../models/tools/ToolImage';
import fetchActiveJobs from '../open-in-halo/fetch-active-jobs';
import {PipelineRunner} from '../../../../models/pipelines/PipelineRunner';
import getToolLaunchingOptions
  from '../../../pipelines/launch/utilities/get-tool-launching-options';
import styles from './open-in-tool.css';

const fileToolsRequest = new FileTools();

@inject('dockerRegistries', 'dataStorages', 'preferences', 'awsRegions')
@inject(() => ({
  openInFileTools: fileToolsRequest
}))
@observer
class OpenInToolAction extends React.Component {
  state = {
    modalVisible: false,
    activeJobsFetching: false,
    activeTool: undefined,
    activeJob: undefined
  }

  componentDidMount () {
    const {dockerRegistries, openInFileTools} = this.props;
    dockerRegistries.fetchIfNeededOrWait().then(() => {
      openInFileTools.fetch(this.tools.map(tool => tool.id));
    });
  }

  componentWillUnmount () {
    const {openInFileTools} = this.props;
    openInFileTools.clearCache();
  }

  get fileExtension () {
    const {file: filePath} = this.props;
    if (filePath) {
      const fileParts = filePath.split('/').pop().split('.');
      const extension = fileParts.length > 1 ? fileParts.pop() : undefined;
      return extension;
    }
    return undefined;
  }

  @computed
  get openInFileTools () {
    const {openInFileTools} = this.props;
    if (openInFileTools.loaded) {
      return openInFileTools.tools.map(t => t);
    }
    return undefined;
  }

  @computed
  get tools () {
    const {dockerRegistries} = this.props;
    if (dockerRegistries.loaded) {
      const result = [];
      const {registries = []} = dockerRegistries.value;
      for (let registry of registries) {
        const {groups = []} = registry;
        for (let group of groups) {
          const {tools = []} = group;
          result.push(
            ...(tools.map(tool => ({
              ...tool,
              group
            })))
          );
        }
      }
      return result;
    }
    return [];
  }

  @computed
  get filteredFileTools () {
    if (this.openInFileTools) {
      return this.openInFileTools
        .filter(tool => tool.openInFiles.includes(this.fileExtension))
        .map(tool => this.tools.find(t => t.id === tool.toolId));
    }
    return [];
  }

  @computed
  get activeToolTemplate () {
    const {activeTool} = this.state;
    if (!activeTool) {
      return undefined;
    }
    const tool = this.openInFileTools
      .find(tool => tool.toolId === activeTool.id);
    return (tool || {}).template;
  }

  @computed
  get storage () {
    const {storageId, dataStorages} = this.props;
    if (storageId && dataStorages.loaded) {
      return (dataStorages.value || []).find(s => +(s.id) === +storageId);
    }
    return undefined;
  }

  @computed
  get toolLaunchingStores () {
    const {preferences, awsRegions} = this.props;
    return {
      preferences,
      awsRegions
    };
  }

  getToolById = (id) => {
    return (this.tools || []).find(tool => tool.id === id);
  };

  fetchJobs = () => {
    const {activeTool} = this.state;
    if (!activeTool) {
      return;
    }
    this.setState({
      activeJobsFetching: true,
      activeJob: undefined
    }, () => {
      fetchActiveJobs()
        .then(jobs => {
          const dockerImage = activeTool
            ? new RegExp(`^${activeTool.registry}/${activeTool.image}(:|$)`, 'i')
            : undefined;
          const job = jobs.find(j => dockerImage.test(j.dockerImage));
          if (job) {
            this.setState({
              activeJobsFetching: false,
              activeJob: job
            });
          } else {
            this.setState({
              activeJobsFetching: false,
              activeJob: undefined
            });
          }
        });
    });
  };

  launch = () => {
    const {activeTool} = this.state;
    if (activeTool) {
      const hide = message.loading('Launching...', 0);
      const request = new PipelineRunner();
      getToolLaunchingOptions(this.toolLaunchingStores, activeTool)
        .then((launchPayload) => {
          return request.send({...launchPayload, force: true});
        })
        .then(() => {
          if (request.error) {
            throw new Error(request.error);
          } else if (request.loaded) {
            const run = request.value;
            return Promise.resolve(run);
          }
        })
        .catch(e => {
          message.error(e.message, 5);
          return Promise.resolve();
        })
        .then((run) => {
          hide();
          this.setState({activeJob: run, activeJobIsService: false});
        });
    }
  };

  modalVisibilityChanged = visible => {
    if (visible) {
      this.openModal();
    } else {
      this.closeModal();
    }
  };

  openModal = () => {
    this.setState({
      modalVisible: true
    });
  };

  closeModal = () => {
    this.setState({
      modalVisible: false,
      activeTool: undefined
    });
  };

  onSelectTool = (toolId) => {
    const tool = this.getToolById(toolId);
    if (tool) {
      this.setState({
        activeTool: this.getToolById(toolId),
        activeJobsFetching: true,
        activeJob: undefined
      }, this.fetchJobs);
    }
  };

  clearToolSelection = () => {
    this.setState({
      activeTool: undefined,
      activeJob: undefined,
      activeJobsFetching: false
    });
  };

  renderToolInfo = () => {
    const {
      activeJob,
      activeJobsFetching,
      activeTool
    } = this.state;
    const {file} = this.props;
    return (
      <OpenToolInfo
        template={this.activeToolTemplate}
        activeJob={activeJob}
        activeJobsFetching={activeJobsFetching}
        file={file}
        storage={this.storage}
        tool={activeTool}
        onLaunchClick={this.launch}
      />
    );
  };

  renderModalContent = () => {
    const {activeTool} = this.state;
    const TABS = {
      toolsList: 'toolsList',
      launchTool: 'launchTool'
    };
    const getActiveKey = () => {
      if (!activeTool && this.filteredFileTools.length > 1) {
        return TABS.toolsList;
      }
      return TABS.launchTool;
    };
    return (
      <div>
        <Tabs
          tabPosition="top"
          tabBarStyle={{display: 'none'}}
          style={{height: '100%', width: '100%'}}
          activeKey={getActiveKey()}
        >
          <Tabs.TabPane
            key={TABS.toolsList}
            tab={TABS.toolsList}
          >
            <Row
              type="flex"
              align="middle"
              className={styles.tabHeaderRow}
            >
              <span
                className={styles.tabHeading}
              >
                Select tool to open:
              </span>
            </Row>
            <div className={styles.toolSelectionContainer}>
              {this.filteredFileTools.map(tool => (
                <div
                  key={tool.id}
                  onClick={() => this.onSelectTool(tool.id)}
                  className={styles.toolItem}
                >
                  <img
                    className={styles.toolIcon}
                    src={ToolImage.url(tool.id, tool.iconId)}
                  />
                  {tool.image}
                </div>
              ))}
            </div>
          </Tabs.TabPane>
          <Tabs.TabPane
            key={TABS.launchTool}
            tab={TABS.launchTool}
          >
            {this.filteredFileTools.length > 1 && (
              <Row
                type="flex"
                align="middle"
                className={styles.tabHeaderRow}
              >
                <Button
                  size="small"
                  onClick={() => this.clearToolSelection()}
                >
                  <Icon
                    type="caret-left"
                    style={{marginRight: '5px'}}
                  />
                  <span className={styles.tabHeading}>
                    Return to tool selection
                  </span>
                </Button>
              </Row>
            )}
            {this.renderToolInfo()}
          </Tabs.TabPane>
        </Tabs>
      </div>
    );
  };

  render () {
    const {
      className,
      style,
      titleStyle
    } = this.props;
    const {modalVisible} = this.state;
    if (this.filteredFileTools.length === 0) {
      return null;
    }
    return (
      <Popover
        onVisibleChange={this.modalVisibilityChanged}
        visible={modalVisible}
        trigger={['click']}
        title={false}
        content={this.renderModalContent()}
        placement="left"
        overlayClassName={classNames(
          styles.modalOverlay,
          {[styles.overlayVisible]: !!modalVisible}
        )}
      >
        <ToolsSelector
          className={classNames(styles.link, className)}
          style={style}
          titleStyle={titleStyle}
          onSelectTool={() => {
            if (this.filteredFileTools.length === 1) {
              this.onSelectTool(this.filteredFileTools[0].id);
              this.openModal(this.filteredFileTools[0].id);
            } else {
              this.openModal();
            }
          }}
          tools={this.filteredFileTools}
          singleMode
        />
      </Popover>
    );
  }
}

OpenInToolAction.propTypes = {
  file: PropTypes.string,
  storageId: PropTypes.oneOfType([PropTypes.string, PropTypes.number]),
  className: PropTypes.string,
  style: PropTypes.object,
  titleStyle: PropTypes.object
};

export default OpenInToolAction;
