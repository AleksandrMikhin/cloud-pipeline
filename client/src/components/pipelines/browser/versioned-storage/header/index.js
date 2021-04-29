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
import {observer} from 'mobx-react';
import {
  Row,
  Col,
  Button,
  Menu,
  Dropdown,
  Icon
} from 'antd';
import localization from '../../../../../utils/localization';
import Breadcrumbs from '../../../../special/Breadcrumbs';
import roleModel from '../../../../../utils/roleModel';
import {ItemTypes} from '../../../model/treeStructureFunctions';
import styles from './header.css';

@localization.localizedComponent
@observer
class VersionedStorageHeader extends localization.LocalizedReactComponent {
  onRunClick = (event) => {
    event && event.stopPropagation();
  }

  onGenerateReportClick = (event) => {
    event && event.stopPropagation();
  }

  onRenameStorage = (name) => {
    const {onRenameStorage} = this.props;
    onRenameStorage && onRenameStorage(name);
  }

  renderActions = () => {
    const {
      actions,
      listingMode,
      issuesPanelOpen,
      metadataPanelOpen
    } = this.props;
    const onSelectDisplayOption = ({key}) => {
      switch (key) {
        case 'metadata':
          metadataPanelOpen
            ? actions.closeMetadataPanel()
            : actions.openMetadataPanel();
          break;
        case 'issues':
          issuesPanelOpen
            ? actions.closeIssuesPanel()
            : actions.openIssuesPanel();
          break;
      }
    };
    const displayOptionsMenuItems = [];
    if (!listingMode) {
      displayOptionsMenuItems.push(
        <Menu.Item
          id={metadataPanelOpen
            ? 'hide-metadata-button'
            : 'show-metadata-button'
          }
          key="metadata"
        >
          <Row
            type="flex"
            justify="space-between"
            align="middle"
          >
            <span>Attributes</span>
            {metadataPanelOpen && (
              <Icon type="check-circle" />
            )}
          </Row>
        </Menu.Item>
      );
      displayOptionsMenuItems.push(
        <Menu.Item
          id={issuesPanelOpen
            ? 'hide-issues-panel-button'
            : 'show-issues-panel-button'
          }
          key="issues"
        >
          <Row
            type="flex"
            justify="space-between"
            align="middle"
          >
            <span>{this.localizedString('Issue')}s</span>
            {issuesPanelOpen && (
              <Icon type="check-circle" />
            )}
          </Row>
        </Menu.Item>
      );
    }
    if (displayOptionsMenuItems.length > 0) {
      const displayOptionsMenu = (
        <Menu onClick={onSelectDisplayOption} style={{width: 125}}>
          {displayOptionsMenuItems}
        </Menu>
      );
      return (
        <Dropdown
          key="display attributes"
          overlay={displayOptionsMenu}
        >
          <Button
            id="display-attributes"
            style={{lineHeight: 1, marginRight: '5px'}}
            size="small"
          >
            <Icon type="appstore" />
          </Button>
        </Dropdown>
      );
    }
    return null;
  };

  renderConfigAction = () => {
    const {readOnly, actions, pipeline} = this.props;
    const menuItems = [];
    const onClick = ({key}) => {
      switch (key) {
        case 'edit':
          actions && actions.openEditPipelineDialog();
          break;
        case 'clone':
          actions && actions.openClonePipelineDialog();
          break;
      }
    };
    if (!readOnly) {
      menuItems.push(
        <Menu.Item
          id="edit-pipeline-button"
          key="edit"
        >
          <Icon type="edit" /> Edit
        </Menu.Item>
      );
    }
    if (!readOnly && roleModel.isOwner(pipeline.value)) {
      menuItems.push(
        <Menu.Item
          key="clone"
          id="clone-pipeline-button"
        >
          <Icon type="copy" /> Clone
        </Menu.Item>
      );
    }
    const overlay = (
      <Menu
        selectedKeys={[]}
        onClick={onClick}
        style={{width: 100}}>
        {menuItems}
      </Menu>
    );
    return (
      <Dropdown
        placement="bottomRight"
        key="edit"
        overlay={overlay}
      >
        <Button
          key="edit"
          id="edit-pipeline-menu-button"
          style={{lineHeight: 1}}
          size="small"
        >
          <Icon type="setting" />
        </Button>
      </Dropdown>
    );
  };

  render () {
    const {
      pipeline,
      pipelineId,
      readOnly
    } = this.props;
    if (!pipeline || !pipelineId) {
      return null;
    }
    return (
      <div className={styles.headerContainer}>
        <Row
          type="flex"
          justify="space-between"
          align="middle"
          style={{minHeight: 41}}
        >
          <Col className={styles.breadcrumbs}>
            <Breadcrumbs
              id={parseInt(pipelineId)}
              type={ItemTypes.versionedStorage}
              readOnlyEditableField={!roleModel.writeAllowed(pipeline.value) || readOnly}
              textEditableField={pipeline.value.name}
              onSaveEditableField={this.onRenameStorage}
              editStyleEditableField={{flex: 1}}
              icon="share-alt"
              iconClassName={styles.versionedStorageIcon}
              lock={pipeline.value.locked}
              subject={pipeline.value}
            />
          </Col>
          <Col className={styles.headerActions}>
            <Row type="flex" justify="end">
              <Button
                size="small"
                onClick={(event) => this.onRunClick(event)}
                className={styles.controlBtn}
                disabled
              >
                RUN
              </Button>
              <Button
                size="small"
                type="primary"
                onClick={(event) => this.onGenerateReportClick(event)}
                className={styles.controlBtn}
                disabled
              >
                Generate report
              </Button>
              {this.renderActions()}
              {this.renderConfigAction()}
            </Row>
          </Col>
        </Row>
        <Row type="flex">
          {pipeline.value.description}
        </Row>
      </div>
    );
  }
}

VersionedStorageHeader.propTypes = {
  pipeline: PropTypes.object,
  pipelineId: PropTypes.oneOfType([
    PropTypes.string,
    PropTypes.number
  ]),
  onRenameStorage: PropTypes.func,
  actions: PropTypes.shape({
    openIssuesPanel: PropTypes.func,
    closeIssuesPanel: PropTypes.func,
    openMetadataPanel: PropTypes.func,
    closeMetadataPanel: PropTypes.func,
    openEditPipelineDialog: PropTypes.func,
    openClonePipelineDialog: PropTypes.func
  }),
  listingMode: PropTypes.bool,
  readOnly: PropTypes.bool,
  issuesPanelOpen: PropTypes.bool,
  metadataPanelOpen: PropTypes.bool
};

export default VersionedStorageHeader;
