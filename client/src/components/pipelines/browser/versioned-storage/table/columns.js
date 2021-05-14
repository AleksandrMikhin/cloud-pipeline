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
import classNames from 'classnames';
import {
  Icon
} from 'antd';
import DOCUMENT_TYPES from '../document-types';
import UserName from '../../../../special/UserName';
import displaySize from '../../../../../utils/displaySize';
import displayDate from '../../../../../utils/displayDate';
import styles from './table.css';

const FILES = {
  [DOCUMENT_TYPES.blob]: <Icon type="file" />,
  [DOCUMENT_TYPES.tree]: <Icon type="folder" />,
  navback: <Icon type="folder" />
};

const ACTIONS = {
  [DOCUMENT_TYPES.blob]: (
    <span
      className={styles.rowActions}
    >
      <Icon
        type="download"
        className={styles.action}
        data-action="download"
      />
      <Icon
        type="edit"
        className={styles.action}
        data-action="edit"
      />
      <Icon
        type="delete"
        className={classNames(
          styles.action,
          styles.actionDelete
        )}
        data-action="delete"
      />
    </span>),
  [DOCUMENT_TYPES.tree]: (
    <span
      className={styles.rowActions}
    >
      <Icon
        type="edit"
        className={styles.action}
        data-action="edit"
      />
      <Icon
        type="delete"
        className={classNames(
          styles.action,
          styles.actionDelete
        )}
        data-action="delete"
      />
    </span>)
};

const COLUMNS = [{
  title: 'Name',
  dataIndex: 'name',
  key: 'name',
  className: styles.nameCell,
  render: (name = '', record) => {
    return (
      <div className={styles.cellContent}>
        <span className={styles.fileIcon}>
          {FILES[record.type]}
        </span>
        <span>{name}</span>
      </div>
    );
  }
}, {
  title: 'Size',
  dataIndex: 'size',
  key: 'size',
  className: classNames(styles.noWrapCell, styles.sizeCell),
  render: (size, item) => item.type === DOCUMENT_TYPES.tree
    ? undefined
    : displaySize(size, false)
}, {
  title: 'Revision',
  dataIndex: 'commit',
  key: 'commit',
  className: classNames(styles.noWrapCell, styles.revisionCell)
}, {
  title: 'Date changed',
  dataIndex: 'committer_date',
  key: 'committer_date',
  className: classNames(styles.noWrapCell, styles.dateCell),
  render: date => displayDate(date)
}, {
  title: 'Author',
  dataIndex: 'author',
  key: 'author',
  className: classNames(styles.noWrapCell, styles.authorCell),
  render: author => <UserName userName={author} />
}, {
  title: 'Message',
  dataIndex: 'commit_message',
  key: 'commit_message',
  className: styles.messageCell
}, {
  title: '',
  dataIndex: 'type',
  key: 'actions',
  render: (name = '', record) => ACTIONS[record.type] || null,
  width: 150
}];

export default COLUMNS;
