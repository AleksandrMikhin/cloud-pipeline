/*
 * Copyright 2017-2019 EPAM Systems, Inc. (https://www.epam.com/)
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

import React from 'react';
import PropTypes from 'prop-types';
import {Button, Icon, InputNumber, Modal, Row, Select, TimePicker} from 'antd';
import {observer} from 'mobx-react';
import moment from 'moment-timezone';
import classNames from 'classnames';
import daysOfWeek from './days-of-week';

import {CronConvert, isTimeZoneEqualCurrent, ruleModes} from './cron-convert';

import styles from './run-scheduling.css';

const actions = {
  pause: 'PAUSE',
  resume: 'RESUME',
  run: 'RUN'
};

function getActionName (action) {
  switch (action) {
    case actions.pause: return 'Pause';
    case actions.resume: return 'Resume';
    case actions.run: return 'Run';
    default:
      return action;
  }
}

//  every X days + time
//  every [weekday] + time

@observer
export default class RunScheduleDialog extends React.Component {
  static propTypes = {
    availableActions: PropTypes.arrayOf(PropTypes.oneOf([
      actions.pause,
      actions.resume,
      actions.run
    ])),
    rules: PropTypes.array,
    visible: PropTypes.bool,
    disabled: PropTypes.bool,
    onSubmit: PropTypes.func,
    onClose: PropTypes.func,
    title: PropTypes.node
  };

  static defaultProps = {
    availableActions: [actions.pause, actions.resume],
    title: 'Maintenance'
  };

  static Actions = actions;

  state = {
    rules: [],
    validationErrors: null
  };

  componentDidMount () {
    this.prepareState();
  }

  componentDidUpdate (prevProps, prevState) {
    if ((this.props.rules !== prevProps.rules) ||
      (!prevProps.visible && this.props.visible &&
        this.state.rules && this.state.rules.length > 0)) {
      this.prepareState();
    }
  }

  prepareState = (props = this.props) => {
    const convertRule = ({action, cronExpression, scheduleId, timeZone, removed = false}) => {
      const schedule = CronConvert.convertToRuleScheduleObject(cronExpression);

      return {
        scheduleId,
        timeZone,
        action,
        removed,
        schedule
      };
    };

    const rules = (props.rules || []).map(convertRule);

    this.setState({rules, validationErrors: null});
  };

  validate = () => {
    const {rules} = this.state;
    const validationErrors = [];

    rules.forEach(({removed, schedule: {mode, dayOfWeek}}, index) => {
      if (!removed && mode === ruleModes.weekly &&
        (dayOfWeek.length === 0 || (dayOfWeek.length === 1 && dayOfWeek[0] === '*'))) {
        validationErrors.push({index, message: 'You must choose at least one weekday.'});
      }
    });

    this.setState({validationErrors});
    return !(validationErrors.length > 0);
  };

  onOkClicked = () => {
    const {disabled, onSubmit, onClose} = this.props;
    if (disabled) {
      onClose && onClose();
      return;
    }
    if (this.validate()) {
      const {rules} = this.state;
      const convertRule = ({
        action,
        schedule,
        scheduleId,
        timeZone = moment.tz.guess(),
        removed = false
      }) => {
        const cronExpression = CronConvert.convertToCronString(schedule);

        return {
          scheduleId,
          action,
          timeZone,
          removed,
          cronExpression
        };
      };

      const result = (rules || []).map(convertRule);

      onSubmit && onSubmit(result);
    }
  };

  onAddRow = () => {
    const {availableActions} = this.props;
    const {rules} = this.state;
    const defaultAction = availableActions && availableActions.length > 0
      ? availableActions[0]
      : actions.pause;
    rules.push({
      schedule: {
        mode: ruleModes.daily,
        every: 1,
        time: {
          hours: 0,
          minutes: 0
        }
      },
      action: defaultAction,
      timeZone: moment.tz.guess()
    });
    this.setState({rules});
  };

  onRuleRemove = (index) => {
    const {rules} = this.state;

    if (rules[index]) {
      rules[index].removed = true;
      this.setState({rules});
    }
  };

  onRuleRestore = (index) => {
    const {rules} = this.state;

    if (rules[index]) {
      rules[index].removed = false;
      this.setState({rules});
    }
  };

  renderActionSelector = ({action, removed}, i) => {
    const onActionChange = (value) => {
      const {rules} = this.state;

      rules[i].action = value;
      this.setState({rules});
    };
    const {availableActions} = this.props;
    if (!availableActions || availableActions.length < 2) {
      return null;
    }
    return (
      <div>
        <Select
          disabled={removed || (availableActions && availableActions.length < 2)}
          onSelect={onActionChange}
          value={action}
          size="small"
          style={{width: 80, marginRight: 15}}
        >
          {
            availableActions.map((action) => (
              <Select.Option key={action}>{getActionName(action)}</Select.Option>
            ))
          }
        </Select>
      </div>
    );
  };

  renderScheduleModeSelector = ({removed, schedule}, i) => {
    const onModeChange = (value) => {
      const {rules} = this.state;

      rules[i].schedule.mode = value;
      if (value === ruleModes.daily) {
        rules[i].schedule.every = 1;
        delete rules[i].schedule.dayOfWeek;
      } else {
        rules[i].schedule.dayOfWeek = [];
        delete rules[i].schedule.every;
      }
      this.setState({rules});
    };
    return (
      <div>
        <Select
          disabled={removed}
          onSelect={onModeChange}
          value={schedule.mode}
          size="small"
          style={{width: 80, marginRight: 15}}
        >
          <Select.Option key={ruleModes.daily}>Daily</Select.Option>
          <Select.Option key={ruleModes.weekly}>Weekly</Select.Option>
        </Select>
      </div>
    );
  };

  renderScheduleEverySelector = ({removed, schedule}, i) => {
    if (schedule.mode !== ruleModes.daily) {
      return null;
    }
    const onEveryChange = (value) => {
      const {rules} = this.state;

      rules[i].schedule.every = value;
      this.setState({rules});
    };
    return (
      <div style={{flex: 1, marginRight: 15}}>
        Every
        <InputNumber
          disabled={removed}
          min={1}
          max={31}
          onChange={onEveryChange}
          value={schedule.every}
          size="small"
          style={{margin: '0 10px 0 10px', width: 50}}
        />
        day(s)
      </div>
    );
  };

  renderDayOfWeekSelector = ({removed, schedule}, i) => {
    if (schedule.mode !== ruleModes.weekly) {
      return null;
    }
    const onDayOfWeekSelect = (value) => {
      const {rules} = this.state;

      rules[i].schedule.dayOfWeek.push(value);
      rules[i].schedule.dayOfWeek.sort();
      this.setState({rules});
    };
    const onDayOfWeekDeselect = (value) => {
      const {rules} = this.state;

      const index = rules[i].schedule.dayOfWeek.indexOf(value);
      if (index >= 0) {
        rules[i].schedule.dayOfWeek.splice(index, 1);
        this.setState({rules});
      }
    };
    const {validationErrors} = this.state;
    const [validationError] = (validationErrors || []).filter(({index}) => index === i);

    return (
      <div style={{flex: 1, marginRight: 15}}>
        <Select
          disabled={removed}
          mode="multiple"
          className={classNames({'cp-error': !!validationError})}
          onDeselect={onDayOfWeekDeselect}
          onSelect={onDayOfWeekSelect}
          value={schedule.dayOfWeek || '1'}
          size="small"
          style={{width: 170}}
        >
          {
            daysOfWeek.map(({day, value}) => (
              <Select.Option key={day} value={value.toString()}>
                {day}
              </Select.Option>
            ))
          }
        </Select>
      </div>
    );
  };

  renderTimePicker = ({removed, schedule}, i) => {
    const onTimeChange = (moment, timeString) => {
      const {rules} = this.state;
      const [hours, minutes] = timeString.split(':');

      rules[i].schedule.time = {hours, minutes};
      this.setState({rules});
    };
    const format = 'HH:mm';
    return (
      <div style={{marginRight: 15}}>
        at
        <TimePicker
          allowEmpty={false}
          disabled={removed}
          hideDisabledOptions
          format={format}
          disabledMinutes={() => {
            const disabledMinutes = [];
            for (let i = 1; i < 60; i++) {
              if (i % 5) {
                disabledMinutes.push(i);
              }
            }
            return disabledMinutes;
          }}
          onChange={onTimeChange}
          value={moment(`${schedule.time.hours}:${schedule.time.minutes}`, format)}
          size="small"
          style={{marginLeft: 10, width: 70}}
        />
      </div>
    );
  };

  renderTimezone = (timezone) => (
    <Row className={styles.timezone}>
      timezone: {timezone}
    </Row>
  );

  renderErrorMessage = (i) => {
    const {validationErrors} = this.state;
    const [validationError] = (validationErrors || []).filter(({index}) => index === i);

    if (validationError && validationError.message) {
      return (
        <Row
          className={
            classNames(
              styles.errorRow,
              'cp-error'
            )
          }
          justify="center"
        >
          {validationError.message}
        </Row>
      );
    }

    return null;
  };

  renderRule = (rule, i) => {
    const sameTimezone = isTimeZoneEqualCurrent(rule.timeZone);

    return (
      <Row
        key={i}
        type="flex"
        justify="space-between"
        className={
          classNames(
            styles.ruleRow,
            {
              'cp-even-odd-element': !rule.removed,
              'cp-maintenance-rule-deleted': rule.removed
            }
          )
        }
      >
        <Row type="flex" className={classNames({
          [styles.scheduling]: sameTimezone,
          [styles.schedulingWithTimezone]: !sameTimezone
        })}>
          {this.renderActionSelector(rule, i)}
          {this.renderScheduleModeSelector(rule, i)}
          {this.renderScheduleEverySelector(rule, i)}
          {this.renderDayOfWeekSelector(rule, i)}
          {this.renderTimePicker(rule, i)}
          {
            !rule.removed
              ? (
                <Button
                  onClick={() => { this.onRuleRemove(i); }}
                  shape="circle"
                  icon="delete"
                  size="small"
                  style={{marginRight: 15}}
                  type="danger"
                />
              ) : (
                <Button
                  onClick={() => { this.onRuleRestore(i); }}
                  shape="circle"
                  icon="reload"
                  size="small"
                />
              )
          }
        </Row>
        {!sameTimezone && this.renderTimezone(rule.timeZone)}
        {this.renderErrorMessage(i)}
      </Row>
    );
  };

  render () {
    const {onClose, visible, title} = this.props;
    const {rules} = this.state;

    return (
      <Modal
        title={title}
        onCancel={onClose}
        onOk={this.onOkClicked}
        visible={visible}
        width={600}>
        <Row type="flex" className={styles.rulesContainer}>
          {rules.map(this.renderRule)}
        </Row>
        <Row type="flex" style={{padding: 5}}>
          <Button size="small" onClick={this.onAddRow}><Icon type="plus" /> Add rule</Button>
        </Row>
      </Modal>
    );
  }
}
