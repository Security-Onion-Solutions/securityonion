# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

import errno
import fcntl
import importlib.util
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from importlib.machinery import SourceFileLoader
from unittest.mock import MagicMock, patch

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, 'so-push-drainer')
_loader = SourceFileLoader('so_push_drainer', SCRIPT)
_spec = importlib.util.spec_from_loader('so_push_drainer', _loader)
drainer = importlib.util.module_from_spec(_spec)

# salt is not installed where these tests run; the drainer only needs salt.client.Caller and CkMinions.
# Mocked only while the drainer loads: run from the repo root, 'salt' is this repo's salt/ directory.
_salt = MagicMock()
with patch.dict(sys.modules, {'salt': _salt, 'salt.client': _salt.client, 'salt.config': _salt.config,
                              'salt.utils': _salt.utils, 'salt.utils.minions': _salt.utils.minions}):
    _loader.exec_module(drainer)

MASTER = 'manager.localdomain_master'
JID = '20260930171554259426'
ASYNC_STDERR = ('[WARNING ] Running in asynchronous mode. Results of this execution may be collected '
                'by attaching to the master event bus or by examining the master job cache, if '
                'configured. This execution is running under tag salt/run/{}\n'.format(JID))
NOT_PENDING = ' and not G@first_highstate_pending:True'
PENDING_TGT = 'G@first_highstate_pending:True'
CONFLICT = ('The function "state.sls" is running as PID 372218 and was started at '
            '2026, Sep 30 17:15:40.466233 with jid 20260930171540466233')


def _orch_ret(steps, success=True):
    return {MASTER: {
        'fun': 'runner.state.orchestrate',
        'jid': JID,
        'return': {'data': {MASTER: steps}, 'outputter': 'highstate', 'retcode': 0 if success else 1},
        'success': success,
    }}


REFRESH_STEP = {
    'salt_|-refresh_pillar_1_|-saltutil.refresh_pillar_|-function': {
        '__id__': 'refresh_pillar_1', 'result': True,
        'changes': {'ret': {'manager_standalone': True}},
        'comment': 'Function ran successfully.',
    },
}

CONFLICT_RET = _orch_ret(dict(REFRESH_STEP, **{
    'salt_|-apply_soc_1_|-apply_soc_1_|-state': {
        '__id__': 'apply_soc_1', 'result': False,
        'changes': {'out': 'highstate', 'ret': {'manager_standalone': [CONFLICT]}},
        'comment': 'Run failed on minions: manager_standalone',
    },
}), success=False)

STATE_FAIL_RET = _orch_ret({
    'salt_|-apply_hydra_1_|-apply_hydra_1_|-state': {
        '__id__': 'apply_hydra_1', 'result': False,
        'changes': {'out': 'highstate', 'ret': {'manager_standalone': {
            'test_|-no_license_|-no_license_|-fail_without_changes': {
                '__id__': 'hydra.enabled_no_license_detected', 'result': False,
                'comment': 'This is a feature supported only for customers with a valid license.',
            },
            'file_|-hydra_conf_|-/opt/so/conf/hydra_|-managed': {'result': True, 'comment': 'ok'},
        }}},
        'comment': 'Run failed on minions: manager_standalone',
    },
}, success=False)

RAISED = ('An exception occurred in this state: Traceback (most recent call last):\n'
          '  File "salt/client/__init__.py", line 1934, in pub\n'
          '    raise AuthenticationError(err_msg)\n'
          'salt.exceptions.AuthenticationError: Authentication error occurred.\n')

RAISED_RET = _orch_ret(dict(REFRESH_STEP, **{
    'salt_|-apply_hydra_1_|-apply_hydra_1_|-state': {
        '__id__': 'apply_hydra_1', 'result': False, 'changes': {}, 'comment': RAISED,
    },
}), success=False)

LOST_RET = _orch_ret(dict(REFRESH_STEP, **{
    'salt_|-apply_soc_1_|-apply_soc_1_|-state': {
        '__id__': 'apply_soc_1', 'result': False,
        'changes': {'out': 'highstate', 'ret': {'manager_standalone': {}}},
        'comment': 'Run failed on minions: manager_standalone',
    },
}), success=False)

LOST_AND_FAILED_RET = _orch_ret({
    'salt_|-apply_soc_1_|-apply_soc_1_|-state': {
        '__id__': 'apply_soc_1', 'result': False,
        'changes': {'out': 'highstate', 'ret': {'manager_standalone': {}, 'sensor1_sensor': [CONFLICT]}},
        'comment': 'Run failed on minions: manager_standalone, sensor1_sensor',
    },
}, success=False)

SUCCESS_RET = _orch_ret(dict(REFRESH_STEP, **{
    'salt_|-apply_telegraf_1_|-apply_telegraf_1_|-state': {
        '__id__': 'apply_telegraf_1', 'result': True,
        'changes': {'out': 'highstate', 'ret': {'manager_standalone': {
            'file_|-tgrafconf_|-/opt/so/conf/telegraf/etc/telegraf.conf_|-managed': {'result': True},
        }}},
        'comment': 'States ran successfully.',
    },
}))


class DrainerTestCase(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.pending = os.path.join(self.tmpdir, 'push_pending')
        self.dispatched = os.path.join(self.tmpdir, 'push_dispatched')
        os.makedirs(self.pending)
        for name, value in (
            ('PENDING_DIR', self.pending),
            ('LOCK_FILE', os.path.join(self.pending, '.lock')),
            ('DISPATCHED_DIR', self.dispatched),
            ('LOG_FILE', os.path.join(self.tmpdir, 'log', 'so-push-drainer.log')),
        ):
            patcher = patch.object(drainer, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.log = MagicMock()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def write_json(self, directory, name, data):
        os.makedirs(directory, exist_ok=True)
        path = os.path.join(directory, name)
        with open(path, 'w') as f:
            if isinstance(data, str):
                f.write(data)
            else:
                json.dump(data, f)
        return path

    def logged(self, level):
        return ' '.join(c.args[0] % c.args[1:] for c in getattr(self.log, level).call_args_list)


class TestHelpers(DrainerTestCase):

    def test_make_logger_adds_handler_once(self):
        logger = logging.getLogger('so-push-drainer')

        def close_handlers():
            for handler in logger.handlers:
                handler.close()
            logger.handlers.clear()

        self.addCleanup(close_handlers)
        logger.handlers.clear()
        self.assertIs(drainer._make_logger(), logger)
        drainer._make_logger()
        self.assertEqual(len(logger.handlers), 1)
        self.assertTrue(os.path.isdir(os.path.dirname(drainer.LOG_FILE)))

    def test_load_push_cfg(self):
        with patch.object(drainer.salt.client, 'Caller') as caller:
            caller.return_value.cmd.return_value = {'enabled': False}
            self.assertEqual(drainer._load_push_cfg(), {'enabled': False})
            caller.return_value.cmd.return_value = 'garbage'
            self.assertEqual(drainer._load_push_cfg(), {})

    def test_read_intent(self):
        good = self.write_json(self.pending, 'good.json', {'a': 1})
        bad = self.write_json(self.pending, 'bad.json', '{nope')
        self.assertEqual(drainer._read_intent(good, self.log), {'a': 1})
        self.assertIsNone(drainer._read_intent(bad, self.log))
        with patch('builtins.open', side_effect=RuntimeError('boom')):
            self.assertIsNone(drainer._read_intent(good, self.log))
        self.log.exception.assert_called_once()

    def test_dedupe_actions(self):
        actions = [
            'not a dict',
            {'state': 'soc'},
            {'state': 'soc', 'tgt': '*'},
            {'state': 'soc', 'tgt': '*', 'tgt_type': 'compound'},
            {'highstate': True, 'tgt': '*'},
            {'state': 'soc', 'tgt': 'node1', 'tgt_type': 'glob'},
        ]
        self.assertEqual(drainer._dedupe_actions(actions), [actions[2], actions[4], actions[5]])

    def test_trim(self):
        self.assertEqual(drainer._trim('  text \n'), 'text')
        self.assertEqual(drainer._trim(['a']), '["a"]')
        self.assertEqual(drainer._trim(None), 'null')
        self.assertEqual(drainer._trim('x' * 600), 'x' * drainer.TEXT_LIMIT + '...')

    def test_trim_traceback(self):
        comment = ('An exception occurred in this state: Traceback (most recent call last):\n'
                   '  File "salt/client/__init__.py", line 1934, in pub\n'
                   '    raise AuthenticationError(err_msg)\n'
                   'salt.exceptions.AuthenticationError: Authentication error occurred.\n')
        self.assertEqual(drainer._trim(comment), 'An exception occurred in this state: '
                         'salt.exceptions.AuthenticationError: Authentication error occurred.')
        self.assertEqual(drainer._trim('line one\n  line two\n'), 'line one line two')

    def test_unlink(self):
        drainer._unlink(os.path.join(self.tmpdir, 'missing'), self.log)
        self.log.exception.assert_not_called()
        drainer._unlink(self.tmpdir, self.log)
        self.log.exception.assert_called_once()

    def test_master_settling(self):
        pidfile = os.path.join(self.tmpdir, 'salt-master.pid')
        now = time.time()
        with patch.object(drainer, 'MASTER_PIDFILE', pidfile):
            self.assertFalse(drainer._master_settling(now))
            self.write_json(self.tmpdir, 'salt-master.pid', '1100')
            for age, settling in ((0, True), (drainer.MASTER_SETTLE_SECONDS - 1, True),
                                  (drainer.MASTER_SETTLE_SECONDS, False), (-60, False)):
                os.utime(pidfile, (now - age, now - age))
                self.assertIs(drainer._master_settling(now), settling, age)


class TestDispatch(DrainerTestCase):

    def run_dispatch(self, **kwargs):
        with patch.object(drainer.subprocess, 'run', **kwargs) as run:
            jid = drainer._dispatch([{'state': 'soc', 'tgt': '*'}], self.log)
        return jid, run

    def test_jid_parsed_from_stderr(self):
        jid, run = self.run_dispatch(return_value=MagicMock(stdout='', stderr=ASYNC_STDERR))
        self.assertEqual(jid, JID)
        cmd = run.call_args[0][0]
        self.assertEqual(cmd[:3], ['salt-run', 'state.orchestrate', 'orch.push_batch'])
        self.assertIn('--async', cmd)

    def test_jid_parsed_from_stdout(self):
        jid, _ = self.run_dispatch(return_value=MagicMock(stdout=ASYNC_STDERR, stderr=None))
        self.assertEqual(jid, JID)

    def test_no_jid(self):
        jid, _ = self.run_dispatch(return_value=MagicMock(stdout='unexpected output', stderr=None))
        self.assertEqual(jid, '')
        self.assertIn('output=unexpected output', self.logged('warning'))

    def test_failures_return_none(self):
        for exc in (subprocess.CalledProcessError(1, 'salt-run', 'out', 'err'),
                    subprocess.TimeoutExpired('salt-run', 60),
                    RuntimeError('boom')):
            jid, _ = self.run_dispatch(side_effect=exc)
            self.assertIsNone(jid)

    def test_record_dispatch(self):
        drainer._record_dispatch(JID, [{'state': 'soc'}], ['audit:soc.config.licenseKey'], self.log)
        with open(os.path.join(self.dispatched, JID + '.json')) as f:
            record = json.load(f)
        self.assertEqual(record['jid'], JID)
        self.assertEqual(record['paths'], ['audit:soc.config.licenseKey'])
        self.assertIn('dispatched_at', record)

    def test_record_dispatch_errors(self):
        with patch.object(drainer.os, 'makedirs', side_effect=OSError('ro')):
            drainer._record_dispatch(JID, [], [], self.log)
        drainer._record_dispatch(JID, [object()], [], self.log)
        self.assertEqual(self.log.exception.call_count, 2)
        self.assertFalse(os.path.exists(os.path.join(self.dispatched, JID + '.json')))


class TestResults(DrainerTestCase):

    def test_lookup_jid(self):
        with patch.object(drainer.subprocess, 'run') as run:
            run.return_value = MagicMock(stdout=json.dumps(SUCCESS_RET))
            self.assertEqual(drainer._lookup_jid(JID, self.log), SUCCESS_RET)
            self.assertEqual(run.call_args[0][0], ['salt-run', 'jobs.lookup_jid', JID, '--out=json'])
            run.return_value = MagicMock(stdout='')
            self.assertEqual(drainer._lookup_jid(JID, self.log), {})
            run.return_value = MagicMock(stdout='not json')
            self.assertIsNone(drainer._lookup_jid(JID, self.log))
            run.side_effect = subprocess.TimeoutExpired('salt-run', 60)
            self.assertIsNone(drainer._lookup_jid(JID, self.log))

    def test_minion_failure_shapes(self):
        self.assertEqual(drainer._minion_failure([CONFLICT]), json.dumps([CONFLICT]))
        self.assertEqual(drainer._minion_failure('Rendering SLS failed'), 'Rendering SLS failed')
        self.assertEqual(drainer._minion_failure(True), '')
        self.assertEqual(drainer._minion_failure({'a': {'result': True}}), '')
        self.assertEqual(drainer._minion_failure({}), drainer.NO_RETURN)

    def test_orch_failures_lost(self):
        self.assertEqual(drainer._orch_failures(LOST_RET), [
            'apply_soc_1: Run failed on minions: manager_standalone',
            'manager_standalone: no return received',
        ])

    def test_orch_failures_conflict(self):
        failures = drainer._orch_failures(CONFLICT_RET)
        self.assertEqual(failures[0], 'apply_soc_1: Run failed on minions: manager_standalone')
        self.assertIn('manager_standalone', failures[1])
        self.assertIn('is running as PID 372218', failures[1])
        self.assertEqual(len(failures), 2)

    def test_orch_failures_failed_state(self):
        failures = drainer._orch_failures(STATE_FAIL_RET)
        self.assertEqual(len(failures), 2)
        self.assertIn('hydra.enabled_no_license_detected: This is a feature', failures[1])
        self.assertNotIn('hydra_conf', failures[1])

    def test_orch_failures_success(self):
        self.assertEqual(drainer._orch_failures(SUCCESS_RET), [])

    def test_orch_failures_render_error(self):
        ret = {MASTER: {'return': {'data': {MASTER: ['Rendering SLS failed']}}, 'success': False}}
        self.assertEqual(drainer._orch_failures(ret), ['["Rendering SLS failed"]'])

    def test_orch_failures_not_a_dict(self):
        self.assertEqual(drainer._orch_failures(['No minions matched']), ['["No minions matched"]'])
        self.assertEqual(drainer._orch_failures('Runner error'), ['Runner error'])

    def test_orch_failures_data_not_a_dict(self):
        ret = {MASTER: {'return': {'data': ["Rendering SLS 'orch.push_batch' failed"]}, 'success': False}}
        self.assertEqual(drainer._orch_failures(ret), ['["Rendering SLS \'orch.push_batch\' failed"]'])

    def test_orch_failures_odd_changes(self):
        for changes in ('Run failed', {'ret': ['manager_standalone']}):
            ret = _orch_ret({'salt_|-apply_soc_1_|-apply_soc_1_|-state': {
                '__id__': 'apply_soc_1', 'result': False, 'changes': changes, 'comment': 'Run failed on minions',
            }}, success=False)
            self.assertEqual(drainer._orch_failures(ret), ['apply_soc_1: Run failed on minions'])

    def test_orch_failures_unparsed(self):
        self.assertEqual(drainer._orch_failures({MASTER: 'odd'}), [])
        ret = {MASTER: {'return': 'Exception occurred', 'success': False}}
        self.assertEqual(drainer._orch_failures(ret), ['orchestration reported failure: Exception occurred'])

    def test_result_unknown(self):
        self.assertTrue(drainer._result_unknown(RAISED_RET))
        self.assertTrue(drainer._result_unknown(LOST_RET))
        changed = json.loads(json.dumps(LOST_RET))
        changed[MASTER]['return']['data'][MASTER]['salt_|-apply_soc_1_|-apply_soc_1_|-state']['changes']['ret'][
            'sensor1_sensor'] = {'file_|-a_|-a_|-managed': {'result': True, 'changes': {'diff': 'x'}}}
        self.assertTrue(drainer._result_unknown(changed))
        odd = _orch_ret({'salt_|-apply_soc_1_|-apply_soc_1_|-state': {
            '__id__': 'apply_soc_1', 'result': False, 'changes': 'Run failed', 'comment': 'Run failed on minions',
        }}, success=False)
        self.assertFalse(drainer._result_unknown(odd))
        for ret in (CONFLICT_RET, STATE_FAIL_RET, SUCCESS_RET, LOST_AND_FAILED_RET, ['No minions matched'],
                    {MASTER: 'odd'},
                    {MASTER: {'return': {'data': {MASTER: ['Rendering SLS failed']}}, 'success': False}}):
            self.assertFalse(drainer._result_unknown(ret), ret)
        mixed = _orch_ret(dict(RAISED_RET[MASTER]['return']['data'][MASTER],
                               **CONFLICT_RET[MASTER]['return']['data'][MASTER]), success=False)
        self.assertFalse(drainer._result_unknown(mixed))

    def record(self, jid, age, now):
        return self.write_json(self.dispatched, jid + '.json', {
            'jid': jid, 'dispatched_at': now - age, 'actions': [], 'paths': ['audit:' + jid],
        })

    def test_check_dispatched(self):
        now = time.time()
        results = {
            '1_failed': CONFLICT_RET,
            '2_ok': SUCCESS_RET,
            '3_pending': {},
            '4_expired': None,
            '6_unknown': RAISED_RET,
        }
        young = self.record('0_young', 5, now)
        paths = {jid: self.record(jid, 60, now) for jid in results}
        paths['4_expired'] = self.record('4_expired', drainer.RESULT_MAX_AGE + 1, now)
        bad = self.write_json(self.dispatched, '5_bad.json', '{nope')
        with patch.object(drainer, '_lookup_jid', side_effect=lambda jid, log: results[jid]):
            drainer._check_dispatched(self.log, now)

        self.assertTrue(os.path.exists(young))
        with open(paths['3_pending']) as f:
            self.assertEqual(json.load(f)['checked_at'], now)
        for jid in ('1_failed', '2_ok', '4_expired', '6_unknown'):
            self.assertFalse(os.path.exists(paths[jid]), jid)
        self.assertFalse(os.path.exists(bad))
        self.assertIn('push failed jid=1_failed', self.logged('error'))
        self.assertIn('is running as PID 372218', self.logged('error'))
        self.assertIn('push succeeded jid=2_ok', self.logged('info'))
        self.assertIn('no result for jid=4_expired', self.logged('warning'))
        self.assertIn('push result unknown jid=6_unknown', self.logged('warning'))
        self.assertIn('AuthenticationError: Authentication error occurred.', self.logged('warning'))
        self.assertNotIn('6_unknown', self.logged('error'))

    def test_check_dispatched_lost(self):
        now = time.time()
        results = {'1_lost': LOST_RET, '2_lost_and_failed': LOST_AND_FAILED_RET}
        paths = [self.record(jid, 60, now) for jid in results]
        with patch.object(drainer, '_lookup_jid', side_effect=lambda jid, log: results[jid]):
            drainer._check_dispatched(self.log, now)

        for path in paths:
            self.assertFalse(os.path.exists(path), path)
        self.assertIn('push result unknown jid=1_lost', self.logged('warning'))
        self.assertIn('manager_standalone: no return received', self.logged('warning'))
        self.assertNotIn('1_lost', self.logged('error'))
        self.assertIn('push failed jid=2_lost_and_failed', self.logged('error'))
        self.assertIn('is running as PID 372218', self.logged('error'))

    def test_check_dispatched_survives_bad_result(self):
        now = time.time()
        bad = self.record('1_bad', 60, now)
        good = self.record('2_ok', 60, now)

        def orch_failures(ret):
            if ret == 'boom':
                raise ValueError('unexpected shape')
            return []

        with patch.object(drainer, '_lookup_jid', side_effect=lambda jid, log: 'boom' if jid == '1_bad' else SUCCESS_RET), \
                patch.object(drainer, '_orch_failures', side_effect=orch_failures):
            drainer._check_dispatched(self.log, now)
        self.assertFalse(os.path.exists(bad))
        self.assertFalse(os.path.exists(good))
        self.log.exception.assert_called_once()
        self.assertIn('jid=1_bad', self.log.exception.call_args[0][0] % self.log.exception.call_args[0][1:])
        self.assertIn('push succeeded jid=2_ok', self.logged('info'))

    def test_check_dispatched_drops_malformed_record(self):
        now = time.time()
        bad_dispatched = self.write_json(self.dispatched, '1_bad.json', {'jid': '1_bad', 'dispatched_at': 'soon'})
        bad_checked = self.write_json(self.dispatched, '2_bad.json', {
            'jid': '2_bad', 'dispatched_at': now - 60, 'checked_at': None,
        })
        good = self.record('3_ok', 60, now)
        with patch.object(drainer, '_lookup_jid', return_value=SUCCESS_RET) as lookup:
            drainer._check_dispatched(self.log, now)
        for path in (bad_dispatched, bad_checked, good):
            self.assertFalse(os.path.exists(path), path)
        self.assertEqual([c.args[0] for c in lookup.call_args_list], ['3_ok'])
        self.assertIn('malformed record for jid=1_bad', self.logged('warning'))
        self.assertIn('malformed record for jid=2_bad', self.logged('warning'))
        self.assertIn('push succeeded jid=3_ok', self.logged('info'))

    def test_recheck_delay(self):
        self.assertEqual(drainer._recheck_delay(10), drainer.RESULT_CHECK_DELAY)
        self.assertEqual(drainer._recheck_delay(400), 100)
        self.assertEqual(drainer._recheck_delay(drainer.RESULT_MAX_AGE), drainer.RESULT_RECHECK_MAX)

    def test_check_dispatched_limit_rotates(self):
        now = time.time()
        limit = drainer.RESULT_CHECKS_PER_PASS
        jids = ['{:02d}'.format(i) for i in range(limit + 2)]
        for jid in jids:
            self.record(jid, 60, now)
        with patch.object(drainer, '_lookup_jid', return_value={}) as lookup:
            drainer._check_dispatched(self.log, now)
            self.assertEqual([c.args[0] for c in lookup.call_args_list], jids[:limit])
            lookup.reset_mock()
            drainer._check_dispatched(self.log, now + 40)
        self.assertEqual([c.args[0] for c in lookup.call_args_list], jids[limit:] + jids[:limit - 2])

    def test_check_dispatched_not_blocked_by_running(self):
        now = time.time()
        for i in range(drainer.RESULT_CHECKS_PER_PASS):
            self.record('1_running{}'.format(i), 600, now)
        done = self.record('2_done', 60, now)

        def lookup(jid, log):
            return SUCCESS_RET if jid == '2_done' else {}

        with patch.object(drainer, '_lookup_jid', side_effect=lookup) as lookup_jid:
            drainer._check_dispatched(self.log, now)
            self.assertTrue(os.path.exists(done))
            lookup_jid.reset_mock()
            drainer._check_dispatched(self.log, now + 15)
        self.assertEqual([c.args[0] for c in lookup_jid.call_args_list], ['2_done'])
        self.assertFalse(os.path.exists(done))
        self.assertIn('push succeeded jid=2_done', self.logged('info'))


class TestTargeted(DrainerTestCase):

    def setUp(self):
        super().setUp()
        self.ckminions = MagicMock()
        patcher = patch.object(drainer.salt.utils.minions, 'CkMinions', return_value=self.ckminions)
        self.CkMinions = patcher.start()
        self.addCleanup(patcher.stop)

    def test_skip_pending(self):
        self.assertEqual(drainer._skip_pending({'state': 'soc', 'tgt': 'G@role:so-eval or G@role:so-manager'}),
                         {'state': 'soc', 'tgt': '( G@role:so-eval or G@role:so-manager )' + NOT_PENDING})
        self.assertEqual(drainer._skip_pending({'highstate': True, 'tgt': '*', 'tgt_type': 'compound'}),
                         {'highstate': True, 'tgt': '( * )' + NOT_PENDING, 'tgt_type': 'compound'})
        listed = {'state': 'soc', 'tgt': 'manager_manager', 'tgt_type': 'list'}
        self.assertEqual(drainer._skip_pending(listed), listed)

    def test_drops_unmatched(self):
        sensor = '( G@role:so-sensor )' + NOT_PENDING
        heavynode = '( G@role:so-heavynode )' + NOT_PENDING
        idh = '( G@role:so-idh )' + NOT_PENDING
        matches = {sensor: ['sensor_sensor'], 'manager_manager': ['manager_manager']}
        self.ckminions.check_minions.side_effect = lambda tgt, tgt_type: {'minions': matches.get(tgt, [])}
        actions = [
            {'state': 'strelka', 'tgt': 'G@role:so-sensor'},
            {'state': 'suricata', 'tgt': 'G@role:so-heavynode'},
            {'highstate': True, 'tgt': 'G@role:so-idh'},
            {'state': 'soc', 'tgt': 'manager_manager', 'tgt_type': 'list'},
        ]
        self.assertEqual(drainer._targeted(actions, self.log), ([{'state': 'strelka', 'tgt': sensor}, actions[3]], {}))
        self.CkMinions.assert_called_once()
        self.assertEqual([c.args for c in self.ckminions.check_minions.call_args_list], [
            (PENDING_TGT, 'compound'), (sensor, 'compound'), (heavynode, 'compound'), (idh, 'compound'),
            ('manager_manager', 'list'),
        ])
        info = self.logged('info')
        self.assertIn('skipping suricata: no minions match tgt=G@role:so-heavynode', info)
        self.assertIn('skipping highstate: no minions match tgt=G@role:so-idh', info)
        self.assertNotIn('strelka', info)

    def test_list_target_unmatched(self):
        self.ckminions.check_minions.return_value = {'minions': []}
        actions = [{'state': 'soc', 'tgt': 'gone_manager', 'tgt_type': 'list'}]
        self.assertEqual(drainer._targeted(actions, self.log), ([], {}))
        self.assertEqual([c.args for c in self.ckminions.check_minions.call_args_list], [
            (PENDING_TGT, 'compound'), ('gone_manager', 'list'),
        ])
        info = self.logged('info')
        self.assertIn('skipping soc: no minions match tgt=gone_manager', info)
        self.assertNotIn('first highstate', info)

    def test_narrowed_match_checks_once(self):
        narrowed = '( G@role:so-sensor )' + NOT_PENDING
        self.ckminions.check_minions.side_effect = lambda tgt, tgt_type: {
            'minions': [] if tgt == PENDING_TGT else ['sensor_sensor']}
        actions = [{'state': 'suricata', 'tgt': 'G@role:so-sensor'}]
        self.assertEqual(drainer._targeted(actions, self.log), ([{'state': 'suricata', 'tgt': narrowed}], {}))
        self.assertEqual([c.args for c in self.ckminions.check_minions.call_args_list], [
            (PENDING_TGT, 'compound'), (narrowed, 'compound'),
        ])

    def test_pending_set_empty_no_extra_calls(self):
        self.ckminions.check_minions.side_effect = lambda tgt, tgt_type: {
            'minions': [] if tgt == PENDING_TGT else ['sensor_sensor']}
        actions = [
            {'state': 'suricata', 'tgt': 'G@role:so-sensor'},
            {'highstate': True, 'tgt': '*'},
            {'state': 'soc', 'tgt': 'manager_manager', 'tgt_type': 'list'},
        ]
        targeted, kept = drainer._targeted(actions, self.log)
        self.assertEqual(len(targeted), 3)
        self.assertEqual(kept, {})
        tgts = [c.args[0] for c in self.ckminions.check_minions.call_args_list]
        self.assertEqual(tgts.count(PENDING_TGT), 1)
        self.assertEqual(len(tgts), 1 + len(actions))
        self.assertNotIn('G@role:so-sensor', tgts)

    def test_list_target_not_kept(self):
        self.ckminions.check_minions.side_effect = lambda tgt, tgt_type: {'minions': ['manager_manager']}
        actions = [{'state': 'soc', 'tgt': 'manager_manager', 'tgt_type': 'list'}]
        self.assertEqual(drainer._targeted(actions, self.log), (actions, {}))
        self.assertEqual([c.args for c in self.ckminions.check_minions.call_args_list], [
            (PENDING_TGT, 'compound'), ('manager_manager', 'list'),
        ])

    def test_original_check_error_keeps_action(self):
        narrowed = '( G@role:so-sensor )' + NOT_PENDING
        results = {PENDING_TGT: {'minions': ['sensor_new']}, narrowed: {'minions': []}}

        def check(tgt, tgt_type):
            if tgt not in results:
                raise RuntimeError('boom')
            return results[tgt]
        self.ckminions.check_minions.side_effect = check
        actions = [{'state': 'suricata', 'tgt': 'G@role:so-sensor'}]
        self.assertEqual(drainer._targeted(actions, self.log), ([{'state': 'suricata', 'tgt': narrowed}], {}))
        self.log.exception.assert_called_once()

    def test_master_config_error_keeps_actions(self):
        actions = [{'state': 'soc', 'tgt': '*'}]
        with patch.object(drainer.salt.config, 'master_config', side_effect=OSError('no config')):
            self.assertEqual(drainer._targeted(actions, self.log), ([{'state': 'soc', 'tgt': '( * )' + NOT_PENDING}], {}))
        self.log.exception.assert_called_once()
        self.CkMinions.assert_not_called()

    def test_check_error_keeps_action(self):
        actions = [{'state': 'soc', 'tgt': 'G@role:'}]
        self.ckminions.check_minions.side_effect = RuntimeError('bad target')
        self.assertEqual(drainer._targeted(actions, self.log), ([{'state': 'soc', 'tgt': '( G@role: )' + NOT_PENDING}], {}))
        self.log.exception.assert_called_once()

    def test_pending_minions_error(self):
        self.ckminions.check_minions.side_effect = RuntimeError('cache unavailable')
        self.assertEqual(drainer._pending_minions(self.ckminions, self.log), set())
        self.assertIn('cannot list nodes still in their first highstate', self.logged('warning'))
        self.assertIn('cache unavailable', self.logged('warning'))

    def test_still_pending(self):
        cache = {'minions/a': {'grains': {drainer.PENDING_GRAIN: True}}, 'minions/b': {'grains': {'role': 'so-sensor'}},
                 'minions/c': {}}
        self.ckminions.cache.fetch.side_effect = lambda bank, key: cache[bank]
        self.assertEqual(drainer._still_pending(self.ckminions, {'a', 'b', 'c'}, self.log), {'a', 'c'})
        self.assertEqual({c.args[1] for c in self.ckminions.cache.fetch.call_args_list}, {'data'})
        self.log.warning.assert_not_called()

    def test_still_pending_lookup_error(self):
        self.ckminions.cache.fetch.side_effect = OSError('cache read failed')
        self.assertEqual(drainer._still_pending(self.ckminions, {'a'}, self.log), {'a'})
        self.assertIn('cannot read the cached grains of a', self.logged('warning'))


class FakeCkMinions:
    """Evaluates the compound targets the drainer builds against a fixed set of role targets."""

    def __init__(self):
        self.targets = {}
        self.accepted = set()
        self.pending = set()
        self.grains = {}
        self.fetch_error = None
        self.cache = MagicMock()
        self.cache.fetch.side_effect = self.fetch

    def fetch(self, bank, key):
        if self.fetch_error:
            raise self.fetch_error
        node = bank.split('/', 1)[1]
        return {'grains': self.grains[node]} if node in self.grains else {}

    def match(self, tgt):
        # Salt's greedy matching: an accepted minion with no cached grains matches any grain target.
        greedy = self.accepted - set(self.grains) if tgt.startswith('G@') else set()
        if tgt == PENDING_TGT:
            return self.pending | greedy
        wrapped = re.fullmatch(r'\( (.*) \)' + re.escape(NOT_PENDING), tgt)
        if wrapped:
            return self.match(wrapped.group(1)) - self.match(PENDING_TGT)
        narrowed = re.fullmatch(r'L@(\S+) and \( (.*) \)', tgt)
        if narrowed:
            return {narrowed.group(1)} & self.match(narrowed.group(2))
        return set(self.targets.get(tgt, [])) | greedy

    def check_minions(self, tgt, tgt_type='compound'):
        return {'minions': sorted(self.match(tgt))}

    def pend(self, *nodes):
        for node in nodes:
            self.pending.add(node)
            self.grains[node] = {'role': 'so-sensor', drainer.PENDING_GRAIN: True}

    def release(self, *nodes):
        for node in nodes:
            self.pending.discard(node)
            self.grains[node] = {'role': 'so-sensor'}


SURICATA = {'state': 'suricata', 'tgt': 'G@role:so-sensor'}


def _kept_copy(node, action):
    return dict(action, tgt='L@{} and ( {} )'.format(node, action['tgt']), tgt_type='compound')


class TestKeptPushes(DrainerTestCase):

    def setUp(self):
        super().setUp()
        self.ck = FakeCkMinions()
        self.ck.targets = {'G@role:so-sensor': ['a', 'b', 'c'], 'G@role:so-searchnode': ['s'], '*': ['a', 'b', 'c', 's']}
        self.ck.release('a', 'b', 'c', 's')
        self.keys = os.path.join(self.tmpdir, 'keys')
        os.makedirs(self.keys)
        for node in ('a', 'b', 'c', 's'):
            self.accept(node)
        self.cfg = {'enabled': True, 'debounce_seconds': 30}
        self.run = MagicMock(return_value=MagicMock(stdout='', stderr=ASYNC_STDERR))
        for target, name, kwargs in (
            (drainer.salt.utils.minions, 'CkMinions', {'return_value': self.ck}),
            (drainer.subprocess, 'run', {'new': self.run}),
            (drainer, 'MINION_KEYS_DIR', {'new': self.keys}),
            (drainer, '_make_logger', {'return_value': self.log}),
            (drainer, '_load_push_cfg', {'side_effect': lambda: self.cfg}),
            (drainer, '_check_dispatched', {}),
            (drainer, '_master_settling', {'return_value': False}),
        ):
            patcher = patch.object(target, name, **kwargs)
            patcher.start()
            self.addCleanup(patcher.stop)

    def accept(self, node):
        self.write_json(self.keys, node, '')
        self.ck.accepted.add(node)

    def source(self, actions, name='pillar_suricata.json', paths=None):
        now = time.time()
        return self.write_json(self.pending, name, {
            'first_touch': now - 65, 'last_touch': now - 60, 'actions': actions,
            'paths': paths or ['audit:suricata.config'],
        })

    def kept_path(self, node):
        return os.path.join(self.pending, 'pending_{}.json'.format(node))

    def kept(self, node):
        with open(self.kept_path(node)) as f:
            return json.load(f)

    def age(self, node, seconds=60):
        intent = self.kept(node)
        intent['last_touch'] -= seconds
        self.write_json(self.pending, 'pending_{}.json'.format(node), intent)

    def dispatched_actions(self):
        return [json.loads(c.args[0][3][len('pillar='):])['actions'] for c in self.run.call_args_list]

    def test_keeps_pending_only(self):
        self.ck.targets['G@role:so-sensor'] = ['a']
        self.ck.pend('a')
        source = self.source([SURICATA])
        self.assertEqual(drainer.main(), 0)
        self.run.assert_not_called()
        intent = self.kept('a')
        self.assertEqual(intent['actions'], [
            {'state': 'suricata', 'tgt': 'L@a and ( G@role:so-sensor )', 'tgt_type': 'compound'}])
        self.assertEqual(intent['pending'], 'a')
        self.assertEqual(intent['paths'], ['audit:suricata.config'])
        self.assertFalse(os.path.exists(source))
        info = self.logged('info')
        self.assertIn('push kept for a until its first highstate completes: suricata tgt=G@role:so-sensor', info)
        self.assertNotIn('L@a', info)
        self.assertNotIn('skipping', info)
        self.assertNotIn('nothing to dispatch', info)

    def test_keeps_pending_only_highstate(self):
        self.ck.targets['*'] = ['a']
        self.ck.pend('a')
        self.source([{'highstate': True, 'tgt': '*'}], name='pillar_global.json')
        self.assertEqual(drainer.main(), 0)
        self.run.assert_not_called()
        self.assertEqual(self.kept('a')['actions'], [{'highstate': True, 'tgt': 'L@a and ( * )', 'tgt_type': 'compound'}])
        info = self.logged('info')
        self.assertIn('push kept for a until its first highstate completes: highstate tgt=*', info)
        self.assertNotIn('L@a', info)
        self.assertNotIn('error', info.lower())

    def test_keeps_and_dispatches(self):
        self.ck.pend('a')
        source = self.source([SURICATA])
        self.assertEqual(drainer.main(), 0)
        self.assertEqual(self.dispatched_actions(), [[{'state': 'suricata', 'tgt': '( G@role:so-sensor )' + NOT_PENDING}]])
        self.assertEqual(self.kept('a')['actions'], [_kept_copy('a', SURICATA)])
        self.assertFalse(os.path.exists(source))
        self.assertIn('push kept for a until its first highstate completes: suricata', self.logged('info'))

    def test_keeps_several_pending(self):
        self.ck.pend('a', 'b')
        self.source([SURICATA])
        self.assertEqual(drainer.main(), 0)
        self.assertEqual(self.kept('a')['actions'], [_kept_copy('a', SURICATA)])
        self.assertEqual(self.kept('b')['actions'], [_kept_copy('b', SURICATA)])
        self.assertEqual(self.dispatched_actions(), [[{'state': 'suricata', 'tgt': '( G@role:so-sensor )' + NOT_PENDING}]])

        self.run.reset_mock()
        self.ck.release('a')
        self.age('a')
        self.age('b')
        self.assertEqual(drainer.main(), 0)
        self.assertEqual(self.dispatched_actions(), [[
            {'state': 'suricata', 'tgt': '( L@a and ( G@role:so-sensor ) )' + NOT_PENDING, 'tgt_type': 'compound'}]])
        self.assertFalse(os.path.exists(self.kept_path('a')))
        self.assertTrue(os.path.exists(self.kept_path('b')))

    def test_keep_merge(self):
        strelka = {'state': 'strelka', 'tgt': 'G@role:so-sensor'}
        paths = ['audit:p{}'.format(i) for i in range(30)]
        self.assertTrue(drainer._keep_for_pending({'a': [_kept_copy('a', SURICATA)]}, paths[:15], self.log))
        first_touch = self.kept('a')['first_touch']
        with patch.object(drainer.time, 'time', return_value=first_touch + 100):
            self.assertTrue(drainer._keep_for_pending(
                {'a': [_kept_copy('a', strelka), _kept_copy('a', SURICATA)]}, paths[10:], self.log))
        intent = self.kept('a')
        self.assertEqual(intent['actions'], [_kept_copy('a', SURICATA), _kept_copy('a', strelka)])
        self.assertEqual(intent['first_touch'], first_touch)
        self.assertEqual(intent['last_touch'], first_touch + 100)
        self.assertEqual(intent['paths'], paths[-drainer.MAX_PATHS:])
        self.assertEqual(intent['pending'], 'a')

    def test_keep_corrupt_file(self):
        self.write_json(self.pending, 'pending_a.json', '{nope')
        self.assertTrue(drainer._keep_for_pending({'a': [_kept_copy('a', SURICATA)]}, [], self.log))
        self.assertIn('cannot read intent', self.logged('warning'))
        self.assertEqual(self.kept('a')['actions'], [_kept_copy('a', SURICATA)])

    def test_keep_logs_other_tgt_unchanged(self):
        action = dict(SURICATA, tgt='L@b and ( G@role:so-sensor )')
        self.assertTrue(drainer._keep_for_pending({'a': [action]}, [], self.log))
        self.assertIn('push kept for a until its first highstate completes: suricata tgt=L@b and ( G@role:so-sensor )',
                      self.logged('info'))
        self.assertEqual(self.kept('a')['actions'], [action])

    def test_keep_logs_nested_parens_tgt(self):
        original = '( G@role:so-sensor or G@role:so-heavynode )'
        action = _kept_copy('a', dict(SURICATA, tgt=original))
        self.assertTrue(drainer._keep_for_pending({'a': [action]}, [], self.log))
        self.assertIn('suricata tgt={}\n'.format(original), self.logged('info') + '\n')
        self.assertEqual(self.kept('a')['actions'], [action])

    def test_keep_logs_prefix_node_tgt_unchanged(self):
        action = dict(SURICATA, tgt='L@ab and ( G@role:so-sensor )')
        self.assertTrue(drainer._keep_for_pending({'a': [action]}, [], self.log))
        self.assertIn('suricata tgt=L@ab and ( G@role:so-sensor )', self.logged('info'))

    def test_keep_logs_unterminated_tgt_unchanged(self):
        action = dict(SURICATA, tgt='L@a and ( G@role:so-sensor')
        self.assertTrue(drainer._keep_for_pending({'a': [action]}, [], self.log))
        self.assertIn('suricata tgt=L@a and ( G@role:so-sensor', self.logged('info'))

    def test_keep_write_fails(self):
        self.ck.targets['G@role:so-sensor'] = ['a', 'c']
        self.ck.pend('a')
        source = self.source([SURICATA])
        real_open = open

        def full_disk(path, *args, **kwargs):
            if str(path).endswith('pending_a.json.tmp'):
                raise OSError(errno.ENOSPC, 'No space left on device')
            return real_open(path, *args, **kwargs)

        with patch('builtins.open', side_effect=full_disk):
            self.assertEqual(drainer.main(), 1)
        self.run.assert_not_called()
        self.assertTrue(os.path.exists(source))
        self.assertFalse(os.path.exists(self.kept_path('a')))
        self.assertIn('cannot keep pushes for a until its first highstate completes', self.logged('error'))
        self.assertIn('No space left on device', self.logged('error'))

        self.assertEqual(drainer.main(), 0)
        self.run.assert_called_once()
        self.assertFalse(os.path.exists(source))
        self.assertEqual(self.kept('a')['actions'], [_kept_copy('a', SURICATA)])

    def test_dispatch_fails_keep_once(self):
        self.ck.pend('a')
        source = self.source([SURICATA])
        self.run.side_effect = subprocess.CalledProcessError(1, 'salt-run', '', 'master down')
        self.assertEqual(drainer.main(), 1)
        self.assertTrue(os.path.exists(source))
        self.assertEqual(self.kept('a')['actions'], [_kept_copy('a', SURICATA)])

        self.run.side_effect = None
        self.assertEqual(drainer.main(), 0)
        self.assertFalse(os.path.exists(source))
        self.assertEqual(self.kept('a')['actions'], [_kept_copy('a', SURICATA)])
        self.assertEqual(len(self.run.call_args_list), 2)

    def test_keep_no_relock(self):
        lock_fd = os.open(drainer.LOCK_FILE, os.O_CREAT | os.O_RDWR, 0o644)
        self.addCleanup(os.close, lock_fd)
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        self.addCleanup(fcntl.flock, lock_fd, fcntl.LOCK_UN)
        result = []
        worker = threading.Thread(
            target=lambda: result.append(drainer._keep_for_pending({'a': [_kept_copy('a', SURICATA)]}, [], self.log)),
            daemon=True)
        worker.start()
        worker.join(timeout=5)
        self.assertFalse(worker.is_alive())
        self.assertEqual(result, [True])
        self.assertTrue(os.path.exists(self.kept_path('a')))

    def test_kept_not_ready_while_pending(self):
        self.ck.pend('a')
        drainer._keep_for_pending({'a': [_kept_copy('a', SURICATA)]}, [], self.log)
        self.age('a')
        self.assertEqual(drainer.main(), 0)
        self.run.assert_not_called()
        self.assertTrue(os.path.exists(self.kept_path('a')))
        self.assertEqual([c.args for c in self.ck.cache.fetch.call_args_list], [('minions/a', 'data')])
        self.assertIn('no ready intents (0 still in debounce window, 1 for nodes still in their first highstate)',
                      self.logged('debug'))

    def test_kept_drains_after_release(self):
        drainer._keep_for_pending({'a': [_kept_copy('a', SURICATA)]}, ['audit:suricata.config'], self.log)
        self.age('a')
        self.ck.release('a')
        self.assertEqual(drainer.main(), 0)
        self.assertEqual(self.dispatched_actions(), [[
            {'state': 'suricata', 'tgt': '( L@a and ( G@role:so-sensor ) )' + NOT_PENDING, 'tgt_type': 'compound'}]])
        self.assertFalse(os.path.exists(self.kept_path('a')))
        self.assertEqual(len(os.listdir(self.dispatched)), 1)

    def test_kept_waits_for_debounce(self):
        drainer._keep_for_pending({'a': [_kept_copy('a', SURICATA)]}, [], self.log)
        self.ck.release('a')
        self.assertEqual(drainer.main(), 0)
        self.run.assert_not_called()
        self.ck.cache.fetch.assert_not_called()
        self.assertTrue(os.path.exists(self.kept_path('a')))

    def test_kept_master_config_error(self):
        drainer._keep_for_pending({'a': [_kept_copy('a', SURICATA)]}, [], self.log)
        self.age('a')
        self.ck.release('a')
        with patch.object(drainer.salt.config, 'master_config', side_effect=OSError('no config')):
            self.assertEqual(drainer.main(), 0)
        self.run.assert_not_called()
        self.assertTrue(os.path.exists(self.kept_path('a')))
        self.assertIn('holding kept pushes', self.logged('warning'))

    def test_kept_removed_node(self):
        drainer._keep_for_pending({'a': [_kept_copy('a', SURICATA)]}, [], self.log)
        os.unlink(os.path.join(self.keys, 'a'))
        self.assertEqual(drainer.main(), 0)
        self.run.assert_not_called()
        self.assertFalse(os.path.exists(self.kept_path('a')))
        self.assertIn('removing kept pushes for a: its key is no longer accepted', self.logged('info'))

    def test_kept_no_match_dropped(self):
        search = {'state': 'elasticsearch', 'tgt': 'G@role:so-searchnode'}
        drainer._keep_for_pending({'a': [_kept_copy('a', search)]}, [], self.log)
        self.age('a')
        self.ck.release('a')
        self.assertEqual(drainer.main(), 0)
        self.run.assert_not_called()
        self.assertFalse(os.path.exists(self.kept_path('a')))
        self.assertIn('skipping elasticsearch: no minions match tgt=L@a and ( G@role:so-searchnode )', self.logged('info'))

    def test_kept_uncached_node_greedy(self):
        self.accept('m')
        manager = {'state': 'nginx', 'tgt': 'G@role:so-manager'}
        source = self.source([manager])
        self.assertEqual(drainer.main(), 0)
        self.run.assert_not_called()
        self.assertFalse(os.path.exists(source))
        self.assertEqual(self.kept('m')['actions'], [_kept_copy('m', manager)])

        self.ck.release('m')
        self.age('m')
        self.log.reset_mock()
        self.assertEqual(drainer.main(), 0)
        self.run.assert_not_called()
        self.assertFalse(os.path.exists(self.kept_path('m')))
        self.assertEqual([c.args[0] % c.args[1:] for c in self.log.info.call_args_list if 'skipping' in c.args[0]],
                         ['skipping nginx: no minions match tgt=L@m and ( G@role:so-manager )'])

        self.log.reset_mock()
        self.assertEqual(drainer.main(), 0)
        self.log.info.assert_not_called()

    def test_kept_partial_match_consumed(self):
        search = {'state': 'elasticsearch', 'tgt': 'G@role:so-searchnode'}
        drainer._keep_for_pending({'a': [_kept_copy('a', SURICATA), _kept_copy('a', search)]}, [], self.log)
        self.age('a')
        self.ck.release('a')
        self.assertEqual(drainer.main(), 0)
        self.assertEqual(self.dispatched_actions(), [[
            {'state': 'suricata', 'tgt': '( L@a and ( G@role:so-sensor ) )' + NOT_PENDING, 'tgt_type': 'compound'}]])
        self.assertFalse(os.path.exists(self.kept_path('a')))

    def test_kept_cache_error_held(self):
        search = {'state': 'elasticsearch', 'tgt': 'G@role:so-searchnode'}
        drainer._keep_for_pending({'a': [_kept_copy('a', search)]}, [], self.log)
        self.age('a')
        self.ck.release('a')
        self.ck.fetch_error = OSError('cache read failed')
        self.assertEqual(drainer.main(), 0)
        self.run.assert_not_called()
        self.assertTrue(os.path.exists(self.kept_path('a')))
        self.assertIn('cannot read the cached grains of a', self.logged('warning'))
        self.assertNotIn('skipping', self.logged('info'))

    def test_no_unlink_written_this_pass(self):
        drainer._keep_for_pending({'a': [_kept_copy('a', SURICATA)]}, ['audit:suricata.config'], self.log)
        self.age('a')
        first_touch = self.kept('a')['first_touch']
        self.ck.release('a')
        self.ck.pending.add('a')
        self.assertEqual(drainer.main(), 0)
        self.run.assert_not_called()
        intent = self.kept('a')
        self.assertEqual(intent['actions'][0], _kept_copy('a', SURICATA))
        self.assertIn('push kept for a', self.logged('info'))
        self.assertEqual(intent['first_touch'], first_touch)
        self.assertGreater(intent['last_touch'], first_touch)
        self.assertEqual(intent['paths'], ['audit:suricata.config'])

    def test_bad_id(self):
        self.ck.targets['*'] = ['bad\n', 'a/../b', 'c']
        self.ck.pending = {'bad\n', 'a/../b'}
        self.source([{'highstate': True, 'tgt': '*'}], name='pillar_global.json')
        for name, node in (('pending_x.json', '../etc'), ('pending_y.json', 5), ('pending_z.json', 'z\n')):
            self.write_json(self.pending, name, {'pending': node, 'last_touch': 0, 'actions': [SURICATA]})
        self.assertEqual(drainer.main(), 0)
        self.assertEqual(os.listdir(self.pending), ['.lock'])
        self.assertEqual(self.dispatched_actions(), [[{'highstate': True, 'tgt': '( * )' + NOT_PENDING}]])
        for call in self.run.call_args_list:
            self.assertNotIn('bad', call.args[0][3])
            self.assertNotIn('a/../b', call.args[0][3])
        warning = self.logged('warning')
        self.assertIn("not keeping highstate for 'bad\\n': not a valid node id", warning)
        self.assertIn("not keeping highstate for 'a/../b'", warning)
        self.assertIn("'../etc' is not a valid node id", warning)
        self.assertIn('5 is not a valid node id', warning)
        self.assertIn("'z\\n' is not a valid node id", warning)
        self.assertNotIn('push kept', self.logged('info'))


class TestMain(DrainerTestCase):

    def setUp(self):
        super().setUp()
        self.cfg = {'enabled': True, 'debounce_seconds': 30}
        for name, kwargs in (
            ('_make_logger', {'return_value': self.log}),
            ('_load_push_cfg', {'side_effect': lambda: self.cfg}),
            ('_check_dispatched', {}),
            ('_targeted', {'side_effect': lambda actions, log: (actions, {})}),
            ('_master_settling', {'return_value': False}),
        ):
            patcher = patch.object(drainer, name, **kwargs)
            setattr(self, name, patcher.start())
            self.addCleanup(patcher.stop)

    def intent(self, name, age=60, actions=None, paths=None):
        now = time.time()
        return self.write_json(self.pending, name, {
            'first_touch': now - age - 5, 'last_touch': now - age,
            'actions': [{'state': 'soc', 'tgt': '*'}] if actions is None else actions,
            'paths': paths or ['audit:soc.config.licenseKey'],
        })

    def test_no_pending_dir(self):
        shutil.rmtree(self.pending)
        self.assertEqual(drainer.main(), 0)
        self._load_push_cfg.assert_not_called()

    def test_cfg_error(self):
        self._load_push_cfg.side_effect = RuntimeError('no salt')
        self.assertEqual(drainer.main(), 1)

    def test_disabled(self):
        self.cfg['enabled'] = False
        self.assertEqual(drainer.main(), 0)
        self._check_dispatched.assert_not_called()

    def test_no_intents_still_checks_results(self):
        self.assertEqual(drainer.main(), 0)
        self._check_dispatched.assert_called_once()

    def test_debounce_and_broken(self):
        young = self.intent('young.json', age=1)
        broken = self.write_json(self.pending, 'broken.json', '{nope')
        with patch.object(drainer, '_dispatch') as dispatch:
            self.assertEqual(drainer.main(), 0)
        dispatch.assert_not_called()
        self.assertTrue(os.path.exists(young))
        self.assertFalse(os.path.exists(broken))

    def test_broken_unlink_error_ignored(self):
        self.write_json(self.pending, 'broken.json', '{nope')
        with patch.object(drainer.os, 'unlink', side_effect=OSError('busy')):
            self.assertEqual(drainer.main(), 0)

    def test_no_usable_actions(self):
        path = self.intent('empty.json', actions=[{'state': 'soc'}])
        self.assertEqual(drainer.main(), 0)
        self.assertFalse(os.path.exists(path))
        self.intent('empty.json', actions=[{'state': 'soc'}])
        with patch.object(drainer.os, 'unlink', side_effect=OSError('busy')):
            self.assertEqual(drainer.main(), 0)

    def test_holds_while_master_settling(self):
        path = self.intent('pillar_soc.json')
        self._master_settling.return_value = True
        with patch.object(drainer, '_dispatch') as dispatch:
            self.assertEqual(drainer.main(), 0)
        dispatch.assert_not_called()
        self._check_dispatched.assert_called_once()
        self.assertTrue(os.path.exists(path))
        self.assertIn('holding 1 intent(s)', self.logged('info'))

    def test_dispatch_failure_keeps_intents(self):
        path = self.intent('pillar_soc.json')
        with patch.object(drainer, '_dispatch', return_value=None):
            self.assertEqual(drainer.main(), 1)
        self.assertTrue(os.path.exists(path))

    def test_dispatch_records_jid(self):
        soc = self.intent('pillar_soc.json')
        hs = self.intent('pillar_global.json', actions=[{'highstate': True, 'tgt': '*'}], paths=['audit:global.x'])
        with patch.object(drainer, '_dispatch', return_value=JID) as dispatch, \
                patch.object(drainer, '_record_dispatch') as record:
            self.assertEqual(drainer.main(), 0)
        self.assertEqual(len(dispatch.call_args[0][0]), 2)
        record.assert_called_once()
        self.assertEqual(record.call_args[0][0], JID)
        self.assertEqual(sorted(record.call_args[0][2]), ['audit:global.x', 'audit:soc.config.licenseKey'])
        self.assertFalse(os.path.exists(soc))
        self.assertFalse(os.path.exists(hs))
        self.assertIn('action: highstate tgt=*', self.logged('info'))

    def test_dispatch_without_jid_not_recorded(self):
        self.intent('pillar_soc.json')
        with patch.object(drainer, '_dispatch', return_value=''), \
                patch.object(drainer, '_record_dispatch') as record, \
                patch.object(drainer.os, 'unlink', side_effect=OSError('busy')):
            self.assertEqual(drainer.main(), 0)
        record.assert_not_called()
        self.log.exception.assert_called_once()

    def test_untargeted_not_dispatched(self):
        path = self.intent('strelka.json', actions=[{'state': 'strelka', 'tgt': 'G@role:so-sensor'}])
        self._targeted.side_effect = None
        self._targeted.return_value = ([], {})
        with patch.object(drainer, '_dispatch') as dispatch, \
                patch.object(drainer, '_record_dispatch') as record:
            self.assertEqual(drainer.main(), 0)
        dispatch.assert_not_called()
        record.assert_not_called()
        self.assertFalse(os.path.exists(path))
        self.assertIn('no action matches a minion; nothing to dispatch', self.logged('info'))

    def test_dispatches_only_targeted(self):
        matched = {'state': 'soc', 'tgt': '*'}
        self.intent('mixed.json', actions=[matched, {'state': 'strelka', 'tgt': 'G@role:so-sensor'}])
        self._targeted.side_effect = None
        self._targeted.return_value = ([matched], {})
        with patch.object(drainer, '_dispatch', return_value=JID) as dispatch, \
                patch.object(drainer, '_record_dispatch') as record:
            self.assertEqual(drainer.main(), 0)
        self.assertEqual(dispatch.call_args[0][0], [matched])
        self.assertEqual(record.call_args[0][1], [matched])


if __name__ == '__main__':
    unittest.main()
