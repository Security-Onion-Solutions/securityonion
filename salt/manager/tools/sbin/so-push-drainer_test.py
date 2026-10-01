# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

import importlib.util
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from importlib.machinery import SourceFileLoader
from unittest.mock import MagicMock, patch

# salt is not installed where these tests run; the drainer only needs salt.client.Caller.
_salt = MagicMock()
sys.modules.setdefault('salt', _salt)
sys.modules.setdefault('salt.client', _salt.client)

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, 'so-push-drainer')
_loader = SourceFileLoader('so_push_drainer', SCRIPT)
_spec = importlib.util.spec_from_loader('so_push_drainer', _loader)
drainer = importlib.util.module_from_spec(_spec)
_loader.exec_module(drainer)

MASTER = 'manager.localdomain_master'
JID = '20260930171554259426'
ASYNC_STDERR = ('[WARNING ] Running in asynchronous mode. Results of this execution may be collected '
                'by attaching to the master event bus or by examining the master job cache, if '
                'configured. This execution is running under tag salt/run/{}\n'.format(JID))
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

    def test_unlink_missing_logs(self):
        drainer._unlink(os.path.join(self.tmpdir, 'missing'), self.log)
        self.log.exception.assert_called_once()


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
        jid, _ = self.run_dispatch(return_value=MagicMock(stdout='', stderr=None))
        self.assertEqual(jid, '')
        self.log.warning.assert_called_once()

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

    def test_record_dispatch_oserror(self):
        with patch.object(drainer.os, 'makedirs', side_effect=OSError('ro')):
            drainer._record_dispatch(JID, [], [], self.log)
        self.log.exception.assert_called_once()


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
        }
        young = self.record('0_young', 5, now)
        paths = {jid: self.record(jid, 60, now) for jid in results}
        paths['4_expired'] = self.record('4_expired', drainer.RESULT_MAX_AGE + 1, now)
        bad = self.write_json(self.dispatched, '5_bad.json', '{nope')
        with patch.object(drainer, '_lookup_jid', side_effect=lambda jid, log: results[jid]):
            drainer._check_dispatched(self.log, now)

        self.assertTrue(os.path.exists(young))
        self.assertTrue(os.path.exists(paths['3_pending']))
        for jid in ('1_failed', '2_ok', '4_expired'):
            self.assertFalse(os.path.exists(paths[jid]), jid)
        self.assertFalse(os.path.exists(bad))
        self.assertIn('push failed jid=1_failed', self.logged('error'))
        self.assertIn('is running as PID 372218', self.logged('error'))
        self.assertIn('push succeeded jid=2_ok', self.logged('info'))
        self.assertIn('no result for jid=4_expired', self.logged('warning'))

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

    def test_check_dispatched_limit(self):
        now = time.time()
        for i in range(drainer.RESULT_CHECKS_PER_PASS + 2):
            self.record('{:02d}'.format(i), 60, now)
        with patch.object(drainer, '_lookup_jid', return_value={}) as lookup:
            drainer._check_dispatched(self.log, now)
        self.assertEqual(lookup.call_count, drainer.RESULT_CHECKS_PER_PASS)


class TestMain(DrainerTestCase):

    def setUp(self):
        super().setUp()
        self.cfg = {'enabled': True, 'debounce_seconds': 30}
        for name, kwargs in (
            ('_make_logger', {'return_value': self.log}),
            ('_load_push_cfg', {'side_effect': lambda: self.cfg}),
            ('_check_dispatched', {}),
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


if __name__ == '__main__':
    unittest.main()
