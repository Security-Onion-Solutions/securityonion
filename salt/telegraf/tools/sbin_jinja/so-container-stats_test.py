# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

# so-container-stats replaces telegraf's inputs.docker plugin, which was dropped along with the
# docker socket. The InfluxDB dashboards query its output by measurement, tag and field name, so
# these tests pin that contract: the shipped defaults, the per-stat toggles, the field types, and
# the value semantics copied from the plugin.
#
# The collector is a jinja template, so every test renders it the way salt does and imports the
# result. Docker and the cgroup filesystem are faked, so nothing here needs a container runtime.

import contextlib
import importlib.util
import io
import json
import os
import tempfile
import unittest

import jinja2
import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
TEMPLATE = os.path.join(HERE, 'so-container-stats')
DEFAULTS = os.path.join(HERE, '..', '..', 'defaults.yaml')

# a container id is a 64 character hex string; the plugin published it in full
SOC_ID = 'a' * 64
TELEGRAF_ID = 'b' * 64
NGINX_ID = 'c' * 64
IDSTOOLS_ID = 'd' * 64


def shipped_defaults():
    with open(DEFAULTS) as handle:
        return yaml.safe_load(handle)['telegraf']['container_stats']


def all_enabled():
    return {group: {field: True for field in fields} for group, fields in shipped_defaults().items()}


def render(settings):
    """Render the template as salt does, import it, and hand back the module."""
    with open(TEMPLATE) as handle:
        source = handle.read()
    rendered = jinja2.Template(source, keep_trailing_newline=True).render(CONTAINER_STATS=settings)
    path = os.path.join(tempfile.mkdtemp(), 'so_container_stats.py')
    with open(path, 'w') as handle:
        handle.write(rendered)
    spec = importlib.util.spec_from_file_location('so_container_stats', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def split_escaped(text, sep):
    """Split on an unescaped, unquoted separator, the way influx line protocol is written."""
    parts, current, escaped, quoted = [], '', False, False
    for char in text:
        if escaped:
            current += char
            escaped = False
        elif char == '\\':
            current += char
            escaped = True
        elif char == '"':
            quoted = not quoted
            current += char
        elif char == sep and not quoted:
            parts.append(current)
            current = ''
        else:
            current += char
    parts.append(current)
    return parts


def split_on_space(line):
    escaped = quoted = False
    for index, char in enumerate(line):
        if escaped:
            escaped = False
        elif char == '\\':
            escaped = True
        elif char == '"':
            quoted = not quoted
        elif char == ' ' and not quoted:
            return line[:index], line[index + 1:]
    return line, ''


def parse(output):
    """Parse line protocol into {(measurement, container): (tags, fields)}."""
    points = {}
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        head, fieldpart = split_on_space(line)
        pieces = split_escaped(head, ',')
        measurement, tags = pieces[0], {}
        for piece in pieces[1:]:
            key, _, value = piece.partition('=')
            tags[key] = value
        fields = {}
        for piece in split_escaped(fieldpart, ','):
            key, _, value = piece.partition('=')
            fields[key] = value
        key = (measurement, tags.get('container_name', ''))
        if key in points:
            # the engine measurement is published as two points, the way inputs.docker did
            points[key][1].update(fields)
        else:
            points[key] = (tags, fields)
    return points


def field_type(value):
    if value.endswith('u'):
        return 'unsigned'
    if value.endswith('i'):
        return 'integer'
    if value.startswith('"'):
        return 'string'
    if value in ('true', 'false'):
        return 'boolean'
    return 'float'


def container(name, cid, pid, status='running', network='bridge', image='registry:5000/repo/img:3.4.0',
              started='2026-09-24T10:00:00.123456789Z', finished='0001-01-01T00:00:00Z', health=None,
              oomkilled=False, exitcode=0, restarts=0):
    state = {'Status': status, 'Pid': pid, 'StartedAt': started, 'FinishedAt': finished,
             'OOMKilled': oomkilled, 'ExitCode': exitcode}
    if health is not None:
        state['Health'] = health
    return {'Id': cid, 'Name': '/' + name, 'State': state, 'RestartCount': restarts,
            'Config': {'Image': image}, 'HostConfig': {'NetworkMode': network}}


class CollectorTestCase(unittest.TestCase):
    """Builds a fake docker engine and cgroup tree, then runs the collector against it."""

    def setUp(self):
        self.inspect = [
            container('so-soc', SOC_ID, 1001),
            container('so-telegraf', TELEGRAF_ID, 1002, network='host'),
            container('so-nginx', NGINX_ID, 1003, health={'Status': 'healthy', 'FailingStreak': 0}),
        ]
        self.stats = {
            'so-soc': {'Name': 'so-soc', 'CPUPerc': '1.25%', 'MemPerc': '6.39%', 'NetIO': '1kB / 2kB'},
            'so-telegraf': {'Name': 'so-telegraf', 'CPUPerc': '0.04%', 'MemPerc': '0.58%', 'NetIO': '0B / 0B'},
            'so-nginx': {'Name': 'so-nginx', 'CPUPerc': '0.00%', 'MemPerc': '0.09%', 'NetIO': '3kB / 4kB'},
        }
        self.info = {'Name': 'sohost', 'ServerVersion': '29.2.1', 'Containers': 3, 'ContainersRunning': 3,
                     'ContainersStopped': 0, 'ContainersPaused': 0, 'Images': 9, 'NCPU': 8,
                     'NGoroutines': 42, 'NFd': 77, 'NEventsListener': 1, 'MemTotal': 16000000000}
        # one cgroup per container, addressed through /proc/<pid>/cgroup exactly as the collector does
        self.files = {
            '/proc/meminfo': 'MemTotal:       15625000 kB\n',
            '/proc/stat': 'cpu  100 200 300 400\ncpu0 1 2 3 4\n',
        }
        for pid in (1001, 1002, 1003):
            self.files['/proc/%d/cgroup' % pid] = '0::/scope%d\n' % pid
            self.cgroup(pid, 'cpu.stat',
                        'usage_usec 1000\nuser_usec 600\nsystem_usec 400\nnr_periods 5\nnr_throttled 2\nthrottled_usec 700\n')
            self.cgroup(pid, 'memory.stat',
                        'active_anon 300\nactive_file 40\ninactive_anon 200\ninactive_file 50\nunevictable 0\npgfault 1234\npgmajfault 56\n')
            self.cgroup(pid, 'memory.current', '1000\n')
            self.cgroup(pid, 'memory.max', '4000\n')
            self.cgroup(pid, 'memory.peak', '2500\n')
            self.cgroup(pid, 'io.stat', '8:0 rbytes=100 wbytes=200 rios=1 wios=2\n252:0 rbytes=10 wbytes=20 rios=1 wios=1\n')
            self.files['/proc/%d/net/dev' % pid] = (
                'Inter-|   Receive                          |  Transmit\n'
                ' face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\n'
                '    lo:  9999      99    9    9    0     0          0         0   9999      99    9    9    0     0       0          0\n'
                '  eth0:  1000      10    1    2    0     0          0         0   2000      20    3    4    0     0       0          0\n'
                '  eth1:   500       5    0    0    0     0          0         0   1000      10    0    0    0     0       0          0\n')

    def cgroup(self, pid, name, contents):
        self.files['/sys/fs/cgroup/scope%d/%s' % (pid, name)] = contents

    def run_collector(self, settings=None, module=None):
        module = module or render(settings if settings is not None else all_enabled())

        def fake_docker(args):
            if args[0] == 'stats':
                return ''.join(json.dumps(entry) + '\n' for entry in self.stats.values())
            if args[0] == 'ps':
                return ' '.join(entry['Id'] for entry in self.inspect)
            if args[0] == 'inspect':
                return json.dumps(self.inspect)
            if args[0] == 'info':
                return json.dumps(self.info)
            raise AssertionError('unexpected docker call: %s' % args)

        module.docker = fake_docker
        module.read_text = lambda path: self.files.get(path, '')
        module.CGROUP_ROOT = '/sys/fs/cgroup'
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            module.main()
        self.output = buffer.getvalue()
        return parse(self.output)


class TestShippedDefaults(CollectorTestCase):

    def test_defaults_emit_only_the_dashboard_fields(self):
        # the Security Onion Performance dashboard queries exactly these five
        points = self.run_collector(shipped_defaults())
        emitted = {(measurement, field) for (measurement, _), (_, fields) in points.items() for field in fields}
        self.assertEqual(emitted, {
            ('docker_container_cpu', 'usage_percent'),
            ('docker_container_mem', 'usage_percent'),
            ('docker_container_net', 'rx_bytes'),
            ('docker_container_status', 'uptime_ns'),
            ('docker_container_status', 'oomkilled'),
        })

    def test_defaults_do_not_emit_the_opt_in_measurements(self):
        points = self.run_collector(shipped_defaults())
        measurements = {measurement for measurement, _ in points}
        self.assertNotIn('docker', measurements)
        self.assertNotIn('docker_container_blkio', measurements)
        self.assertNotIn('docker_container_health', measurements)

    def test_defaults_carry_the_tags_the_dashboard_filters_on(self):
        points = self.run_collector(shipped_defaults())
        tags, _ = points[('docker_container_cpu', 'so-soc')]
        self.assertEqual(tags['container_status'], 'running')
        self.assertEqual(tags['cpu'], 'cpu-total')
        # identity tags are opt in, so they must be absent by default
        self.assertNotIn('container_image', tags)
        self.assertNotIn('engine_host', tags)


class TestToggles(CollectorTestCase):

    def test_enabling_one_stat_adds_only_that_field(self):
        settings = shipped_defaults()
        settings['cpu']['usage_total'] = True
        _, fields = self.run_collector(settings)[('docker_container_cpu', 'so-soc')]
        self.assertIn('usage_total', fields)
        self.assertNotIn('usage_in_usermode', fields)

    def test_disabling_one_stat_leaves_its_neighbours(self):
        settings = all_enabled()
        settings['blkio']['io_service_bytes_recursive_read'] = False
        _, fields = self.run_collector(settings)[('docker_container_blkio', 'so-soc')]
        self.assertNotIn('io_service_bytes_recursive_read', fields)
        self.assertIn('io_service_bytes_recursive_write', fields)

    def test_identity_tags_are_added_when_enabled(self):
        tags, _ = self.run_collector(all_enabled())[('docker_container_cpu', 'so-soc')]
        self.assertEqual(tags['container_image'], 'registry:5000/repo/img')
        self.assertEqual(tags['container_version'], '3.4.0')
        self.assertEqual(tags['engine_host'], 'sohost')
        self.assertEqual(tags['server_version'], '29.2.1')

    def test_everything_off_emits_nothing(self):
        settings = {group: {field: False for field in fields} for group, fields in shipped_defaults().items()}
        self.assertEqual(self.run_collector(settings), {})


class TestFieldTypes(CollectorTestCase):
    """inputs.docker wrote the cgroup and network counters as unsigned; influx treats u and i as
    different field types, so a mismatch breaks queries spanning the change."""

    def test_counter_fields_are_unsigned(self):
        points = self.run_collector(all_enabled())
        for measurement, field in (('docker_container_cpu', 'usage_total'),
                                   ('docker_container_cpu', 'throttling_periods'),
                                   ('docker_container_mem', 'usage'),
                                   ('docker_container_mem', 'limit'),
                                   ('docker_container_mem', 'pgfault'),
                                   ('docker_container_net', 'rx_bytes'),
                                   ('docker_container_blkio', 'io_service_bytes_recursive_read')):
            _, fields = points[(measurement, 'so-soc')]
            self.assertEqual(field_type(fields[field]), 'unsigned', '%s.%s' % (measurement, field))

    def test_status_and_engine_fields_are_signed(self):
        points = self.run_collector(all_enabled())
        _, status = points[('docker_container_status', 'so-soc')]
        for field in ('uptime_ns', 'pid', 'exitcode', 'restart_count', 'started_at'):
            self.assertEqual(field_type(status[field]), 'integer', field)
        _, engine = points[('docker', '')]
        self.assertEqual(field_type(engine['n_containers']), 'integer')

    def test_percentages_are_floats_and_ids_are_quoted_strings(self):
        points = self.run_collector(all_enabled())
        _, cpu = points[('docker_container_cpu', 'so-soc')]
        self.assertEqual(field_type(cpu['usage_percent']), 'float')
        self.assertEqual(field_type(cpu['container_id']), 'string')
        self.assertEqual(cpu['container_id'], '"%s"' % SOC_ID)
        _, status = points[('docker_container_status', 'so-soc')]
        self.assertEqual(field_type(status['oomkilled']), 'boolean')
        _, health = points[('docker_container_health', 'so-nginx')]
        self.assertEqual(health['health_status'], '"healthy"')


class TestMemorySemantics(CollectorTestCase):

    def test_usage_subtracts_reclaimable_page_cache(self):
        # inputs.docker reports usage net of inactive_file: 1000 - 50
        _, fields = self.run_collector(all_enabled())[('docker_container_mem', 'so-soc')]
        self.assertEqual(fields['usage'], '950u')

    def test_usage_percent_is_usage_over_limit(self):
        _, fields = self.run_collector(all_enabled())[('docker_container_mem', 'so-soc')]
        self.assertAlmostEqual(float(fields['usage_percent']), 950 / 4000 * 100.0)

    def test_limit_falls_back_to_host_memory_when_unlimited(self):
        for pid in (1001, 1002, 1003):
            self.cgroup(pid, 'memory.max', 'max\n')
        _, fields = self.run_collector(all_enabled())[('docker_container_mem', 'so-soc')]
        self.assertEqual(fields['limit'], '%du' % (15625000 * 1024))

    def test_max_usage_reports_the_cgroup_peak(self):
        # the daemon reports 0 on cgroup v2, so this deliberately carries the real peak
        _, fields = self.run_collector(all_enabled())[('docker_container_mem', 'so-soc')]
        self.assertEqual(fields['max_usage'], '2500u')


class TestCpuSemantics(CollectorTestCase):

    def test_microsecond_counters_are_published_as_nanoseconds(self):
        _, fields = self.run_collector(all_enabled())[('docker_container_cpu', 'so-soc')]
        self.assertEqual(fields['usage_total'], '1000000u')
        self.assertEqual(fields['usage_in_usermode'], '600000u')
        self.assertEqual(fields['usage_in_kernelmode'], '400000u')
        self.assertEqual(fields['throttling_throttled_time'], '700000u')

    def test_throttling_counts_are_not_scaled(self):
        _, fields = self.run_collector(all_enabled())[('docker_container_cpu', 'so-soc')]
        self.assertEqual(fields['throttling_periods'], '5u')
        self.assertEqual(fields['throttling_throttled_periods'], '2u')

    def test_usage_system_is_host_wide_cpu_time(self):
        _, fields = self.run_collector(all_enabled())[('docker_container_cpu', 'so-soc')]
        self.assertEqual(field_type(fields['usage_system']), 'unsigned')
        self.assertNotEqual(fields['usage_system'], '0u')


class TestNetwork(CollectorTestCase):

    def test_counters_sum_interfaces_and_ignore_loopback(self):
        _, fields = self.run_collector(all_enabled())[('docker_container_net', 'so-soc')]
        self.assertEqual(fields['rx_bytes'], '1500u')
        self.assertEqual(fields['rx_packets'], '15u')
        self.assertEqual(fields['tx_bytes'], '3000u')
        self.assertEqual(fields['rx_dropped'], '2u')

    def test_host_network_containers_emit_no_row(self):
        # inputs.docker skipped these: its Networks map is empty for --net=host
        points = self.run_collector(all_enabled())
        self.assertNotIn(('docker_container_net', 'so-telegraf'), points)
        self.assertIn(('docker_container_net', 'so-soc'), points)

    def test_total_tag_is_present(self):
        tags, _ = self.run_collector(all_enabled())[('docker_container_net', 'so-soc')]
        self.assertEqual(tags['network'], 'total')


class TestBlkio(CollectorTestCase):

    def test_counters_sum_devices(self):
        _, fields = self.run_collector(all_enabled())[('docker_container_blkio', 'so-soc')]
        self.assertEqual(fields['io_service_bytes_recursive_read'], '110u')
        self.assertEqual(fields['io_service_bytes_recursive_write'], '220u')

    def test_container_with_no_io_reports_zero_rather_than_disappearing(self):
        for pid in (1001, 1002, 1003):
            self.cgroup(pid, 'io.stat', '')
        tags, fields = self.run_collector(all_enabled())[('docker_container_blkio', 'so-soc')]
        self.assertEqual(fields['io_service_bytes_recursive_read'], '0u')
        self.assertEqual(tags['device'], 'total')


class TestStatus(CollectorTestCase):

    def test_running_container_uptime_counts_from_start(self):
        _, fields = self.run_collector(all_enabled())[('docker_container_status', 'so-soc')]
        self.assertGreater(int(fields['uptime_ns'].rstrip('i')), 0)
        self.assertNotIn('finished_at', fields)

    def test_exited_container_reports_its_lifetime_and_finished_at(self):
        self.inspect.append(container('so-idstools', IDSTOOLS_ID, 0, status='exited',
                                      started='2026-09-24T10:00:00.000000000Z',
                                      finished='2026-09-24T10:00:02.000000000Z', exitcode=3, restarts=1))
        points = self.run_collector(all_enabled())
        tags, fields = points[('docker_container_status', 'so-idstools')]
        self.assertEqual(tags['container_status'], 'exited')
        self.assertEqual(fields['uptime_ns'], '2000000000i')
        self.assertEqual(fields['finished_at'], '1790244002000000000i')
        self.assertEqual(fields['exitcode'], '3i')
        self.assertEqual(fields['restart_count'], '1i')
        # a stopped container has no live stats, so only the status row is emitted
        self.assertNotIn(('docker_container_cpu', 'so-idstools'), points)

    def test_health_is_emitted_only_for_containers_with_a_healthcheck(self):
        points = self.run_collector(all_enabled())
        self.assertIn(('docker_container_health', 'so-nginx'), points)
        self.assertNotIn(('docker_container_health', 'so-soc'), points)

    def test_oomkilled_is_reported(self):
        self.inspect[0]['State']['OOMKilled'] = True
        _, fields = self.run_collector(all_enabled())[('docker_container_status', 'so-soc')]
        self.assertEqual(fields['oomkilled'], 'true')


class TestEngineMeasurement(CollectorTestCase):

    def test_engine_counts_come_from_docker_info(self):
        _, fields = self.run_collector(all_enabled())[('docker', '')]
        self.assertEqual(fields['n_containers'], '3i')
        self.assertEqual(fields['n_cpus'], '8i')
        self.assertEqual(fields['n_used_file_descriptors'], '77i')

    def test_engine_is_published_as_two_points(self):
        # inputs.docker emitted memory_total on its own point, so keep that shape
        self.run_collector(all_enabled())
        engine = [line for line in self.output.splitlines() if line.startswith('docker,')]
        self.assertEqual(len(engine), 2)
        self.assertTrue(any('memory_total=' in line for line in engine))
        self.assertTrue(any('n_containers=' in line for line in engine))

    def test_engine_rows_are_tagged_with_host_and_version(self):
        tags, _ = self.run_collector(all_enabled())[('docker', '')]
        self.assertEqual(tags['engine_host'], 'sohost')
        self.assertEqual(tags['server_version'], '29.2.1')


class TestLineProtocol(CollectorTestCase):

    def test_tag_values_are_escaped(self):
        self.inspect[0]['Name'] = '/odd name,with=chars'
        self.stats['odd name,with=chars'] = self.stats.pop('so-soc')
        self.stats['odd name,with=chars']['Name'] = 'odd name,with=chars'
        output = self.run_collector(all_enabled())
        self.assertIn(('docker_container_cpu', 'odd\\ name\\,with\\=chars'), output)

    def test_image_without_a_tag_reports_version_unknown(self):
        self.inspect[0]['Config']['Image'] = 'busybox'
        tags, _ = self.run_collector(all_enabled())[('docker_container_cpu', 'so-soc')]
        self.assertEqual(tags['container_image'], 'busybox')
        self.assertEqual(tags['container_version'], 'unknown')

    def test_every_line_has_a_measurement_tagset_and_fieldset(self):
        module = render(all_enabled())

        def fake_docker(args):
            if args[0] == 'stats':
                return ''.join(json.dumps(entry) + '\n' for entry in self.stats.values())
            if args[0] == 'ps':
                return ' '.join(entry['Id'] for entry in self.inspect)
            if args[0] == 'inspect':
                return json.dumps(self.inspect)
            return json.dumps(self.info)

        module.docker = fake_docker
        module.read_text = lambda path: self.files.get(path, '')
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            module.main()
        lines = [line for line in buffer.getvalue().splitlines() if line.strip()]
        self.assertTrue(lines)
        for line in lines:
            head, fieldpart = split_on_space(line)
            self.assertIn(',', head, line)
            self.assertIn('=', fieldpart, line)
            self.assertFalse(fieldpart.endswith(','), line)


# group -> (measurement, the container whose row carries it)
GROUP_TARGET = {
    'engine': ('docker', ''),
    'cpu': ('docker_container_cpu', 'so-soc'),
    'mem': ('docker_container_mem', 'so-soc'),
    'net': ('docker_container_net', 'so-soc'),
    'blkio': ('docker_container_blkio', 'so-soc'),
    'status': ('docker_container_status', 'so-soc'),
    'health': ('docker_container_health', 'so-nginx'),
}


class TestEverySetting(CollectorTestCase):
    """Whatever is offered in defaults.yaml has to actually be collectable. These tests are driven
    off that file, so a new setting that is never wired up fails here rather than shipping."""

    def setUp(self):
        super().setUp()
        # an exited container so status.finished_at has a value to report
        self.inspect.append(container('so-idstools', IDSTOOLS_ID, 0, status='exited',
                                      started='2026-09-24T10:00:00.000000000Z',
                                      finished='2026-09-24T10:00:02.000000000Z'))

    def test_every_setting_emits_its_field_when_enabled(self):
        points = self.run_collector(all_enabled())
        for group, fields in shipped_defaults().items():
            if group == 'tags':
                continue
            measurement, name = GROUP_TARGET[group]
            if group == 'status':
                # finished_at only exists for a container that has actually exited
                _, exited = points[(measurement, 'so-idstools')]
                self.assertIn('finished_at', exited)
            _, emitted = points[(measurement, name)]
            for field in fields:
                if group == 'status' and field == 'finished_at':
                    continue
                self.assertIn(field, emitted, '%s.%s is offered but never emitted' % (group, field))

    def test_every_setting_is_individually_wired(self):
        # enabling one stat on its own must produce exactly that field, proving each toggle is
        # read rather than riding along with a neighbour
        for group, fields in shipped_defaults().items():
            if group == 'tags':
                continue
            measurement, name = GROUP_TARGET[group]
            for field in fields:
                settings = {other: {key: False for key in values} for other, values in shipped_defaults().items()}
                settings[group][field] = True
                target = 'so-idstools' if (group == 'status' and field == 'finished_at') else name
                points = self.run_collector(settings)
                self.assertIn((measurement, target), points, '%s.%s emitted no row' % (group, field))
                _, emitted = points[(measurement, target)]
                self.assertEqual(sorted(emitted), [field], '%s.%s did not emit itself alone' % (group, field))

    def test_all_enabled_values_are_exact(self):
        points = self.run_collector(all_enabled())
        clock = os.sysconf('SC_CLK_TCK')
        expected = {
            ('docker_container_cpu', 'so-soc'): {
                'usage_percent': '1.25', 'usage_total': '1000000u', 'usage_in_usermode': '600000u',
                'usage_in_kernelmode': '400000u', 'usage_system': '%du' % int(1000 * 10**9 / clock),
                'throttling_periods': '5u', 'throttling_throttled_periods': '2u',
                'throttling_throttled_time': '700000u', 'container_id': '"%s"' % SOC_ID,
            },
            ('docker_container_mem', 'so-soc'): {
                'usage': '950u', 'limit': '4000u', 'max_usage': '2500u', 'active_anon': '300u',
                'active_file': '40u', 'inactive_anon': '200u', 'inactive_file': '50u',
                'unevictable': '0u', 'pgfault': '1234u', 'pgmajfault': '56u',
                'usage_percent': '23.75', 'container_id': '"%s"' % SOC_ID,
            },
            ('docker_container_net', 'so-soc'): {
                'rx_bytes': '1500u', 'rx_packets': '15u', 'rx_errors': '1u', 'rx_dropped': '2u',
                'tx_bytes': '3000u', 'tx_packets': '30u', 'tx_errors': '3u', 'tx_dropped': '4u',
                'container_id': '"%s"' % SOC_ID,
            },
            ('docker_container_blkio', 'so-soc'): {
                'io_service_bytes_recursive_read': '110u',
                'io_service_bytes_recursive_write': '220u', 'container_id': '"%s"' % SOC_ID,
            },
            ('docker', ''): {
                'n_containers': '3i', 'n_containers_running': '3i', 'n_containers_stopped': '0i',
                'n_containers_paused': '0i', 'n_images': '9i', 'n_cpus': '8i', 'n_goroutines': '42i',
                'n_used_file_descriptors': '77i', 'n_listener_events': '1i',
                'memory_total': '16000000000i',
            },
            ('docker_container_health', 'so-nginx'): {
                'health_status': '"healthy"', 'failing_streak': '0i',
            },
        }
        for key, fields in expected.items():
            _, emitted = points[key]
            for field, value in fields.items():
                self.assertEqual(emitted[field], value, '%s %s' % (key[0], field))

    def test_status_values_are_exact(self):
        # uptime is relative to now, so it is checked separately from the fixed fields
        points = self.run_collector(all_enabled())
        _, running = points[('docker_container_status', 'so-soc')]
        self.assertEqual(running['pid'], '1001i')
        self.assertEqual(running['exitcode'], '0i')
        self.assertEqual(running['restart_count'], '0i')
        self.assertEqual(running['oomkilled'], 'false')
        self.assertEqual(running['container_id'], '"%s"' % SOC_ID)
        self.assertEqual(int(running['started_at'].rstrip('i')) // 10**9, 1790244000)
        self.assertGreater(int(running['uptime_ns'].rstrip('i')), 0)
        _, exited = points[('docker_container_status', 'so-idstools')]
        self.assertEqual(exited['uptime_ns'], '2000000000i')
        self.assertEqual(exited['finished_at'], '1790244002000000000i')

    def test_tags_identity_toggle_controls_the_identity_tags(self):
        settings = shipped_defaults()
        settings['tags']['identity'] = False
        tags, _ = self.run_collector(settings)[('docker_container_cpu', 'so-soc')]
        self.assertEqual(sorted(tags), ['container_name', 'container_status', 'cpu'])
        settings['tags']['identity'] = True
        tags, _ = self.run_collector(settings)[('docker_container_cpu', 'so-soc')]
        self.assertEqual(sorted(tags), ['container_image', 'container_name', 'container_status',
                                        'container_version', 'cpu', 'engine_host', 'server_version'])

    def test_identity_tags_cover_every_documented_tag(self):
        tags, _ = self.run_collector(all_enabled())[('docker_container_cpu', 'so-soc')]
        for tag in ('container_image', 'container_version', 'engine_host', 'server_version'):
            self.assertIn(tag, tags)


class TestTemplate(unittest.TestCase):

    def test_template_renders_to_valid_python_for_the_shipped_defaults(self):
        with open(TEMPLATE) as handle:
            source = handle.read()
        rendered = jinja2.Template(source, keep_trailing_newline=True).render(CONTAINER_STATS=shipped_defaults())
        compile(rendered, 'so-container-stats', 'exec')
        self.assertNotIn('{%', rendered)
        # the docker format strings must survive rendering untouched
        self.assertIn('{{json .}}', rendered)

    def test_every_annotated_setting_exists_in_defaults(self):
        # SOC reads both trees; an annotation without a default cannot be reverted in the UI
        with open(os.path.join(HERE, '..', '..', 'soc_telegraf.yaml')) as handle:
            annotated = yaml.safe_load(handle)['telegraf']['container_stats']
        defaults = shipped_defaults()
        for group, fields in annotated.items():
            self.assertIn(group, defaults)
            for field in fields:
                self.assertIn(field, defaults[group], '%s.%s annotated but missing from defaults' % (group, field))

    def test_every_default_setting_is_annotated_for_soc(self):
        with open(os.path.join(HERE, '..', '..', 'soc_telegraf.yaml')) as handle:
            annotated = yaml.safe_load(handle)['telegraf']['container_stats']
        for group, fields in shipped_defaults().items():
            self.assertIn(group, annotated)
            for field in fields:
                self.assertIn(field, annotated[group], '%s.%s missing a SOC annotation' % (group, field))


if __name__ == '__main__':
    unittest.main()
