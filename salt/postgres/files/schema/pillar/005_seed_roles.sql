-- Seed the so_pillar.role table with the role buckets defined in pillar/top.sls.
-- The match_expr column preserves the original Salt compound expression purely
-- as documentation; PG-side membership is materialised in role_member.
-- Idempotent: ON CONFLICT lets re-application leave existing rows untouched.

INSERT INTO so_pillar.role(role_name, match_kind, match_expr, description) VALUES
    ('manager',       'compound', '*_manager or *_managersearch or *_managerhype',
        'Manager-class node. Includes managersearch and managerhype subtypes.'),
    ('managersearch', 'compound', '*_managersearch',
        'Combined manager + searchnode role.'),
    ('managerhype',   'compound', '*_managerhype',
        'Combined manager + hypervisor role.'),
    ('sensor',        'compound', '*_sensor',
        'Sensor node running zeek/suricata/strelka.'),
    ('eval',          'compound', '*_eval',
        'Single-node evaluation install (manager + sensor + storage on one host).'),
    ('standalone',    'compound', '*_standalone',
        'Single-node production install (no distributed cluster).'),
    ('heavynode',     'compound', '*_heavynode',
        'Distributed manager node carrying logstash + ES.'),
    ('idh',           'compound', '*_idh',
        'Intrusion-detection-honeypot node.'),
    ('searchnode',    'compound', '*_searchnode',
        'Distributed Elasticsearch search node.'),
    ('receiver',      'compound', '*_receiver',
        'Kafka receiver node.'),
    ('import',        'compound', '*_import',
        'Single-node import-only install.'),
    ('fleet',         'compound', '*_fleet',
        'Elastic Fleet server node.'),
    ('hypervisor',    'compound', '*_hypervisor',
        'Hypervisor host (libvirt). Hosts VM minions.'),
    ('desktop',       'compound', '*_desktop',
        'Desktop minion (no firewall/nginx pillars apply).'),
    ('not_desktop',   'compound', '* and not *_desktop',
        'Pseudo-role; matches every minion that is not a desktop. Used for global firewall/nginx.'),
    ('libvirt',       'grain',    'salt-cloud:driver:libvirt',
        'Pseudo-role; matches any minion with grain salt-cloud.driver = libvirt.')
ON CONFLICT (role_name) DO NOTHING;
