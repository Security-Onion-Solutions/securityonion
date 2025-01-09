{% set qcow2_url = 'https://yum.oracle.com/templates/OracleLinux/OL9/u5/x86_64/OL9U5_x86_64-kvm-b253.qcow2' %}
{% set expected_sha256 = '3b00bbbefc8e78dd28d9f538834fb9e2a03d5ccdc2cadf2ffd0036c0a8f02021' %}
{% set target_path = '/nsm/libvirt/createvm/OL9U5_x86_64-kvm-b253.qcow2' %}
{% set master_id = salt.local.opts.get('id') %}

createvm_directories:
  salt.state:
    - tgt: {{ master_id }}
    - sls:
      - manager.hypervisor.directories

check_qcow2_exists:
  salt.function:
    - name: file.file_exists
    - tgt: {{ master_id }}
    - arg:
      - {{ target_path }}
    - require:
      - salt: createvm_directories

download_qcow2:
  salt.function:
    - name: cmd.run
    - tgt: {{ master_id }}
    - arg:
      - curl -L {{ qcow2_url }} -o {{ target_path }}
    - onlyif: 
      - fun: file.file_exists
        tgt: {{ master_id }}
        arg:
          - {{ target_path }}
        expected: False

verify_checksum:
  salt.function:
    - name: cmd.run_all
    - tgt: {{ master_id }}
    - arg:
      - echo "{{ expected_sha256 }}  {{ target_path }}" | sha256sum -c
    - require:
      - salt: download_qcow2
    - onlyif:
      - fun: file.file_exists
        tgt: {{ master_id }}
        arg:
          - {{ target_path }}

handle_failed_verification:
  salt.function:
    - name: log.error
    - tgt: {{ master_id }}
    - arg:
      - "Checksum verification failed for {{ target_path }}"
    - onfail:
      - salt: verify_checksum

cleanup_failed_download:
  salt.function:
    - name: file.remove
    - tgt: {{ master_id }}
    - arg:
      - {{ target_path }}
    - onfail:
      - salt: verify_checksum
    - require:
      - salt: verify_checksum
