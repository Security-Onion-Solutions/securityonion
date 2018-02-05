# PCAP Section

file.directory:
  - name: /opt/so/conf/steno

file.directory:
  - name: /nsm/pcap

so-steno:
  dockerng.running:
    - image: pillaritem/so-steno
    - network_mode: host
