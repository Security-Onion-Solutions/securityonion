{% if grains['role'] == 'so-sensor' or grains['role'] == 'so-eval' %}

so-tcpreplayimage:
 cmd.run:
   - name: docker pull --disable-content-trust=false docker.io/soshybridhunter/so-tcpreplay:HH1.1.4

so-tcpreplay:
  docker_container.running:
    - require:
      - so-tcpreplayimage
    - network_mode: "host"
    - image: docker.io/soshybridhunter/so-tcpreplay:HH1.1.4
    - name: so-tcpreplay
    - user: root
    - interactive: True
    - tty: True
    
{% endif %}
