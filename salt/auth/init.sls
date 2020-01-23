{% set VERSION = salt['pillar.get']('static:soversion', '1.1.4') %}
{% set MASTER = salt['grains.get']('master') %}

so-auth-api-dir:
  file.directory:
    - name: /opt/so/conf/auth/api
    - user: 939
    - group: 939
    - makedirs: True

so-auth-api:
    docker_container.running:
        - require:
            - so-auth-api-image
        - image: {{ MASTER }}:5000/soshybridhunter/so-auth-api:HH{{ VERSION }}
        - hostname: so-auth-api
        - name: so-auth-api
        - environment:
            - BASE_PATH: "/so-auth/api"
        - binds:
            - /opt/so/conf/auth/api:/data
        - port_bindings:
            - 0.0.0.0:5656:5656

so-auth-ui:
    docker_container.running:
        - require:
            - so-auth-ui-image
        - image: {{ MASTER }}:5000/soshybridhunter/so-auth-ui:HH{{ VERSION }}
        - hostname: so-auth-ui
        - name: so-auth-ui
        - port_bindings:
            - 0.0.0.0:4242:80
