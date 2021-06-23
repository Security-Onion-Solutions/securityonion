# The creation of a user will require a pub key placed in /opt/so/saltstack/local/salt/users/authorized_keys/<username>

# If a user is changed from present to absent, their usergroup will be removed, but any additional usergroups that were created
# for that user will remain.

{% from 'users/map.jinja' import reserved_usernames with context %}

{% for username, userdeets in pillar.get('users', {}).items() if username not in reserved_usernames %}
  {% if 'status' in userdeets %}
    {% if userdeets.status == 'absent' %}

remove_user_{{username}}:
  user.absent:
    - name: {{ username }}
    {% if 'purge' in userdeets %}
    - purge: {{ userdeets.purge }}
    {% endif %}
    - force: True

  {% elif userdeets.status == 'present' %}

    {% if 'node_access' in userdeets %}
      {% if grains.role in userdeets.node_access or grains.id.split('_')|last in userdeets.node_access %}

add_user_group_{{username}}:
  group.present:
    - name: {{ username }}
        {% if 'uid' in userdeets %}
    - gid: {{ userdeets.uid }}
        {% endif %}

add_user_{{username}}:
  user.present:
    - name: {{ username }}
    - home: {{ userdeets.get('home', "/home/%s" % username) }}
    - shell: {{ userdeets.get('shell', '/bin/bash') }}
    - usergroup: True

        {% if 'fullname' in userdeets %}
    - fullname: {{ userdeets.fullname }}
        {% endif %}

        {% if 'uid' in userdeets %}
    - uid: {{ userdeets.uid }}
        {% endif %}

        {% if 'gid' in userdeets %}
    - gid: {{ userdeets.gid }}
        {% endif %}

        {% if 'roomnumber' in userdeets %}
    - roomnumber: {{ userdeets.roomnumber }}
        {% endif %}

        {% if 'workphone' in userdeets %}
    - workphone: {{ userdeets.workphone }}
        {% endif %}

        {% if 'homephone' in userdeets %}
    - homephone: {{ userdeets.homephone }}
        {% endif %}

        {% if 'groups' in userdeets %}
    - groups:
          {% for group in userdeets.groups %}
      - {{ group }}
          {% endfor %}
        {% endif %}

{{username}}_authorized_keys:
  file.managed:
    - name: /home/{{username}}/.ssh/authorized_keys
    - source: salt://users/authorized_keys/{{username}}
    - user: {{username}}
    - group: {{username}}
    - mode: 644
    - show_diff: False
    - makedirs: True
    - require:
      - user: add_user_{{username}}

      {% endif %}
    {% endif %}

  {% else %}

unknown_status_or_password_not_provided_for_user_{{username}}:
  test.fail_without_changes:
    - comment: "Verify status is 'present' or 'absent' and a password is provided for {{username}} in the users pillar."

    {% endif %}

  {% else %}

status_not_provided_for_user_{{username}}:
  test.fail_without_changes:
    - comment: "Status should be 'present' or 'absent'."

  {% endif %}
{% endfor %}

disable_wheel_pwd_required:
  file.comment:
    - name: /etc/sudoers
    - regex: "%wheel\\s+ALL=\\(ALL\\)\\s+ALL"

allow_wheel_no_pwd:
  file.uncomment:
    - name: /etc/sudoers
    - regex: "%wheel\\s+ALL=\\(ALL\\)\\s+NOPASSWD: ALL"
