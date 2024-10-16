{% from 'versionlock/map.jinja' import VERSIONLOCKMERGED %}

{% for pkg in VERSIONLOCKMERGED.hold %}
{{pkg}}_held:
  pkg.held:
    - name: {{pkg}}
{% endfor %}

{% for pkg in VERSIONLOCKMERGED.UNHOLD %}
{{pkg}}_unheld:
  pkg.unheld:
    - name: {{pkg}}
{% endfor %}
