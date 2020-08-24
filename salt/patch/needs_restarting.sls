needs_restarting:
  module.run:
    - mine.send:
      - name: needs_restarting.check
    - order: last
