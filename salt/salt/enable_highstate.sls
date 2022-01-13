enable_highstate:
  module.run:
    - state.enable:
      - states:
        - highstate
    - unless: pgrep soup
  