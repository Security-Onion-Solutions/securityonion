schedule:
  schedule.present:
    - function: state.highstate
    - minutes: 15
    - maxrunning: 1
