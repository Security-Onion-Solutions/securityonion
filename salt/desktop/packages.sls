{% from 'vars/globals.map.jinja' import GLOBALS %}

{# we only want this state to run it is CentOS #}
{% if GLOBALS.os == 'OEL' %}


desktop_packages:
  pkg.installed:
    - pkgs:
      - ModemManager
      - ModemManager-glib
      - NetworkManager
      - NetworkManager-adsl
      - NetworkManager-bluetooth
      - NetworkManager-config-server
      - NetworkManager-libnm
      - NetworkManager-team
      - NetworkManager-tui
      - NetworkManager-wifi
      - NetworkManager-wwan
      - PackageKit
      - PackageKit-command-not-found
      - PackageKit-glib
      - PackageKit-gstreamer-plugin
      - PackageKit-gtk3-module
      - audit
      - audit-libs
      - authselect
      - authselect-libs
      - avahi
      - avahi-glib
      - avahi-libs
      - baobab
      - basesystem
      - bc
      - bcache-tools
      - bluez
      - bluez-libs
      - bluez-obexd
      - bolt
      - bzip2
      - bzip2-libs
      - c-ares
      - ca-certificates
      - cairo
      - cairo-gobject
      - cairomm
      - checkpolicy
      - cheese
      - cheese-libs
      - chkconfig
      - chrome-gnome-shell
      - clutter
      - clutter-gst3
      - clutter-gtk
      - cogl
      - color-filesystem
      - colord
      - colord-gtk
      - colord-libs
      - conmon
      - cups
      - cups-client
      - cups-filesystem
      - cups-filters
      - cups-filters-libs
      - cups-ipptool
      - cups-libs
      - cups-pk-helper
      - dconf
      - dejavu-sans-fonts
      - dejavu-sans-mono-fonts
      - dejavu-serif-fonts
      - desktop-file-utils
      - evolution-data-server
      - evolution-data-server-langpacks
      - firefox
      - flac-libs
      - flashrom
      - flatpak
      - flatpak-libs
      - flatpak-selinux
      - flatpak-session-helper
      - fontconfig
      - fonts-filesystem
      - foomatic
      - foomatic-db
      - foomatic-db-filesystem
      - foomatic-db-ppds
      - freetype
      - fuse
      - fuse-common
      - fuse-libs
      - fuse-overlayfs
      - fuse3
      - fuse3-libs
      - fwupd
      - fwupd-plugin-flashrom
      - gcr
      - gcr-base
      - gd
      - gdbm-libs
      - gdisk
      - gdk-pixbuf2
      - gdk-pixbuf2-modules
      - gdm
      - gedit
      - geoclue2
      - geoclue2-libs
      - geocode-glib
      - gettext
      - gettext-libs
      - ghostscript
      - ghostscript-tools-fonts
      - ghostscript-tools-printing
      - giflib
      - glx-utils
      - gmp
      - gnome-autoar
      - gnome-bluetooth
      - gnome-bluetooth-libs
      - gnome-calculator
      - gnome-characters
      - gnome-classic-session
      - gnome-color-manager
      - gnome-control-center
      - gnome-control-center-filesystem
      - gnome-desktop3
      - gnome-disk-utility
      - gnome-font-viewer
      - gnome-initial-setup
      - gnome-keyring
      - gnome-keyring-pam
      - gnome-logs
      - gnome-menus
      - gnome-online-accounts
      - gnome-remote-desktop
      - gnome-screenshot
      - gnome-session
      - gnome-session-wayland-session
      - gnome-session-xsession
      - gnome-settings-daemon
      - gnome-shell
      - gnome-shell-extension-apps-menu
      - gnome-shell-extension-background-logo
      - gnome-shell-extension-common
      - gnome-shell-extension-desktop-icons
      - gnome-shell-extension-launch-new-instance
      - gnome-shell-extension-places-menu
      - gnome-shell-extension-window-list
      - gnome-software
      - gnome-system-monitor
      - gnome-terminal
      - gnome-terminal-nautilus
      - gnome-tour
      - gnome-user-docs
      - gnome-video-effects
      - gobject-introspection
      - gom
      - google-droid-sans-fonts
      - google-noto-cjk-fonts-common
      - google-noto-emoji-color-fonts
      - google-noto-fonts-common
      - google-noto-sans-cjk-ttc-fonts
      - google-noto-sans-gurmukhi-fonts
      - google-noto-sans-sinhala-vf-fonts
      - google-noto-serif-cjk-ttc-fonts
      - gpgme
      - gpm-libs
      - graphene
      - graphite2
      - gsettings-desktop-schemas
      - gsm
      - gsound
      - gspell
      - gstreamer1
      - gstreamer1-plugins-bad-free
      - gstreamer1-plugins-base
      - gstreamer1-plugins-good
      - gstreamer1-plugins-good-gtk
      - gstreamer1-plugins-ugly-free
      - gtk-update-icon-cache
      - gtk3
      - gtk4
      - gtkmm30
      - gtksourceview4
      - gutenprint
      - gutenprint-cups
      - gutenprint-doc
      - gutenprint-libs
      - gvfs
      - gvfs-client
      - gvfs-fuse
      - gvfs-goa
      - gvfs-gphoto2
      - gvfs-mtp
      - gvfs-smb
      - gzip
      - harfbuzz
      - harfbuzz-icu
      - hdparm
      - hicolor-icon-theme
      - highcontrast-icon-theme
      - hplip-common
      - hplip-libs
      - hunspell
      - hunspell-en
      - hunspell-en-GB
      - hunspell-en-US
      - hunspell-filesystem
      - hyphen
      - ibus
      - ibus-gtk3
      - ibus-libs
      - ibus-setup
      - iio-sensor-proxy
      - ima-evm-utils
      - inih
      - initscripts-rename-device
      - initscripts-service
      - iso-codes
      - jansson
      - jbig2dec-libs
      - jbigkit-libs
      - jomolhari-fonts
      - jose
      - jq
      - json-c
      - json-glib
      - julietaula-montserrat-fonts
      - kbd
      - kbd-misc
      - khmer-os-system-fonts
      - langpacks-core-en
      - langpacks-core-font-en
      - langpacks-en
      - lcms2
      - libICE
      - libSM
      - libX11
      - libX11-common
      - libX11-xcb
      - libXau
      - libXcomposite
      - libXcursor
      - libXdamage
      - libXdmcp
      - libXext
      - libXfixes
      - libXfont2
      - libXft
      - libXi
      - libXinerama
      - libXmu
      - libXpm
      - libXrandr
      - libXrender
      - libXres
      - libXt
      - libXtst
      - libXv
      - libXxf86dga
      - libXxf86vm
      - libappstream-glib
      - liberation-fonts-common
      - liberation-mono-fonts
      - liberation-sans-fonts
      - liberation-serif-fonts
      - libertas-sd8787-firmware
      - libglvnd-gles
      - libglvnd-glx
      - libglvnd-opengl
      - libgnomekbd
      - libgomp
      - libgphoto2
      - lockdev
      - lohit-assamese-fonts
      - lohit-bengali-fonts
      - lohit-devanagari-fonts
      - lohit-gujarati-fonts
      - lohit-kannada-fonts
      - lohit-odia-fonts
      - lohit-tamil-fonts
      - lohit-telugu-fonts
      - mesa-dri-drivers
      - mesa-filesystem
      - mesa-libEGL
      - mesa-libGL
      - mesa-libgbm
      - mesa-libglapi
      - mesa-libxatracker
      - mesa-vulkan-drivers
      - microcode_ctl
      - mobile-broadband-provider-info
      - mozilla-filesystem
      - mpfr
      - mpg123-libs
      - mtdev
      - mtr
      - nautilus
      - nautilus-extensions
      - oracle-backgrounds
      - oracle-indexhtml
      - oracle-logos
      - pcaudiolib
      - pinentry
      - pinentry-gnome3
      - pinfo
      - pipewire
      - pipewire-alsa
      - pipewire-gstreamer
      - pipewire-jack-audio-connection-kit
      - pipewire-libs
      - pipewire-pulseaudio
      - pipewire-utils
      - pixman
      - plymouth
      - plymouth-core-libs
      - plymouth-graphics-libs
      - plymouth-plugin-label
      - plymouth-plugin-two-step
      - plymouth-scripts
      - plymouth-system-theme
      - plymouth-theme-spinner
      - policycoreutils
      - policycoreutils-python-utils
      - pt-sans-fonts
      - pulseaudio-libs
      - pulseaudio-libs-glib2
      - pulseaudio-utils
      - sane-airscan
      - sane-backends
      - sane-backends-drivers-cameras
      - sane-backends-drivers-scanners
      - sane-backends-libs
      - sil-abyssinica-fonts
      - sil-nuosu-fonts
      - sil-padauk-fonts
      - smartmontools
      - smc-meera-fonts
      - snappy
      - sound-theme-freedesktop
      - soundtouch
      - speech-dispatcher
      - speech-dispatcher-espeak-ng
      - speex
      - spice-vdagent
      - switcheroo-control
      - symlinks
      - system-config-printer-libs
      - system-config-printer-udev
      - taglib
      - tcpdump
      - thai-scalable-fonts-common
      - thai-scalable-waree-fonts
      - totem
      - totem-pl-parser
      - totem-video-thumbnailer
      - tpm2-tools
      - tpm2-tss
      - tracer-common
      - tracker
      - tracker-miners
      - tree
      - tuned
      - twolame-libs
      - tzdata
      - udisks2
      - udisks2-iscsi
      - udisks2-lvm2
      - unzip
      - upower
      - urw-base35-bookman-fonts
      - urw-base35-c059-fonts
      - urw-base35-d050000l-fonts
      - urw-base35-fonts
      - urw-base35-fonts-common
      - urw-base35-gothic-fonts
      - urw-base35-nimbus-mono-ps-fonts
      - urw-base35-nimbus-roman-fonts
      - urw-base35-nimbus-sans-fonts
      - urw-base35-p052-fonts
      - urw-base35-standard-symbols-ps-fonts
      - urw-base35-z003-fonts
      - usb_modeswitch
      - usb_modeswitch-data
      - usbutils
      - usermode
      - userspace-rcu
      - vdo
      - vulkan-loader
      - wavpack
      - webkit2gtk3
      - webkit2gtk3-jsc
      - webrtc-audio-processing
      - wireless-regdb
      - wireplumber
      - wireplumber-libs
      - woff2
      - words
      - wpa_supplicant
      - wpebackend-fdo
      - xdg-dbus-proxy
      - xdg-desktop-portal
      - xdg-desktop-portal-gnome
      - xdg-desktop-portal-gtk
      - xdg-user-dirs
      - xdg-user-dirs-gtk
      - xdg-utils
      - xkeyboard-config
      - xorg-x11-drv-evdev
      - xorg-x11-drv-fbdev
      - xorg-x11-drv-libinput
      - xorg-x11-drv-vmware
      - xorg-x11-drv-wacom
      - xorg-x11-drv-wacom-serial-support
      - xorg-x11-server-Xorg
      - xorg-x11-server-Xwayland
      - xorg-x11-server-common
      - xorg-x11-server-utils
      - xorg-x11-utils
      - xorg-x11-xauth
      - xorg-x11-xinit
      - xorg-x11-xinit-session
#
#      - aajohan-comfortaa-fonts
#      - abattis-cantarell-fonts
#      - acl
#      - alsa-ucm
#      - alsa-utils
#      - anaconda
#      - anaconda-install-env-deps
#      - at
#      - attr
#      - audit
#      - authselect
#      - basesystem
#      - bash
#      - bash-completion
#      - bc
#      - blktrace
#      - bluez
#      - bolt
#      - bpftool
#      - bzip2
#      - chkconfig
#      - chromium
#      - chrony
#      - cockpit
#      - coreutils
#      - cpio
#      - cronie
#      - crontabs
#      - crypto-policies
#      - crypto-policies-scripts
#      - cryptsetup
#      - curl
#      - cyrus-sasl-plain
#      - dbus
#      - dejavu-sans-fonts
#      - dejavu-sans-mono-fonts
#      - dejavu-serif-fonts
#      - dnf
#      - dnf-plugins-core
#      - dos2unix
#      - dosfstools
#      - dracut-config-rescue
#      - dracut-live
#      - dsniff
#      - e2fsprogs
#      - ed
#      - efibootmgr
#      - efi-filesystem
#      - efivar-libs
#      - eom
#      - ethtool
#      - file
#      - filesystem
#      - firewall-config
#      - firewalld
#      - fprintd-pam
#      - gdm
#      - git
#      - glibc
#      - glibc-all-langpacks
#      - gnome-autoar
#      - gnome-bluetooth
#      - gnome-bluetooth-libs
#      - gnome-calculator
#      - gnome-characters
#      - gnome-color-manager
#      - gnome-control-center
#      - gnome-desktop3
#      - gnome-disk-utility
#      - gnome-font-viewer
#      - gnome-initial-setup
#      - gnome-keyring
#      - gnome-keyring-pam
#      - gnome-logs
#      - gnome-menus
#      - gnome-online-accounts
#      - gnome-remote-desktop
#      - gnome-screenshot
#      - gnome-session
#      - gnome-session-wayland-session
#      - gnome-session-xsession
#      - gnome-settings-daemon
#      - gnome-shell
#      - gnome-software
#      - gnome-system-monitor
#      - gnome-terminal
#      - gnome-terminal-nautilus
#      - gnome-tour
#      - gnupg2
#      - google-noto-emoji-color-fonts
#      - google-noto-sans-cjk-ttc-fonts
#      - google-noto-sans-gurmukhi-fonts
#      - google-noto-sans-sinhala-vf-fonts
#      - google-noto-serif-cjk-ttc-fonts
#      - grub2-common
#      - grub2-pc-modules
#      - grub2-tools
#      - grub2-tools-efi
#      - grub2-tools-extra
#      - grub2-tools-minimal
#      - grubby
#      - gstreamer1-plugins-bad-free
#      - gstreamer1-plugins-good
#      - gstreamer1-plugins-ugly-free
#      - gvfs-gphoto2
#      - gvfs-mtp
#      - gvfs-smb
#      - hostname
#      - hyperv-daemons
#      - ibus-anthy
#      - ibus-hangul
#      - ibus-libpinyin
#      - ibus-libzhuyin
#      - ibus-m17n
#      - ibus-typing-booster
#      - imsettings-systemd
#      - initial-setup-gui
#      - initscripts
#      - initscripts-rename-device
#      - iproute
#      - iproute-tc
#      - iprutils
#      - iputils
#      - irqbalance
#      - iwl1000-firmware
#      - iwl100-firmware
#      - iwl105-firmware
#      - iwl135-firmware
#      - iwl2000-firmware
#      - iwl2030-firmware
#      - iwl3160-firmware
#      - iwl5000-firmware
#      - iwl5150-firmware
#      - iwl6000g2a-firmware
#      - iwl6000g2b-firmware
#      - iwl6050-firmware
#      - iwl7260-firmware
#      - jomolhari-fonts
#      - julietaula-montserrat-fonts
#      - kbd
#      - kernel
#      - kernel-modules
#      - kernel-modules-extra
#      - kernel-tools
#      - kexec-tools
#      - khmer-os-system-fonts
#      - kmod-kvdo
#      - ledmon
#      - less
#      - liberation-mono-fonts
#      - liberation-sans-fonts
#      - liberation-serif-fonts
#      - libertas-sd8787-firmware
#      - libstoragemgmt
#      - libsysfs
#      - lightdm
#      - linux-firmware
#      - logrotate
#      - lohit-assamese-fonts
#      - lohit-bengali-fonts
#      - lohit-devanagari-fonts
#      - lohit-gujarati-fonts
#      - lohit-kannada-fonts
#      - lohit-odia-fonts
#      - lohit-tamil-fonts
#      - lohit-telugu-fonts
#      - lshw
#      - lsof
#      - lsscsi
#      - lvm2
#      - mailcap
#      - man-db
#      - man-pages
#      - mcelog
#      - mdadm
#      - memtest86+
#      - metacity
#      - microcode_ctl
#      - mlocate
#      - mtr
#      - nano
#      - ncurses
#      - netronome-firmware
#      - net-tools
#      - NetworkManager
#      - NetworkManager-adsl
#      - NetworkManager-bluetooth
#      - NetworkManager-l2tp-gnome
#      - NetworkManager-libreswan-gnome
#      - NetworkManager-openconnect-gnome
#      - NetworkManager-openvpn-gnome
#      - NetworkManager-ppp
#      - NetworkManager-pptp-gnome
#      - NetworkManager-team
#      - NetworkManager-tui
#      - NetworkManager-wifi
#      - NetworkManager-wwan
#      - ngrep
#      - nmap-ncat
#      - nm-connection-editor
#      - nvme-cli
#      - openssh-clients
#      - openssh-server
#      - open-vm-tools-desktop
#      - p11-kit
#      - PackageKit-gstreamer-plugin
#      - paktype-naskh-basic-fonts
#      - parole
#      - parted
#      - passwd
#      - pciutils
#      - pinfo
#      - pipewire
#      - pipewire-alsa
#      - pipewire-gstreamer
#      - pipewire-jack-audio-connection-kit
#      - pipewire-pulseaudio
#      - pipewire-utils
#      - plymouth
#      - policycoreutils
#      - powerline
#      - ppp
#      - prefixdevname
#      - procps-ng
#      - psacct
#      - pt-sans-fonts
#      - python3-libselinux
#      - python3-scapy
#      - qemu-guest-agent
#      - quota
#      - realmd
#      - redshift-gtk
#      - rootfiles
#      - rpm
#      - rpm-plugin-audit
#      - rsync
#      - rsyslog
#      - rsyslog-gnutls
#      - rsyslog-gssapi
#      - rsyslog-relp
#      - salt-minion
#      - sane-backends-drivers-scanners
#      - selinux-policy-targeted
#      - setroubleshoot
#      - setup
#      - sg3_utils
#      - sg3_utils-libs
#      - shadow-utils
#      - sil-abyssinica-fonts
#      - sil-nuosu-fonts
#      - sil-padauk-fonts
#      - slick-greeter
#      - slick-greeter-cinnamon
#      - smartmontools
#      - smc-meera-fonts
#      - sos
#      - spice-vdagent
#      - ssldump
#      - sssd
#      - sssd-common
#      - sssd-kcm
#      - stix-fonts
#      - strace
#      - sudo
#      - symlinks
#      - syslinux
#      - systemd
#      - systemd-udev
#      - tar
#      - tcpdump
#      - tcpflow
#      - teamd
#      - thai-scalable-waree-fonts
#      - time
#      - tmux
#      - tmux-powerline
#      - transmission
#      - tree
#      - tuned
#      - unzip
#      - usb_modeswitch
#      - usbutils
#      - util-linux
#      - util-linux-user
#      - vdo
#      - vim-enhanced
#      - vim-minimal
#      - vim-powerline
#      - virt-what
#      - wget
#      - which
#      - whois
#      - wireplumber
#      - wireshark
#      - words
#      - xdg-user-dirs-gtk
#      - xed
#      - xfsdump
#      - xfsprogs
#      - xreader
#      - yum
#      - zip
#
{% else %}

desktop_packages_os_fail:
  test.fail_without_changes:
    - comment: 'SO desktop can only be installed on Oracle Linux'

{% endif %}
