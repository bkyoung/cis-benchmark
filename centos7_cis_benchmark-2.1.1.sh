#!/bin/bash

###############################
# CIS Benchmark CentOS 7 v2.1.1
###############################
CIS_LEVEL=1
INCLUDE_UNSCORED=0
WIDTH=79
if [ $CIS_LEVEL -gt 1 ];then
  RESULT_FIELD=10
else
  RESULT_FIELD=6
fi
MSG_FIELD=$(($WIDTH - $RESULT_FIELD))
RED=$(tput setaf 1)
GREEN=$(tput setaf 2)
YELLOW=$(tput setaf 3)
NC=$(tput sgr0)
PASSED_CHECKS=0
FAILED_CHECKS=0

function header() {
    local HEADING=$1
    local TEXT=$((${#HEADING}+2))
    local LBAR=5
    local RBAR=$(($WIDTH - $TEXT - $LBAR))
    echo ""
    for (( x=0; x < $LBAR; x++));do
        printf %s '#'
    done
    echo -n " $HEADING "
    for (( x=0; x < $RBAR; x++));do
        printf %s '#'
    done
    echo ""
}

function msg() {
  printf "%-${MSG_FIELD}s" " - ${1}"
}

function success_result() {
    PASSED_CHECKS=$((PASSED_CHECKS+1))
    local RESULT="$GREEN${1:-PASSED}$NC"
    printf "%-${RESULT_FIELD}s\n" $RESULT
}

function failed_result() {
    FAILED_CHECKS=$((FAILED_CHECKS+1))
    local RESULT="$RED${1:-FAILED}$NC"
    printf "%-${RESULT_FIELD}s\n" $RESULT
}

function warning_result() {
    local RESULT="$YELLOW${1:-NOT CHECKED}$NC"
    printf "%-${RESULT_FIELD}s\n" $RESULT
}

function check_retval_eq_0() {
  RETVAL=$1
  if [ $RETVAL -eq 0 ]; then
    success_result
  else
    failed_result
  fi
}

function check_retval_ne_0() {
  RETVAL=$1
  if [ $RETVAL -ne 0 ]; then
    success_result
  else
    failed_result
  fi
}

#################
# 1 Initial Setup
#################
  ##############################
  # 1.1 Filesystem Configuration
  ##############################
    ##################################
    # 1.1.1 Disable Unused Filesystems
    ##################################
    let i=0
    for module in cramfs freevxfs jffs2 hfs hfsplus squashfs udf vfat;do
      i=$((i+1))
      header "1.1.1.${i} $module disabled"
      MODPROBE_COMMAND="modprobe -n -v $module"
      LSMOD_COMMAND="lsmod | grep $module"
      
      msg " $MODPROBE_COMMAND"
      if [[ $(eval $MODPROBE_COMMAND 2>&1) =~ install.*/bin/true ]];then
          LEVEL1_PASSED=$(($LEVEL1_PASSED + 1))
          success_result
      else
          LEVEL1_FAILED=$(($LEVEL1_FAILED + 1))
          failed_result
      fi
  
      msg " $LSMOD_COMMAND"
      if [[ $(eval $LSMOD_COMMAND 2>&1) =~ ^$ ]];then
          success_result
      else
          failed_result
      fi
    done

    ##################################
    # 1.1.2 - 1.1.5 /tmp setup
    ##################################
    if [ $CIS_LEVEL -gt 1 ];then
        FURTHER_TMP_CHECKS=1
        header "1.1.2 /tmp on own partition"
        msg " mount | grep /tmp"
        mount | grep ^/tmp 2>&1 > /dev/null
        check_retval_eq_0 $?
    
        if [ $FURTHER_TMP_CHECKS -gt 0 ];then
            let tmp=2
            for option in nodev nosuid noexec;do
                tmp=$((tmp+1))
                header "1.1.${tmp} Ensure $option mount option set on /tmp"
                msg " mount | grep /tmp | grep $option"
                mount | grep ^/tmp | grep $option 2>&1 > /dev/null
                check_retval_eq_0 $?
            done
        fi
    fi

    ##################################
    # 1.1.6 /var setup
    ##################################
    if [ $CIS_LEVEL -gt 1 ];then
      header "1.1.6 /var on own partition"
      msg " mount | grep /var"
      mount | grep ^/var 2>&1 > /dev/null
      check_retval_eq_0 $?
    fi
    
    ##################################
    # 1.1.7 /var/tmp setup
    ##################################
    if [ $CIS_LEVEL -gt 1 ];then
      FURTHER_VAR_TMP_CHECKS=1
      header "1.1.7 /var/tmp on own partition"
      msg " mount | grep /var/tmp"
      mount | grep ^/var/tmp 2>&1 > /dev/null
      if [ $? -eq 0 ];then
          success_result
      else
          FURTHER_VAR_TMP_CHECKS=0
          failed_result
      fi
  
      if [ $FURTHER_VAR_TMP_CHECKS -gt 0 ];then
          let tmp=7
          for option in nodev nosuid noexec;do
              tmp=$((tmp+1))
              header "1.1.${tmp} Ensure $option mount option set on /var/tmp"
              msg " mount | grep /var/tmp | grep $option"
              mount | grep ^/var/tmp | grep $option 2>&1 > /dev/null
              check_retval_eq_0 $?
          done
      fi
    fi
    ##################################
    # 1.1.11 /var/log setup
    ##################################
    if [ $CIS_LEVEL -gt 1 ];then
        header "1.1.11 /var/log on own partition"
        msg " mount | grep /var/log"
        mount | grep ^/var/log 2>&1 > /dev/null
        check_retval_eq_0 $?
    fi

    ##################################
    # 1.1.12 /var/log/audit setup
    ##################################
    if [ $CIS_LEVEL -gt 1 ];then
        header "1.1.12 /var/log/audit on own partition"
        msg " mount | grep /var/log/audit"
        mount | grep ^/var/log/audit 2>&1 > /dev/null
        check_retval_eq_0 $?
    fi

    ##################################
    # 1.1.13 /home setup
    ##################################
    if [ $CIS_LEVEL -gt 1 ];then
        FURTHER_HOME_CHECKS=1
        header "1.1.13 /home on own partition"
        msg " mount | grep /home"
        mount | grep  -w /home 2>&1 > /dev/null
        check_retval_eq_0 $?
    
        if [ $FURTHER_HOME_CHECKS -gt 0 ];then
            let tmp=13
            for option in nodev;do
                tmp=$((tmp+1))
                header "1.1.${tmp} Ensure $option mount option set on /home"
                msg " mount | grep /home | grep $option"
                mount | grep ^/home | grep $option 2>&1 > /dev/null
                check_retval_eq_0 $?
            done
        fi
    fi

    ##################################
    # 1.1.15 /dev/shm setup
    ##################################
    let tmp=14
    for option in nodev nosuid noexec;do
        tmp=$((tmp+1))
        header "1.1.${tmp} Ensure $option mount option set on /dev/shm"
        msg " mount | grep /dev/shm | grep $option"
        mount | grep -w /dev/shm | grep $option 2>&1 > /dev/null
        check_retval_eq_0 $?
    done

    ##################################
    # 1.1.18 - 1.1.20 removable media
    ##################################
    if [ $INCLUDE_UNSCORED -gt 0 ];then
        header "1.1.18 - 1.1.20 removable media setup"
        printf "%50s"
        warning_result
    fi

    ##################################
    # 1.1.21 Sticky Bit Set
    ##################################
    header "1.1.21 Sticky bit on world-writable dirs"
    msg
    df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null
    check_retval_eq_0 $?

    ##################################
    # 1.1.22 autofs Disabled
    ##################################
    header "1.1.22 Ensure autofs is disabled"
    msg " systemctl is-enabled autofs"
    if ! [[ $(systemctl is-enabled autofs 2>&1) =~ ^enabled$ ]];then
        success_result
    else
        failed_result
    fi
  
  ################################
  # 1.2 Configure Software Updates
  ################################
    #######################################
    # 1.2.1 Ensure yum repos are configured
    #######################################
    if [ $INCLUDE_UNSCORED -gt 0 ];then
        header "1.2.1 Ensure yum repos are configured"
        msg " yum repolist"
        warning_result
    fi

    #######################################
    # 1.2.2 Ensure GPG Keys are configured
    #######################################
    if [ $INCLUDE_UNSCORED -gt 0 ];then
        header "1.2.1 Ensure gpg keys are configured"
        msg " rpm -q gpg-pubkey"
        warning_result
    fi

    ########################################
    # 1.2.3 Ensure gpgcheck enabled globally
    ########################################
    header "1.2.3 Ensure gpgcheck enabled"
    msg " grep ^gpgcheck /etc/yum.conf"
    if [[ $(grep ^gpgcheck /etc/yum.conf) =~ gpgcheck=1 ]];then
        success_result
    else
        failed_result
    fi
    msg " grep ^gpgcheck /etc/yum.repos.d/*"
    if [ $(grep ^gpgcheck /etc/yum.repos.d/* | grep -v gpgcheck=1 | wc -l) -eq 0 ];then
        success_result
    else
        failed_result
    fi

  ################################
  # 1.3 Filesystem Integrity Check
  ################################
    #######################################
    # 1.3.1 Ensure aide installed
    #######################################
    header "1.3.1 aide installed"
    msg " rpm -q aide"
    rpm -q aide 2>&1 > /dev/null
    check_retval_eq_0 $?

    #######################################
    # 1.3.2 Ensure aide cron exists
    #######################################
    header "1.3.2 aide cron installed"
    msg
    grep -r aide /etc/cron.* /etc/crontab 2>&1 > /dev/null
    check_retval_eq_0 $?

  ################################
  # 1.4 Secure Boot Settings
  ################################
    ##############################################################
    # 1.4.1 Ensure permissions on bootloader config are configured
    ##############################################################
    header "1.4.1 Check bootlader filesystem permissions"
    msg " Ensure bootloader permissions are 0600 root:root"
    if [[ $(stat /boot/grub2/grub.cfg) =~ Access:.*(0600/-rw-------).*Uid:.*(.*0/.*root).*Gid:.*(.*0/.*root) ]];then
        success_result
    else
        failed_result
    fi
    
    #########################################
    # 1.4.2 Ensure bootloader password is set
    #########################################
    header "1.4.2 Ensure bootloader password is set"
    msg ' grep "^set superusers" /boot/grub2/grub.cfg'
    grep "^set superusers" /boot/grub2/grub.cfg 2>&1 > /dev/null
    check_retval_eq_0 $?
    
    msg ' grep "^password" /boot/grub2/grub.cfg'
    grep "^password" /boot/grub2/grub.cfg 2>&1 > /dev/null
    check_retval_eq_0 $?

    #################################################
    # 1.4.3 Ensure auth required for single user mode
    #################################################
    if [ $INCLUDE_UNSCORED -gt 0 ];then
        header "1.4.3 Ensure auth required for single user mode"
        msg
        warning_result
    fi

  ##################################
  # 1.5 Additional Process Hardening
  ##################################
    ########################################
    # 1.5.1 Ensure core dumps are restricted
    ########################################
    header "1.5.1 Ensure core dumps are restricted"
    msg 'grep "hard core" /etc/security/limits.conf'
    grep "hard core" /etc/security/limits.conf /etc/security/limits.d/* 2>&1 > /dev/null
    check_retval_eq_0 $?
    msg ' sysctl fs.suid_dumpable'
    if [[ "$(sysctl fs.suid_dumpable)" == "fs.suid_dumpable = 0" ]];then
        success_result
    else
        failed_result
    fi

    #######################################
    # 1.5.2 Ensure XD/NX support is enabled
    #######################################
    header "1.5.2 Ensure XD/NX support is enabled"
    msg 'cat /proc/cpuinfo | grep ^flags | grep -Ewi "nx|xd"'
    cat /proc/cpuinfo | grep ^flags | grep -Ewi "nx|xd" 2>&1 > /dev/null
    check_retval_eq_0 $?

    ###################################################################
    # 1.5.3 Ensure address space layout randomization (ASLR) is enabled
    ###################################################################
    header "1.5.3 Ensure ASLR is enabled"
    msg 'sysctl kernel.randomize_va_space'
    if [[ "$(sysctl kernel.randomize_va_space)" == "kernel.randomize_va_space = 2" ]];then
        success_result
    else
        failed_result
    fi

    ##################################
    # 1.5.4 Ensure prelink is disabled
    ##################################
    header "1.5.4 Ensure prelink is disabled"
    msg 'rpm -q prelink'
    if [[ "$(rpm -q prelink)" == "package prelink is not installed" ]];then
        success_result
    else
        failed_result
    fi

  ##############################
  # 1.6 Mandatory Access Control
  ##############################
    #########################
    # 1.6.1 Configure SELinux
    #########################
      ######################################################
      # 1.6.1.1 Ensure SELinux is not disabled by bootloader
      ######################################################
      if [ $CIS_LEVEL -gt 1 ];then
        header "1.6.1.1 Ensure SELinux is not disabled by bootloader"
        msg ' grep "^\s*linux" /boot/grub2/grub.cfg'
      
        grep "^\s*linux" /boot/grub2/grub.cfg | grep -E "selinux=0|enforcing=0" 2>&1 > /dev/null
        check_retval_ne_0 $?
      fi

      ###############################################
      # 1.6.1.2 Ensure the SELinux state is enforcing
      ###############################################
      if [ $CIS_LEVEL -gt 1 ];then
          header "1.6.1.2 Ensure the SELinux state is enforcing"
          msg ' grep SELINUX=enforcing /etc/selinux/config'
          grep SELINUX=enforcing /etc/selinux/config 2>&1 > /dev/null
          check_retval_eq_0 $?
      fi

      ###############################################
      # 1.6.1.3 Ensure SELinux policy is configured
      ###############################################
      if [ $CIS_LEVEL -gt 1 ];then
          header "1.6.1.3 Ensure SELinux policy is configured"
          msg ' grep SELINUXTYPE=targeted /etc/selinux/config'
          grep SELINUXTYPE=targeted /etc/selinux/config 2>&1 > /dev/null
          check_retval_eq_0 $?
      fi

      ################################################
      # 1.6.1.4 Ensure SETroubleshoot is not installed
      ################################################
      if [ $CIS_LEVEL -gt 1 ];then
          header "1.6.1.4 Ensure SETroubleshoot is not installed"
          msg ' rpm -q setroubleshoot'
      
          if [[ "$(rpm -q setroubleshoot)" == "package setroubleshoot is not installed" ]];then
              success_result
          else
              failed_result
          fi
      fi

      ##########################################
      # 1.6.1.5 Ensure mcstrans is not installed
      ##########################################
      if [ $CIS_LEVEL -gt 1 ];then
          header "1.6.1.5 Ensure mcstrans is not installed"
          msg ' rpm -q mcstrans'
      
          if [[ "$(rpm -q mcstrans)" == "package mcstrans is not installed" ]];then
              success_result
          else
              failed_result
          fi
      fi

      ############################################
      # 1.6.1.6 Ensure no unconfiged daemons exist
      ############################################
      if [ $CIS_LEVEL -gt 1 ];then
          header "1.6.1.6 Ensure no unconfined daemons exist"
          msg ' Check for no unconfigured daemons'
      
          if [[ $(ps -eZ | egrep "initrc" | egrep -vw "tr|ps|egrep|bash|awk" | tr ':' ' ' | awk '{ print $NF }') =~ ^$ ]];then
              success_result
          else
              failed_result
          fi
      fi

    ###################################
    # 1.6.2 Ensure SELinux is Installed
    ###################################
    if [ $CIS_LEVEL -gt 1 ];then
        header "1.6.2 Ensure SELinux is Installed"
        msg ' rpm -q libselinux'
      
        rpm -q libselinux 2>&1 > /dev/null
        check_retval_eq_0 $?
      fi

  #####################
  # 1.7 Warning Banners
  #####################
    ####################################
    # 1.7.1 Command Line Warning Banners 
    ####################################
      ##########################################################
      # 1.7.1.1 Ensure message of the day is configured properly
      ##########################################################
      header "1.7.1.1 Ensure /etc/motd is configured"
      msg  " egrep '(\\v|\\r|\\m|\\s)' /etc/motd"
      egrep '(\\v|\\r|\\m|\\s)' /etc/motd 2>&1 > /dev/null
      check_retval_ne_0 $?

      ##########################################################
      # 1.7.1.2 Ensure local login warning banner is configured
      ##########################################################
      header "1.7.1.2 Ensure local login warning banner conf"
      msg  " egrep '(\\v|\\r|\\m|\\s)' /etc/issue"
      egrep '(\\v|\\r|\\m|\\s)' /etc/issue 2>&1 > /dev/null
      check_retval_ne_0 $?

      ##########################################################
      # 1.7.1.3 Ensure remote login warning banner is configured
      ##########################################################
      header "1.7.1.3 Ensure remote login warning banner conf"
      msg  " egrep '(\\v|\\r|\\m|\\s)' /etc/issue.net"
      egrep '(\\v|\\r|\\m|\\s)' /etc/issue.net 2>&1 > /dev/null
      check_retval_ne_0 $?

      ##########################################################
      # 1.7.1.4 Ensure permissions on /etc/motd are configured
      ##########################################################
      header "1.7.1.4 Ensure permissions on /etc/motd"
      msg " Ensure /etc/motd permissions are 0644 root:root"
      if [[ $(stat /etc/motd) =~ Access:.*(0644/-rw-r--r--).*Uid:.*(.*0/.*root).*Gid:.*(.*0/.*root) ]];then
          success_result
      else
          failed_result
      fi

      ##########################################################
      # 1.7.1.5 Ensure permissions on /etc/issue are configured
      ##########################################################
      header "1.7.1.5 Ensure permissions on /etc/issue"
      msg " Ensure /etc/issue permissions are 0644 root:root"
      if [[ $(stat /etc/issue) =~ Access:.*(0644/-rw-r--r--).*Uid:.*(.*0/.*root).*Gid:.*(.*0/.*root) ]];then
          success_result
      else
          failed_result
      fi

      #############################################################
      # 1.7.1.6 Ensure permissions on /etc/issue.net are configured
      #############################################################
      if [ $CIS_LEVEL -gt 1 ];then
          header "1.7.1.6 Ensure permissions on /etc/issue.net"
          msg " Ensure /etc/issue.net permissions are 0644 root:root"
          if [[ $(stat /etc/issue.net) =~ Access:.*(0644/-rw-r--r--).*Uid:.*(.*0/.*root).*Gid:.*(.*0/.*root) ]];then
              success_result
          else
              failed_result
          fi
      fi

    #############################################
    # 1.7.2 Ensure GDM login banner is configured
    #############################################
    header "1.7.2 Ensure GDM login banner is configured"
    rpm -q gdm 2>&1 > /dev/null
    if [ $? -ne 0 ];then
        msg ' gdm not even installed'
        success_result
    else
        msg ' Checking GDM conf'
        [[ $(grep "user-db:user" /etc/dconf/profile/gdm) ]] && \
        [[ $(grep "system-db:gdm" /etc/dconf/profile/gdm) ]] && \
        [[ $(grep "file-db:/usr/share/gdm/greeter-dconf-defaults" /etc/dconf/profile/gdm) ]] && \
        success_result || \
        failed_result
    fi

  #############################################################################
  # 1.8 Ensure updates, patches, and additional security software are installed
  #############################################################################
  header "1.8 Ensure all updates are installed"
  msg  "yum check-update"
  yum check-update --exclude=epel-release 2>&1 > /dev/null
  check_retval_eq_0 $?

############
# 2 Services
############
  #####################
  # 2.1 Inetd services
  #####################
  ENABLED_SERVICES=$(systemctl list-unit-files | awk '($2 == "enabled") {print $0}')
  header "2.1.1 - 2.1.7 Ensure inetd services diabled"
  for service in chargen-dgram chargen-stream daytime-dgram daytime-stream discard-dgram discard-stream echo-dgram echo-stream time-dgram time-stream tftp xinetd;do
      msg "$service"
      echo $ENABLED_SERVICES | grep $service 2>&1 > /dev/null
      check_retval_ne_0 $?
  done

  ##############################
  # 2.2 Special Purpose Services
  ##############################
      #################################
      # 2.2.1.1 Ensure time sync in use
      #################################
      header "2.2.1.1 Ensure time sync enabled and configured"
      msg "Check if ntpd/chrony installed"
      
      rpm -qa | grep -Ew "ntp|chrony" 2>&1 > /dev/null
      check_retval_eq_0 $?

      if [ "$(rpm -q ntp)" != "package ntp is not installed" ];then
          header "2.2.1.2 Ensure ntp is configured"
          msg 'grep "^restrict" /etc/ntp.conf'
          grep "^restrict" /etc/ntp.conf 2>&1 > /dev/null
          check_retval_eq_0 $?
          msg "grep "^server" /etc/ntp.conf"
          grep "^server" /etc/ntp.conf 2>&1 > /dev/null
          check_retval_eq_0 $?
          msg 'grep "^OPTIONS" /etc/sysconfig/ntpd'
          grep "^OPTIONS" /etc/sysconfig/ntpd | grep "\-u ntp:ntp" 2>&1 > /dev/null
          check_retval_eq_0 $?
      else
          header "2.2.1.3 Ensure chrony is configured"
          msg 'grep "^server" /etc/chrony.conf'
          check_retval_eq_0 $?
          msg 'grep ^OPTIONS /etc/sysconfig/chronyd'
          grep ^OPTIONS /etc/sysconfig/chronyd | grep "\-u chrony" 2>&1 > /dev/null
          check_retval_eq_0 $?
      fi
  ###############################################
  # 2.2.2 Ensure X Window System is not installed
  ###############################################
  header "2.2.2 Ensure X Window System is not installed"
  msg "rpm -qa xorg-x11*"
  if [ $(rpm -qa xorg-x11* | wc -l) -eq 0 ];then
    success_result
  else
    failed_result
  fi

  ####################################################
  # 2.2.3 - 2.2.14 Ensure Unneeded Servers not enabled
  ####################################################
  header "2.2.3 - 2.2.21 Ensure Following services are not enabled"
  for service in avahi-daemoncups dhcpd slapd nfs rpcbind named vsftpd httpd dovecot smb squid snmpd ypserv rsh.socket rlogin.socket rexec.socket telnet.socket tftp.socket rsyncd ntalk;do
      msg "$service"
      check_output="$(systemctl is-enabled $service 2>&1)"
      if [ "$check_output" == "disabled" -o "$check_output" == "indirect" ];then
        success_result
      else
        if [[ $check_output =~ Failed.*to.*get.*unit.*file.*state.*for.* ]];then
          success_result
        else
          failed_result
        fi
      fi
  done

  ###################################################
  # 2.2.15 Ensure MTA Configured for local-only mode
  ###################################################
  header "2.2.15 Ensure MTA Configured for local-only mode"
  msg 'netstat -an | grep LISTEN | grep ":25[[:space:]]"'
  netstat -an | grep LISTEN | grep ":25[[:space:]]"  | grep -vE "127.0.0.1|::1" 2>&1 > /dev/null
  check_retval_ne_0 $?

  #####################
  # 2.3 Service Clients
  #####################
    #############################################
    # 2.3.1 - 2.3.5 Ensure clients not installed
    #############################################
    header "2.3.1 - 2.3.5 Ensure following clients not installed"
    for client in ypbind rsh talk telnet openldap-clients;do
        msg "$client"
        rpm -q $client 2>&1 > /dev/null
        check_retval_ne_0 $?
    done

#########################
# 3 Network Configuration
#########################
  ####################################
  # 3.1 Network Parameters (Host Only)
  ####################################
    #####################################
    # 3.1.1 Esnure IP Forwarding disabled
    #####################################
    header "3.1.1 Ensure IP forwarding disabled"
    msg "sysctl net.ipv4.ip_forward"
    sysctl net.ipv4.ip_forward 2>&1 > /dev/null
    if [[ "$(sysctl net.ipv4.ip_forward)" == "net.ipv4.ip_forward = 0" ]];then
      success_result
    else
      failed_result
    fi

    ##################################################
    # 3.1.2 Ensure packet redirect sending is disabled
    ##################################################
    header "3.1.2 Ensure packet redirect sending is disabled"
    msg "sysctl net.ipv4.conf.all.send_redirects"
    sysctl net.ipv4.conf.all.send_redirects 2>&1 > /dev/null
    if [[ "$(sysctl net.ipv4.conf.all.send_redirects)" == "net.ipv4.conf.all.send_redirects = 0" ]];then
      success_result
    else
      failed_result
    fi
    msg "sysctl net.ipv4.conf.default.send_redirects"
    sysctl net.ipv4.conf.default.send_redirects 2>&1 > /dev/null
    if [[ "$(sysctl net.ipv4.conf.default.send_redirects)" == "net.ipv4.conf.default.send_redirects = 0" ]];then
      success_result
    else
      failed_result
    fi
  ##########################################
  # 3.2 Network Parameters (Host and Router)
  ##########################################
    ####################################################
    # 3.2.1 Ensure source routed packets aren't accepted
    ####################################################
    header "3.2.1 Ensure source routed packets aren't accepted"
    msg "sysctl net.ipv4.conf.all.accept_source_route"
    if [[ "$(sysctl net.ipv4.conf.all.accept_source_route)" == "net.ipv4.conf.all.accept_source_route = 0" ]];then
      success_result
    else
      failed_result
    fi

    msg "sysctl net.ipv4.conf.default.accept_source_route"
    if [[ "$(sysctl net.ipv4.conf.default.accept_source_route)" == "net.ipv4.conf.default.accept_source_route = 0" ]];then
      success_result
    else
      failed_result
    fi
    ##############################################
    # 3.2.2 Ensure ICMP redirects are not accepted
    ##############################################
    header "3.2.2 Ensure ICMP redirects are not accepted"
    msg "sysctl net.ipv4.conf.all.accept_redirects"
    if [[ "$(sysctl net.ipv4.conf.all.accept_redirects)" == "net.ipv4.conf.all.accept_redirects = 0" ]];then
      success_result
    else
      failed_result
    fi

    msg "sysctl net.ipv4.conf.default.accept_redirects"
    if [[ "$(sysctl net.ipv4.conf.default.accept_redirects)" == "net.ipv4.conf.default.accept_redirects = 0" ]];then
      success_result
    else
      failed_result
    fi
    
    #####################################################
    # 3.2.3 Ensure secure ICMP redirects are not accepted
    #####################################################
    header "3.2.3 Ensure secure ICMP redirects are not accepted"
    msg "sysctl net.ipv4.conf.all.secure_redirects"
    if [[ "$(sysctl net.ipv4.conf.all.secure_redirects)" == "net.ipv4.conf.all.secure_redirects = 0" ]];then
      success_result
    else
      failed_result
    fi

    ############################################
    # 3.2.4 Ensure suspicious packets are logged
    ############################################
    header "3.2.4 Ensure suspicious packets are logged"
    msg "sysctl net.ipv4.conf.all.log_martians"
    if [[ "$(sysctl net.ipv4.conf.all.log_martians)" == "net.ipv4.conf.all.log_martians = 1" ]];then
      success_result
    else
      failed_result
    fi

    ##################################################
    # 3.2.5 Ensure broadcast ICMP requests are ignored
    ##################################################
    header "3.2.5 Ensure broadcast ICMP requests are ignored"
    msg "sysctl net.ipv4.icmp_echo_ignore_broadcasts"
    if [[ "$(sysctl net.ipv4.icmp_echo_ignore_broadcasts)" == "net.ipv4.icmp_echo_ignore_broadcasts = 1" ]];then
      success_result
    else
      failed_result
    fi

    ###############################################
    # 3.2.6 Ensure bogus ICMP responses are ignored
    ###############################################
    header "3.2.6 Ensure bogus ICMP responses are ignored"
    msg "sysctl net.ipv4.icmp_ignore_bogus_error_responses"
    if [[ "$(sysctl net.ipv4.icmp_ignore_bogus_error_responses)" == "net.ipv4.icmp_ignore_bogus_error_responses = 1" ]];then
      success_result
    else
      failed_result
    fi

    ################################################
    # 3.2.7 Ensure Reverse Path Filtering is enabled
    ################################################
    header "3.2.7 Ensure Reverse Path Filtering is enabled"
    msg "sysctl net.ipv4.conf.all.rp_filter"
    if [[ "$(sysctl net.ipv4.conf.all.rp_filter)" == "net.ipv4.conf.all.rp_filter = 1" ]];then
      success_result
    else
      failed_result
    fi

    msg "sysctl net.ipv4.conf.default.rp_filter"
    if [[ "$(sysctl net.ipv4.conf.default.rp_filter)" == "net.ipv4.conf.default.rp_filter = 1" ]];then
      success_result
    else
      failed_result
    fi

    #########################################
    # 3.2.8 Ensure TCP SYN Cookies is enabled
    #########################################
    header "3.2.8 Ensure TCP SYN Cookies is enabled"
    msg "sysctl net.ipv4.tcp_syncookies"
    if [[ "$(sysctl net.ipv4.tcp_syncookies)" == "net.ipv4.tcp_syncookies = 1" ]];then
      success_result
    else
      failed_result
    fi

  ##########
  # 3.3 IPv6
  ##########
    ##########################################################
    # 3.3.1 Ensure IPv6 router advertisements are not accepted
    ##########################################################
    header "3.3.1 Ensure IPv6 router advertisements are not accepted"
    msg "sysctl net.ipv6.conf.all.accept_ra"
    if [[ "$(sysctl net.ipv6.conf.all.accept_ra)" == "net.ipv6.conf.all.accept_ra = 0" ]];then
      success_result
    else
      failed_result
    fi

    msg "sysctl net.ipv6.conf.default.accept_ra"
    if [[ "$(sysctl net.ipv6.conf.default.accept_ra)" == "net.ipv6.conf.default.accept_ra = 0" ]];then
      success_result
    else
      failed_result
    fi

    ##############################################
    # 3.3.2 Ensure IPv6 redirects are not accepted
    ##############################################
    header "3.3.2 Ensure IPv6 redirects are not accepted"
    msg "sysctl net.ipv6.conf.all.accept_redirects"
    if [[ "$(sysctl net.ipv6.conf.all.accept_redirects)" == "net.ipv6.conf.all.accept_redirects = 0" ]];then
      success_result
    else
      failed_result
    fi

    msg "sysctl net.ipv6.conf.default.accept_redirects"
    if [[ "$(sysctl net.ipv6.conf.default.accept_redirects)" == "net.ipv6.conf.default.accept_redirects = 0" ]];then
      success_result
    else
      failed_result
    fi

    ###############################
    # 3.3.3 Ensure IPv6 is disabled
    ###############################
    if [ $INCLUDE_UNSCORED -eq 1 ];then
        header "3.3.3 Ensure IPv6 is disabled"
        msg "modprobe -c | grep ipv6"
        modprobe -c | grep ipv6 | grep "options ipv6 disable=1" 2>&1 > /dev/null
        check_retval_eq_0 $?
    fi

  ##################
  # 3.4 TCP Wrappers
  ##################
    ########################################
    # 3.4.1 Ensure TCP Wrappers is installed 
    ########################################
    header "3.4.1 Ensure TCP Wrappers is installed"
    msg "rpm -q tcp_wrappers"
    rpm -q tcp_wrappers 2>&1 > /dev/null
    check_retval_eq_0 $?

    msg "rpm -q tcp_wrappers-libs"
    rpm -q tcp_wrappers-libs 2>&1 > /dev/null
    check_retval_eq_0 $?

    #############################################
    # 3.4.2 Ensure /etc/hosts.allow is configured
    #############################################
    header "3.4.2 Ensure /etc/hosts.allow is configured"
    msg "cat /etc/hosts.allow"
    grep "ALL:" /etc/hosts.allow 2>&1 > /dev/null
    check_retval_eq_0 $?

    #############################################
    # 3.4.3 Ensure /etc/hosts.deny is configured
    #############################################
    header "3.4.3 Ensure /etc/hosts.deny is configured"
    msg "cat /etc/hosts.deny"
    grep "ALL: ALL" /etc/hosts.deny 2>&1 > /dev/null
    check_retval_eq_0 $?

    #############################################################
    # 3.4.4 Ensure permissions on /etc/hosts.allow are configured
    #############################################################
    header "3.4.4 Ensure permissions on /etc/hosts.allow are configured"
    msg "Ensure /etc/hosts.allow permissions are 0644 root:root"
    if [[ $(stat /etc/hosts.allow) =~ Access:.*(0644/-rw-r--r--).*Uid:.*(.*0/.*root).*Gid:.*(.*0/.*root) ]];then
        success_result
    else
        failed_result
    fi

    #############################################################
    # 3.4.5 Ensure permissions on /etc/hosts.deny are configured
    #############################################################
    header "3.4.5 Ensure permissions on /etc/hosts.deny are configured"
    msg "Ensure /etc/hosts.deny permissions are 0644 root:root"
    if [[ $(stat /etc/hosts.deny) =~ Access:.*(0644/-rw-r--r--).*Uid:.*(.*0/.*root).*Gid:.*(.*0/.*root) ]];then
        success_result
    else
        failed_result
    fi
  
  ################################
  # 3.5 Uncommon Network Protocols
  ################################
    ###############################
    # 3.5.1 Ensure DCCP is disabled
    ###############################
    if [ $INCLUDE_UNSCORED -eq 1 ];then
      header "3.5.1 - 3.5.4 Ensure unneeded modules disabled"
      for module in dccp sctp rds tipc;do
          msg "modprobe -n -v $module"
          modprobe -n -v $module | grep "install /bin/true" 2>&1 > /dev/null
          check_retval_eq_0 $?
          msg "lsmod | grep $module"
          lsmod | grep "$module" 2>&1 > /dev/null
          check_retval_ne_0 $?
      done
    fi

  ############################
  # 3.6 Firewall Configuration
  ############################
    ####################################
    # 3.6.1 Ensure IPTables is installed
    ####################################
    header "3.6.1 Ensure IPTables is installed"
    msg "rpm -q iptables"
    rpm -q iptables 2>&1 > /dev/null
    check_retval_eq_0 $?

    ###########################################
    # 3.6.2 Ensure default deny firewall policy
    ###########################################
    header "3.6.2 Ensure default deny firewall policy"
    msg 'iptables -L | grep "INPUT" | grep "policy DROP"'
    iptables -L | grep "INPUT" | grep "policy DROP" 2>&1 > /dev/null
    check_retval_eq_0 $?
    msg 'iptables -L | grep "FORWARD" | grep "policy DROP"'
    iptables -L | grep "FORWARD" | grep "policy DROP" 2>&1 > /dev/null
    check_retval_eq_0 $?
    msg 'iptables -L | grep "OUTPUT" | grep "policy DROP"'
    iptables -L | grep "OUTPUT" | grep "policy DROP" 2>&1 > /dev/null
    check_retval_eq_0 $?

    #############################################
    # 3.6.3 Ensure loopback traffic is configured
    #############################################
    header "3.6.3 Ensure loopback traffic is configured"
    msg "iptables -L INPUT -v -n =~ .*ACCEPT.*all.*--.*lo.*0.0.0.0/0.*0.0.0.0/0"
    if [[ $(iptables -L INPUT -v -n) =~ .*ACCEPT.*all.*--.*lo.*0.0.0.0/0.*0.0.0.0/0  ]];then
      success_result
    else
      failed_result
    fi
    msg "iptables -L INPUT -v -n =~ .*DROP.*all.*--.*127.0.0.0/8.*0.0.0.0/0'"
    if [[ $(iptables -L INPUT -v -n) =~ .*DROP.*all.*--.*127.0.0.0/8.*0.0.0.0/0  ]];then
      success_result
    else
      failed_result
    fi

    ##################################################################
    # 3.6.4 Ensure outbound and established connections are configured
    ##################################################################
    if [ $INCLUDE_UNSCORED -eq 1 ];then
        header "3.6.4 Ensure outbound and established connections are configured"
        msg "See page 179, section 3.6.4"
        /bin/true
        check_retval_eq_0 $?
    fi

    ######################################################
    # 3.6.5 Ensure firewall rules exist for all open ports
    ######################################################
    header "3.6.5 Ensure firewall rules exist for all open ports"
    msg "See section 3.6.5, pg 183 for method"
    /bin/true
    check_retval_eq_0 $?

  #############################################
  # 3.7 Ensure wireless interfaces are disabled
  #############################################
  if [ $INCLUDE_UNSCORED -eq 1 ];then
      header "3.7 Ensure wireless interfaces are disabled"
      msg "See section 3.7, page 179"
      /bin/true
      check_retval_eq_0 $?
  fi

########################
# 4 Logging and Auditing
########################
  ##########################################
  # 4.1 Configure System Accounting (auditd) 
  ##########################################
    ################################
    # 4.1.1 Configure Data Retention
    ################################
      #####################################################
      # 4.1.1.1 Ensure audit log storage size is configured
      #####################################################
      if [ $CIS_LEVEL -gt 1 ];then
        header "4.1.1.1 - 4.1.1.18"
        msg "ALL LEVEL 2 CHECKS, NOT IMPLEMENTED YET"
        /bin/true
        check_retval_eq_0 $?
      fi

  #######################
  # 4.2 Configure Logging
  #######################
  rpm -qa | grep -E "rsyslog|syslog-ng" 2>&1 > /dev/null
  if [ $? -eq 0 ];then
    #########################
    # 4.2.1 Configure rsyslog
    #########################
    rpm -q rsyslog 2>&1 > /dev/null
    if [ $? -eq 0 ];then
      ###########################################
      # 4.2.1.1 Ensure rsyslog service is enabled
      ###########################################
      header "4.2.1.1 Ensure rsyslog service is enabled"
      msg "systemctl is-enabled rsyslog"
      if [[ "$(systemctl is-enabled rsyslog)" == "enabled" ]];then
          success_result
      else
          failed_result
      fi

      ######################################
      # 4.2.1.2 Ensure logging is configured
      ######################################
      if [ $INCLUDE_UNSCORED -eq 1 ];then
          header "4.2.1.2 Ensure logging is configured"
          msg "Unscored, not implemented.  See section 4.2.1.2, pg 225"
          /bin/true
          check_retval_eq_0 $?
      fi

      ############################################################
      # 4.2.1.3 Ensure rsyslog default file permissions configured
      ############################################################
      header "4.2.1.3 Ensure rsyslog default file permissions configured"
      msg "grep ^\$FileCreateMode /etc/rsyslog.conf | grep 0640"
      grep ^\$FileCreateMode /etc/rsyslog.conf | grep 0640 2>&1 > /dev/null
      check_retval_eq_0 $?

      ########################################################################
      # 4.2.1.4 Ensure rsyslog is configured to send logs to a remote log host
      ########################################################################
      header "4.2.1.4 Ensure rsyslog is configured to send logs to a remote host"
      msg 'grep "^*.*[^I][^I]*@" /etc/rsyslog.conf'
      grep "^*.*[^I][^I]*@" /etc/rsyslog.conf
      check_retval_eq_0 $?

      ##################################################################################
      # 4.2.1.5 Ensure remote rsyslog messages are only accepted on designated log hosts
      ##################################################################################
      if [ $INCLUDE_UNSCORED -eq 1 ];then
          header "4.2.1.5 Ensure remote rsyslog messages only to designated log hosts"
          msg "Unscored, not implemented.  See section 4.2.1.5, pg 230"
          /bin/true
          check_retval_eq_0 $?
      fi
    fi

    ###########################
    # 4.2.2 Configure syslog-ng
    ###########################
    rpm -q syslog-ng 2>&1 > /dev/null
    if [ $? -eq 0 ];then 
      ##########################################
      # 4.2.2.1 Ensure syslog-ng service enabled
      ##########################################
      header "4.2.2.1 Ensure syslog-ng service enabled"
      msg "systemctl is-enabled syslog-ng | grep enabled"
      systemctl is-enabled syslog-ng | grep enabled 2>&1 > /dev/null
      check_retval_eq_0 $?

      if [ $INCLUDE_UNSCORED -eq 1 ];then
          header "4.2.2.2 Ensure logging is configured"
          msg "Unscored.  Not implements.  See section 4.2.2.2, pg 234"
          /bin/true
          check_retval_eq_0 $?
      fi

      ##############################################################
      # 4.2.2.3 Ensure syslog-ng default file permissions configured
      ##############################################################
      header "4.2.2.3 Ensure syslog-ng default file permissions configured"
      msg 'grep ^options /etc/syslog-ng/syslog-ng.conf'
      grep ^options /etc/syslog-ng/syslog-ng.conf | grep "perm(0640)" 2>&1 > /dev/null
      check_retval_eq_0 $?
    fi
  fi

  ####################################
  # 4.3 Ensure logrotate is configured 
  ####################################
  if [ $INCLUDE_UNSCORED -eq 1 ];then
    header "4.3 Ensure logrotate is configured"
    msg "Not implemented.  See section 4.3, pg 244"
    /bin/true
    check_retval_eq_0 $?
  fi

############################################
# 5 Access, Authentication and Authorization
############################################
  ####################
  # 5.1 Configure cron
  ####################
    ##################################
    # 5.1.1 Ensure cron daemon enabled
    ##################################
    header "5.1.1 Ensure cron daemon enabled"
    msg 'systemctl is-enabled crond'
    systemctl is-enabled crond | grep enabled 2>&1 > /dev/null
    check_retval_eq_0 $?

    #########################################################
    # 5.1.2 Ensure permissions on /etc/crontab are configured
    #########################################################
    header "5.1.2 Ensure permissions on /etc/crontab are configured"
    msg "Ensure /etc/crontab permissions are 0600 root:root"
    if [[ $(stat -L -c "%a %U %G" /etc/crontab) == "600 root root" ]];then
        success_result
    else
        failed_result
    fi

    #############################################################
    # 5.1.3 Ensure permissions on /etc/cron.hourly are configured
    #############################################################
    header "5.1.3 Ensure permissions on /etc/cron.hourly are configured"
    msg "Ensure /etc/cron.hourly permissions are 0600 root:root"
    if [[ $(stat -L -c "%a %U %G" /etc/cron.hourly) == "600 root root" ]];then
        success_result
    else
        failed_result
    fi

    #############################################################
    # 5.1.4 Ensure permissions on /etc/cron.daily are configured
    #############################################################
    header "5.1.4 Ensure permissions on /etc/cron.daily are configured"
    msg "Ensure /etc/cron.daily permissions are 0600 root:root"
    if [[ $(stat -L -c "%a %U %G" /etc/cron.daily) == "600 root root" ]];then
        success_result
    else
        failed_result
    fi

    #############################################################
    # 5.1.5 Ensure permissions on /etc/cron.weekly are configured
    #############################################################
    header "5.1.5 Ensure permissions on /etc/cron.weekly are configured"
    msg "Ensure /etc/cron.weekly permissions are 0600 root:root"
    if [[ $(stat -L -c "%a %U %G" /etc/cron.weekly) == "600 root root" ]];then
        success_result
    else
        failed_result
    fi

    ##############################################################
    # 5.1.6 Ensure permissions on /etc/cron.monthly are configured
    ##############################################################
    header "5.1.6 Ensure permissions on /etc/cron.monthly are configured"
    msg "Ensure /etc/cron.monthly permissions are 0600 root:root"
    if [[ $(stat -L -c "%a %U %G" /etc/cron.monthly) == "600 root root" ]];then
        success_result
    else
        failed_result
    fi

    #############################################################
    # 5.1.7 Ensure permissions on /etc/cron.d are configured
    #############################################################
    header "5.1.7 Ensure permissions on /etc/cron.d are configured"
    msg "Ensure /etc/cron.d permissions are 0600 root:root"
    if [[ $(stat -L -c "%a %U %G" /etc/cron.d) == "600 root root" ]];then
        success_result
    else
        failed_result
    fi

    ########################################################
    # 5.1.8 Ensure at/cron is restricted to authorized users
    ########################################################
    header "5.1.8 Ensure at/cron is restricted to authorized users"
    msg "Ensure /etc/cron.deny doesn't exist"
    if [ -f /etc/cron.deny ];then
      failed_result
    else
      success_result
    fi
    msg "Ensure /etc/at.deny doesn't exist"
    if [ -f /etc/at.deny ];then
      failed_result
    else
      success_result
    fi

  ##############################
  # 5.2 SSH Server Configuration
  ##############################
    #################################################################
    # 5.2.1 Ensure permissions on /etc/ssh/sshd_config are configured
    #################################################################
    header "5.2.1 Ensure permissions on /etc/ssh/sshd_config are configured"
    msg "Ensure /etc/ssh/sshd_config permissions are 0600 root:root"
    if [[ $(stat /etc/ssh/sshd_config) =~ Access:.*(0600/-rw-------).*Uid:.*(.*0/.*root).*Gid:.*(.*0/.*root) ]];then
        success_result
    else
        failed_result
    fi

    #######################################
    # 5.2.2 Ensure SSH Protocol is set to 2
    #######################################
    header "5.2.2 Ensure SSH Protocol is set to 2"
    msg 'grep "^Protocol" /etc/ssh/sshd_config | grep "2"'
    grep "^Protocol" /etc/ssh/sshd_config | grep "2" 2>&1 > /dev/null
    check_retval_eq_0 $?

    ##########################################
    # 5.2.3 Ensure SSH LogLevel is set to INFO
    ##########################################
    header "5.2.3 Ensure SSH LogLevel is set to INFO"
    msg 'grep "^LogLevel" /etc/ssh/sshd_config | grep "INFO"'
    grep "^LogLevel" /etc/ssh/sshd_config | grep "INFO" 2>&1 > /dev/null
    check_retval_eq_0 $?

    #############################################
    # 5.2.4 Ensure SSH X11 forwarding is disabled
    #############################################
    header "5.2.4 Ensure SSH X11 forwarding is disabled"
    msg 'grep "^X11Forwarding" /etc/ssh/sshd_config  | grep "no"'
    grep "^X11Forwarding" /etc/ssh/sshd_config  | grep "no" 2>&1 > /dev/null
    check_retval_eq_0 $?

    ###################################################
    # 5.2.5 Ensure SSH MaxAuthTries is set to 4 or less
    ###################################################
    header "5.2.5 Ensure SSH MaxAuthTries is set to 4 or less"
    msg 'grep "^MaxAuthTries" /etc/ssh/sshd_config | grep "4"'
    if [[ $(grep "^MaxAuthTries" /etc/ssh/sshd_config | awk '{print $2}') -le 4 ]];then
      success_result
    else
      failed_result
    fi

    ##########################################
    # 5.2.6 Ensure SSH IgnoreRhosts is enabled
    ##########################################
    header "5.2.6 Ensure SSH IgnoreRhosts is enabled"
    msg 'grep "^IgnoreRhosts" /etc/ssh/sshd_config | grep "yes"'
    grep "^IgnoreRhosts" /etc/ssh/sshd_config | grep "yes" 2>&1 > /dev/null
    check_retval_eq_0 $?

    ######################################################
    # 5.2.7 Ensure SSH HostbasedAuthentication is disabled
    ######################################################
    header "5.2.7 Ensure SSH HostbasedAuthentication is disabled"
    msg 'grep "^HostbasedAuthentication" /etc/ssh/sshd_config | grep "no"'
    grep "^HostbasedAuthentication" /etc/ssh/sshd_config | grep "no" 2>&1 > /dev/null
    check_retval_eq_0 $?

    #########################################
    # 5.2.8 Ensure SSH root login is disabled
    #########################################
    header "5.2.8 Ensure SSH root login is disabled"
    msg 'grep "^PermitRootLogin" /etc/ssh/sshd_config | grep no'
    grep "^PermitRootLogin" /etc/ssh/sshd_config | grep "no" 2>&1 > /dev/null
    check_retval_eq_0 $?

    ###################################################
    # 5.2.9 Ensure SSH PermitEmptyPasswords is disabled
    ###################################################
    header "5.2.9 Ensure SSH PermitEmptyPasswords is disabled"
    msg 'grep "^PermitEmptyPasswords" /etc/ssh/sshd_config | grep "no"'
    grep "^PermitEmptyPasswords" /etc/ssh/sshd_config | grep "no" 2>&1 > /dev/null
    check_retval_eq_0 $?

    #####################################################
    # 5.2.10 Ensure SSH PermitUserEnvironment is disabled
    #####################################################
    header "5.2.10 Ensure SSH PermitUserEnvironment is disabled"
    msg 'grep PermitUserEnvironment /etc/ssh/sshd_config | grep "no"'
    grep PermitUserEnvironment /etc/ssh/sshd_config | grep "no" 2>&1 > /dev/null
    check_retval_eq_0 $?

    ##############################################
    # 5.2.11 Ensure only approved ciphers are used
    ##############################################
    header "5.2.11 Ensure only approved ciphers are used"
    msg 'grep "Ciphers" /etc/ssh/sshd_config'
    grep "Ciphers" /etc/ssh/sshd_config 2>&1 > /dev/null
    check_retval_eq_0 $?

    #####################################################
    # 5.2.12 Ensure only approved MAC algorithms are used
    #####################################################
    header "5.2.12 Ensure only approved MAC algorithms are used"
    msg 'grep "MACs" /etc/ssh/sshd_config'
    grep "MACs" /etc/ssh/sshd_config 2>&1 > /dev/null
    check_retval_eq_0 $?

    #######################################################
    # 5.2.13 Ensure SSH Idle Timeout Interval is configured
    #######################################################
    header "5.2.13 Ensure SSH Idle Timeout Interval is configured"
    msg 'grep "^ClientAliveInterval" /etc/ssh/sshd_config'
    if [[ $(grep "^ClientAliveInterval" /etc/ssh/sshd_config | awk '{print $2}') -le 300 ]];then
      success_result
    else
      failed_result
    fi
    msg 'grep "^ClientAliveCountMax" /etc/ssh/sshd_config '
    if [[ $(grep "^ClientAliveCountMax" /etc/ssh/sshd_config  | awk '{print $2}') -le 3 ]];then
      success_result
    else
      failed_result
    fi

    ###############################################################
    # 5.2.14 Ensure SSH LoginGraceTime is set to one minute or less
    ###############################################################
    header "5.2.14 Ensure SSH LoginGraceTime is set <= 1 minute"
    msg 'grep "^LoginGraceTime" /etc/ssh/sshd_config'
    if [[ $(grep "^LoginGraceTime" /etc/ssh/sshd_config | awk '{print $2}') -le 60 ]];then
      success_result
    else
      failed_result
    fi

    #####################################
    # 5.2.15 Ensure SSH access is limited
    #####################################
    header "5.2.15 Ensure SSH access is limited"
    msg 'grep "^AllowUsers" /etc/ssh/sshd_config'
    grep "^AllowUsers" /etc/ssh/sshd_config 2>&1 > /dev/null
    check_retval_eq_0 $?

    msg 'grep "^AllowGroups" /etc/ssh/sshd_config'
    grep "^AllowGroups" /etc/ssh/sshd_config 2>&1 > /dev/null
    check_retval_eq_0 $?

    msg 'grep "^DenyUsers" /etc/ssh/sshd_config'
    grep "^DenyUsers" /etc/ssh/sshd_config 2>&1 > /dev/null
    check_retval_eq_0 $?

    msg 'grep "^DenyGroups" /etc/ssh/sshd_config'
    grep "^DenyGroups" /etc/ssh/sshd_config 2>&1 > /dev/null
    check_retval_eq_0 $?

    ################################################
    # 5.2.16 Ensure SSH warning banner is configured
    ################################################
    header "5.2.16 Ensure SSH warning banner is configured"
    msg 'grep "^Banner" /etc/ssh/sshd_config'
    grep "^Banner" /etc/ssh/sshd_config  2>&1 > /dev/null
    check_retval_eq_0 $?

  ###################
  # 5.3 Configure PAM
  ###################
    ############################################################
    # 5.3.1 Ensure password creation requirements are configured
    ############################################################
    header "5.3.1 Ensure password creation requirements are configured"
    msg 'grep pam_pwquality.so /etc/pam.d/password-auth'
    grep pam_pwquality.so /etc/pam.d/password-auth | grep -E "try_first_pass.*retry=3" 2>&1 > /dev/null
    check_retval_eq_0 $?
    
    msg 'grep pam_pwquality.so /etc/pam.d/system-auth'
    grep pam_pwquality.so /etc/pam.d/system-auth | grep -E "try_first_pass.*retry=3" 2>&1 > /dev/null
    check_retval_eq_0 $?

    msg "grep ^minlen /etc/security/pwquality.conf"
    grep -E ^minlen /etc/security/pwquality.conf | grep "minlen=14" 2>&1 > /dev/null
    check_retval_eq_0 $?

    msg 'grep ^dcredit /etc/security/pwquality.conf'
    grep -E ^dcredit /etc/security/pwquality.conf | grep "dcredit=-1" 2>&1 > /dev/null
    check_retval_eq_0 $?

    msg 'grep ^lcredit /etc/security/pwquality.conf'
    grep -E ^lcredit /etc/security/pwquality.conf | grep "lcredit=-1" 2>&1 > /dev/null
    check_retval_eq_0 $?

    msg 'grep ^ocredit /etc/security/pwquality.conf'
    grep -E ^ocredit /etc/security/pwquality.conf | grep "ocredit=-1" 2>&1 > /dev/null
    check_retval_eq_0 $?

    msg 'grep ^ucredit /etc/security/pwquality.conf'
    grep -E ^ucredit /etc/security/pwquality.conf | grep "ucredit=-1" 2>&1 > /dev/null
    check_retval_eq_0 $?

    #################################################################
    # 5.3.2 Ensure lockout for failed password attempts is configured
    #################################################################
    header "5.3.2 Ensure lockout for failed password attempts is configured"
    msg 'grep pam_unix.so /etc/pam.d/password-auth'
    grep pam_unix.so /etc/pam.d/password-auth | grep "success=1.*default=bad" 2>&1 > /dev/null
    check_retval_eq_0 $?
    msg 'grep pam_unix.so /etc/pam.d/system-auth'
    grep pam_unix.so /etc/pam.d/system-auth | grep "success=1.*default=bad" 2>&1 > /dev/null
    check_retval_eq_0 $?

    ########################################
    # 5.3.3 Ensure password reuse is limited
    ########################################
    header "5.3.3 Ensure password reuse is limited"
    msg "egrep '^password\s+sufficient\s+pam_unix.so' /etc/pam.d/password-auth"
    egrep '^password\s+sufficient\s+pam_unix.so' /etc/pam.d/password-auth | grep "remember=5" 2>&1 > /dev/null
    check_retval_eq_0 $?

    msg "egrep '^password\s+sufficient\s+pam_unix.so' /etc/pam.d/system-auth"
    egrep '^password\s+sufficient\s+pam_unix.so' /etc/pam.d/system-auth | grep "remember=5" 2>&1 > /dev/null
    check_retval_eq_0 $?

    ####################################################
    # 5.3.4 Ensure password hashing algorithm is SHA-512
    ####################################################
    header "5.3.4 Ensure password hashing algorithm is SHA-512"
    msg "egrep '^password\s+sufficient\s+pam_unix.so' /etc/pam.d/password-auth"
    egrep '^password\s+sufficient\s+pam_unix.so' /etc/pam.d/password-auth | grep sha512 2>&1 > /dev/null
    check_retval_eq_0 $?

    msg "egrep '^password\s+sufficient\s+pam_unix.so' /etc/pam.d/system-auth"
    egrep '^password\s+sufficient\s+pam_unix.so' /etc/pam.d/system-auth | grep sha512 2>&1 > /dev/null
    check_retval_eq_0 $?

  ###################################
  # 5.4 User Accounts and Environment
  ###################################
    ############################################
    # 5.4.1 Set Shadow Password Suite Parameters 
    ############################################
      #######################################################
      # 5.4.1.1 Ensure password expiration is 90 days or less
      #######################################################
      header "5.4.1.1 Ensure password expiration is 90 days or less"
      msg 'grep PASS_MAX_DAYS /etc/login.defs'
      if [[ $(grep PASS_MAX_DAYS /etc/login.defs | grep -v \# | awk '{print $2}') -le 90 ]];then
        success_result
      else
        failed_result
      fi

      msg "Ensure all users have max days between passwd reset <= 90"
      if [[ $(egrep ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1 | xargs -n1 chage --list | grep Maximum | uniq | cut -d: -f2) -le 90 ]];then
        success_result
      else
        failed_result
      fi

      ###################################################################
      # 5.4.1.2 Ensure minimum days between password changes is 7 or more
      ###################################################################
      header "5.4.1.2 Ensure minimum days between password changes >= 7"
      msg 'grep PASS_MAX_DAYS /etc/login.defs'
      if [[ $(grep PASS_MAX_DAYS /etc/login.defs | grep -v \# | awk '{print $2}') -ge 7 ]];then
        success_result
      else
        failed_result
      fi
      
      msg "Ensure all users have min days between passwd resets >= 7"
      if [[ $(egrep ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1 | xargs -n1 chage --list | grep Minimum | uniq | cut -d: -f2) -ge 7 ]];then
        success_result
      else
        failed_result
      fi

      ##############################################################
      # 5.4.1.3 Ensure password expiration warning days is 7 or more
      ##############################################################
      header "5.4.1.3 Ensure password expiration warning days is 7 or more"
      msg "grep ^PASS_WARN_AGE /etc/login.defs | awk '{print $2}'"
      if [[ $(grep -E ^PASS_WARN_AGE /etc/login.defs | awk '{print $2}') -ge 7 ]];then
        success_result
      else
        failed_result
      fi

      msg "Ensure all users have >= 7 days warning for passwd expires"
      if [[ $(egrep ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1 | xargs -n1 chage --list | grep warning | uniq | cut -d: -f2) -ge 7 ]];then
        success_result
      else
        failed_result
      fi

      ##########################################################
      # 5.4.1.4 Ensure inactive password lock is 30 days or less
      ##########################################################
      header "5.4.1.4 Ensure inactive password lock is 30 days or less"
      msg "useradd -D | grep INACTIVE"
      if [[ $(useradd -D | grep INACTIVE | cut -d= -f2) -le 30 ]];then
        success_result
      else
        failed_result
      fi

      msg "Verify no user has inactive password <=30 days"
      if [[ $(egrep ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1 | xargs -n1 chage --list | grep warning | uniq | cut -d: -f2) -le 30 ]];then
        success_result
      else
        failed_result
      fi

    ############################################
    # 5.4.2 Ensure system accounts are non-login
    ############################################
    header "5.4.2 Ensure system accounts are non-login"
    msg ""
    if [[ $(egrep -v "^\+" /etc/passwd | awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $3<1000 && $7!="/sbin/nologin" && $7!="/bin/false") {print}' | wc -l) -eq 0 ]];then
      success_result
    else
      failed_result
    fi

    ##########################################################
    # 5.4.3 Ensure default group for the root account is GID 0
    ##########################################################
    header "5.4.3 Ensure default group for the root account is GID 0"
    msg "grep "^root:" /etc/passwd | cut -f4 -d:"
    if [[ $(grep "^root:" /etc/passwd | cut -f4 -d:) -eq 0 ]];then
      success_result
    else
      failed_result
    fi

    ############################################################
    # 5.4.4 Ensure default user umask is 027 or more restrictive
    ############################################################
    header "5.4.4 Ensure default user umask is 027 or more restrictive"
    msg 'grep "^umask" /etc/bashrc'
    if [[ "$(grep -E '^\s*umask' /etc/bashrc | awk '{print $2}' | uniq)" == "027" ]];then
      success_result
    else
      failed_result
    fi

    msg 'grep "^umask" /etc/profile'
    if [[ "$(grep -E '^\s*umask' /etc/profile | awk '{print $2}' | uniq)" == "027" ]];then
      success_result
    else
      failed_result
    fi

    #######################################################
    # 5.5 Ensure root login is restricted to system console
    #######################################################
    if [ $INCLUDE_UNSCORED -eq 1 ];then
      header "5.5 Ensure root login is restricted to system console"
      msg "cat /etc/securetty"
      check_retval_eq_0 $?
    fi

    ###################################################
    # 5.6 Ensure access to the su command is restricted
    ###################################################
    header "5.6 Ensure access to the su command is restricted"
    msg 'grep pam_wheel.so /etc/pam.d/su'
    if [[ $(grep pam_wheel.so /etc/pam.d/su | grep -v \#) =~ ^auth.*required.*pam_wheel.so.*use_uid.*$ ]];then
      success_result
    else
      failed_result
    fi

    msg 'grep wheel /etc/group'
    if [[ $(grep wheel /etc/group) =~ ^wheel:x:.*:.*$ ]];then
      success_result
    else
      failed_result
    fi

######################
# 6 System Maintenance
######################
  #############################
  # 6.1 System File Permissions
  #############################
    #####################################
    # 6.1.1 Audit system file permissions
    #####################################
    if [ $INCLUDE_UNSCORED -eq 1 ];then
      if [ $CIS_LEVEL -gt 1 ];then
        header "6.1.1 Audit system file permissions"
        msg "NOT IMPLEMENTED: See section 6.1.1, pg 298"
        warning_result
      fi
    fi

    ########################################################
    # 6.1.2 Ensure permissions on /etc/passwd are configured
    ########################################################
    header "6.1.2 Ensure permissions on /etc/passwd are are 0644 root:root"
    msg "state /etc/passwd"
    if [[ $(stat /etc/passwd) =~ Access:.*(0644/-rw-r--r--).*Uid:.*(.*0/.*root).*Gid:.*(.*0/.*root) ]];then
        success_result
    else
        failed_result
    fi

    ########################################################
    # 6.1.3 Ensure permissions on /etc/shadow are configured
    ########################################################
    header "6.1.3 Ensure permissions on /etc/shadow are 0000 root:root"
    msg "stat /etc/shadow"
    if [[ $(stat /etc/shadow) =~ Access:.*(0000/----------).*Uid:.*(.*0/.*root).*Gid:.*(.*0/.*root) ]];then
        success_result
    else
        failed_result
    fi

    ########################################################
    # 6.1.4 Ensure permissions on /etc/group are configured
    ########################################################
    header "6.1.4 Ensure permissions on /etc/group are are 0644 root:root"
    msg "stat /etc/group"
    if [[ $(stat /etc/group) =~ Access:.*(0644/-rw-r--r--).*Uid:.*(.*0/.*root).*Gid:.*(.*0/.*root) ]];then
        success_result
    else
        failed_result
    fi

    ########################################################
    # 6.1.5 Ensure permissions on /etc/gshadow are configured
    ########################################################
    header "6.1.5 Ensure permissions on /etc/gshadow are are 0000 root:root"
    msg "stat /etc/gshadow"
    if [[ $(stat /etc/gshadow) =~ Access:.*(0000/----------).*Uid:.*(.*0/.*root).*Gid:.*(.*0/.*root) ]];then
        success_result
    else
        failed_result
    fi

    #########################################################
    # 6.1.6 Ensure permissions on /etc/passwd- are configured
    #########################################################
    header "6.1.6 Ensure permissions on /etc/passwd- are are 0600 root:root"
    msg "stat /etc/passwd-"
    if [[ $(stat /etc/passwd-) =~ Access:.*(0600/-rw-------).*Uid:.*(.*0/.*root).*Gid:.*(.*0/.*root) ]];then
        success_result
    else
        failed_result
    fi

    #########################################################
    # 6.1.7 Ensure permissions on /etc/shadow- are configured
    #########################################################
    header "6.1.7 Ensure permissions on /etc/shadow- are 0600 root:root"
    msg "state /etc/shadow-"
    if [[ $(stat /etc/shadow-) =~ Access:.*(0600/-rw-------).*Uid:.*(.*0/.*root).*Gid:.*(.*0/.*root) ]];then
        success_result
    else
        failed_result
    fi

    #########################################################
    # 6.1.8 Ensure permissions on /etc/group- are configured
    #########################################################
    header "6.1.8 Ensure permissions on /etc/group- are 0600 root:root"
    msg "state /etc/group-"
    if [[ $(stat /etc/group-) =~ Access:.*(0600/-rw-------).*Uid:.*(.*0/.*root).*Gid:.*(.*0/.*root) ]];then
        success_result
    else
        failed_result
    fi

    ##########################################################
    # 6.1.9 Ensure permissions on /etc/gshadow- are configured
    ##########################################################
    header "6.1.9 Ensure permissions on /etc/gshadow- are 0600 root:root"
    msg "state /etc/gshadow-"
    if [[ $(stat /etc/gshadow-) =~ Access:.*(0600/-rw-------).*Uid:.*(.*0/.*root).*Gid:.*(.*0/.*root) ]];then
        success_result
    else
        failed_result
    fi

    #############################################
    # 6.1.10 Ensure no world writable files exist
    #############################################
    header ""
    msg "df --local -P ... "
    if [[ $(df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -0002) =~ ^$ ]];then
        success_result
    else
        failed_result
    fi

    #####################################################
    # 6.1.11 Ensure no unowned files or directories exist
    #####################################################
    header "6.1.11 Ensure no unowned files or directories exist"
    msg "SEARCHING ... "
    if [[ $(df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -nouser) =~ ^$ ]];then
        success_result
    else
        failed_result
    fi

    #######################################################
    # 6.1.12 Ensure no ungrouped files or directories exist
    #######################################################
    header "6.1.12 Ensure no ungrouped files or directories exist"
    msg "SEARCHING ... "
    if [[ $(df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -nogroup) =~ ^$ ]];then
        success_result
    else
        failed_result
    fi

    ############################################
    # 6.1.13 Audit SUID executables (Not Scored) 
    ############################################
    if [ $INCLUDE_UNSCORED -eq 1 ];then
        header "6.1.13 Audit SUID executables"
        msg "df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -4000"
        if [[ $(df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -4000) =~ ^$ ]];then
            success_result
        else
            failed_result
        fi
    fi

    ############################################
    # 6.1.14 Audit SGID executables (Not Scored) 
    ############################################
    if [ $INCLUDE_UNSCORED -eq 1 ];then
        header "6.1.14 Audit SGID executables"
        msg "df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -4000"
        if [[ $(df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -2000) =~ ^$ ]];then
            success_result
        else
            failed_result
        fi
    fi

  #############################
  # 6.2 User and Group Settings
  #############################
    ############################################
    # 6.2.1 Ensure password fields are not empty
    ############################################
    header ".2.1 Ensure password fields are not empty"
    msg "awk -F: '($2 == \"\") {print $1}' /etc/shadow"
    if [[ $(awk -F: '($2 == "") {print $1}' /etc/shadow | wc -l) -eq 0 ]];then
      success_result
    else
      failed_result
    fi

    #########################################################
    # 6.2.2 Ensure no legacy "+" entries exist in /etc/passwd
    #########################################################
    header '6.2.2 Ensure no legacy "+" entries exist in /etc/passwd'
    msg "grep '^+:' /etc/passwd | wc -l"
    if [[ $(grep '^+:' /etc/passwd| wc -l) -eq 0 ]];then
      success_result
    else
      failed_result
    fi

    #########################################################
    # 6.2.3 Ensure no legacy "+" entries exist in /etc/shadow
    #########################################################
    header '6.2.3 Ensure no legacy "+" entries exist in /etc/shadow'
    msg "grep '^+:' /etc/shadow | wc -l"
    if [[ $(grep '^+:' /etc/shadow| wc -l) -eq 0 ]];then
      success_result
    else
      failed_result
    fi

    #########################################################
    # 6.2.4 Ensure no legacy "+" entries exist in /etc/group
    #########################################################
    header '6.2.4 Ensure no legacy "+" entries exist in /etc/group'
    msg "grep '^+:' /etc/group | wc -l"
    if [[ $(grep '^+:' /etc/group| wc -l) -eq 0 ]];then
      success_result
    else
      failed_result
    fi

    #############################################
    # 6.2.5 Ensure root is the only UID 0 account
    #############################################
    header "6.2.5 Ensure root is the only UID 0 account"
    msg "awk -F: '($3 == 0) { print $1 }' /etc/passwd"
    if [[ "$(awk -F: '($3 == 0) { print $1 }' /etc/passwd)" == "root" ]];then
      success_result
    else
      failed_result
    fi

    ##################################
    # 6.2.6 Ensure root PATH Integrity
    ##################################
    header "6.2.6 Ensure root PATH Integrity"
    msg "RUNNING ... "
    read -r -d '' script << EOM
#!/bin/bash 
if [ "`echo $PATH | grep ::`" != "" ]; then     
  echo "Empty Directory in PATH (::)" 
fi  
if [ "`echo $PATH | grep :$`"  != "" ]; then   
  echo "Trailing : in PATH" 
fi  
p=`echo $PATH | sed -e 's/::/:/' -e 's/:$//' -e 's/:/ /g'` set -- $p 
while [ "$1" != "" ]; do   
if [ "$1" = "." ]; then     
  echo "PATH contains ."     
  shift     
  continue   
fi   
if [ -d $1 ]; then     
  dirperm=`ls -ldH $1 | cut -f1 -d" "`     
  if [ `echo $dirperm | cut -c6`  != "-" ]; then       
    echo "Group Write permission set on directory $1"     
  fi     
  if [ `echo $dirperm | cut -c9`  != "-" ]; then       
    echo "Other Write permission set on directory $1"     
  fi     
  dirown=`ls -ldH $1 | awk '{print $3}'`     
  if [ "$dirown" != "root" ] ; then       
    echo $1 is not owned by root
  fi   
else     
  echo $1 is not a directory   
fi   
shift 
done
EOM
    if [[ $(eval $script | wc -l) -ne 0 ]];then
      failed_result
    else
      success_result
    fi

    ################################################
    # 6.2.7 Ensure all users' home directories exist
    ################################################
    header "6.2.7 Ensure all users' home directories exist"
    msg "CHECKING ... "
    read -r -d '' hdir << EOM
#!/bin/bash

cat /etc/passwd | awk -F: '{ print $1 " " $3 " " $6 }' | while read user uid dir; do   
    if [ $uid -ge 1000 -a ! -d "$dir" -a $user != "nfsnobody" ]; then     
      echo "The home directory ($dir) of user $user does not exist."   
    fi 
done
EOM
    if [[ $(eval $hdir | wc -l) -eq 0 ]];then
      success_result
    else
      failed_result
    fi

    ##############################################################################
    # 6.2.8 Ensure users' home directories permissions are 750 or more restrictive
    ##############################################################################
    header "6.2.8 Ensure users' home directories permissions are 750 or more restrictive"
    msg "CHECKING ... "
    read -r -d '' hdir_perms << EOM
#!/bin/bash

for dir in `cat /etc/passwd  | egrep -v '(root|halt|sync|shutdown)' | awk -F: '($7 != "/sbin/nologin") { print $6 }'`; do   
    dirperm=`ls -ld $dir | cut -f1 -d" "`   
    if [ `echo $dirperm | cut -c6`  != "-" ]; then     
      echo "Group Write permission set on directory $dir"   
    fi   
    if [ `echo $dirperm | cut -c8`  != "-" ]; then     
      echo "Other Read permission set on directory $dir"   
    fi   
    if [ `echo $dirperm | cut -c9`  != "-" ]; then     
      echo "Other Write permission set on directory $dir"   
    fi   
    if [ `echo $dirperm | cut -c10`  != "-" ]; then     
      echo "Other Execute permission set on directory $dir"   
    fi 
done
EOM
    if [[ $(eval $hdir_perms | wc -l) -eq 0 ]];then
      success_result
    else
      failed_result
    fi

    ###############################################
    # 6.2.9 Ensure users own their home directories
    ###############################################
    header "6.2.9 Ensure users own their home directories"
    msg "CHECKING ... "
    read -r -d '' hdir_own << EOM
#!/bin/bash
awk -F: '{ print $1 " " $3 " " $6 }' /etc/passwd | while read user uid dir; do  
if [ $uid -ge 1000 -a -d "$dir" -a $user != "nfsnobody" ]; then  
  owner=$(stat -L -c "%U" "$dir")  
  if [ "$owner" != "$user" ]; then  
    echo "The home directory ($dir) of user $user is owned by $owner."  
  fi  
fi 
done
EOM
    if [[ $(eval $hdir_own 2>&1 | wc -l) -eq 0 ]];then
      success_result
    else
      failed_result
    fi

    ################################################################
    # 6.2.10 Ensure users' dot files are not group or world writable
    ################################################################
    header "6.2.10 Ensure users' dot files are not group or world writable"
    msg "CHECKING ... "
    read -r -d '' dotfiles << EOM
#!/bin/bash
for dir in `cat /etc/passwd | egrep -v '(root|sync|halt|shutdown)' | awk -F: '($7 != "/sbin/nologin") { print $6 }'`; do   
    for file in $dir/.[A-Za-z0-9]*; do     
       if [ ! -h "$file" -a -f "$file" ]; then       
         fileperm=`ls -ld $file | cut -f1 -d" "`        
         if [ `echo $fileperm | cut -c6`  != "-" ]; then         
           echo "Group Write permission set on file $file"       
         fi       
         if [ `echo $fileperm | cut -c9`  != "-" ]; then         
           echo "Other Write permission set on file $file"       
         fi     
       fi   
   done 
done
EOM
    if [[ $(eval $dotfiles | wc -l) -eq 0 ]];then
      success_result
    else
      failed_result
    fi

    ############################################
    # 6.2.11 Ensure no users have .forward files
    ############################################
    header "6.2.11 Ensure no users have .forward files"
    msg "CHECKING ... "
    read -r -d '' forwards << EOM
#!/bin/bash
for dir in `cat /etc/passwd | awk -F: '{ print $6 }'`; do
  if [ ! -h "$dir/.forward" -a -f "$dir/.forward" ]; then
    echo ".forward file $dir/.forward exists"
  fi
done
EOM
    if [[ $(eval $forwards | wc -l) -eq 0 ]];then
      success_result
    else
      failed_result
    fi

    ############################################
    # 6.2.12 Ensure no users have .netrc files
    ############################################
    header "6.2.12 Ensure no users have .netrc files"
    msg "CHECKING ... "
    read -r -d '' netrc << EOM
#!/bin/bash
for dir in `cat /etc/passwd | awk -F: '{ print $6 }'`; do
  if [ ! -h "$dir/.netrc" -a -f "$dir/.netrc" ]; then
    echo ".netrc file $dir/.netrc exists"
  fi
done
EOM
    if [[ $(eval $netrc | wc -l) -eq 0 ]];then
      success_result
    else
      failed_result
    fi
    
    #####################################################################
    # 6.2.13 Ensure users' .netrc Files are not group or world accessible
    #####################################################################
    header "6.2.12 Ensure .netrc files aren't world accessible"
    msg "CHECKING ... "
    read -r -d '' netrcwa << EOM
#!/bin/bash
for dir in `egrep -v '(root|sync|halt|shutdown)' /etc/passwd | awk -F: '($7 != "/sbin/nologin") { print $6 }'`; do   
for file in $dir/.netrc; do     
    if [ ! -h "$file" -a -f "$file" ]; then       
      fileperm=`ls -ld $file | cut -f1 -d" "`       
      if [ `echo $fileperm | cut -c5`  != "-" ]; then         
        echo "Group Read set on $file"       
      fi       
      if [ `echo $fileperm | cut -c6`  != "-" ]; then         
        echo "Group Write set on $file"       
      fi       
      if [ `echo $fileperm | cut -c7`  != "-" ]; then         
        echo "Group Execute set on $file"       
      fi       
      if [ `echo $fileperm | cut -c8`  != "-" ]; then         
        echo "Other Read  set on $file"       
      fi       
      if [ `echo $fileperm | cut -c9`  != "-" ]; then         
        echo "Other Write set on $file"       
      fi       
      if [ `echo $fileperm | cut -c10`  != "-" ]; then         
        echo "Other Execute set on $file"       
      fi     
    fi   
  done 
done
EOM
    if [[ $(eval $netrcwa | wc -l) -eq 0 ]];then
      success_result
    else
      failed_result
    fi

    ###########################################
    # 6.2.14 Ensure no users have .rhosts files
    ###########################################
    header "6.2.14 Ensure no users have .rhosts files"
    msg "CHECKING ... "
    read -r -d '' rhosts << EOM
#!/bin/bash
for dir in `egrep -v '(root|halt|sync|shutdown)' /etc/passwd | awk -F: '($7 != "/sbin/nologin") { print $6 }'`; do   
    for file in $dir/.rhosts; do     
        if [ ! -h "$file" -a -f "$file" ]; then       
          echo ".rhosts file in $dir"     
        fi   
    done 
done
EOM
    if [[ $(eval $rhosts | wc -l) -eq 0 ]];then
      success_result
    else
      failed_result
    fi

    #############################################################
    # 6.2.15 Ensure all groups in /etc/passwd exist in /etc/group
    #############################################################
    header "6.2.15 Ensure all groups in /etc/passwd exist in /etc/group"
    msg "CHECKING ... "
    read -r -d '' gp << EOM
#!/bin/bash
for i in $(cut -s -d: -f4 /etc/passwd | sort -u ); do   
  grep -q -P "^.*?:[^:]*:$i:" /etc/group   
  if [ $? -ne 0 ]; then     
    echo "Group $i is referenced by /etc/passwd but does not exist in /etc/group"   
  fi 
done
EOM
    if [[ $(eval $gp | wc -l) -eq 0 ]];then
      success_result
    else
      failed_result
    fi

    #######################################
    # 6.2.16 Ensure no duplicate UIDs exist
    #######################################
    header "6.2.16 Ensure no duplicate UIDs exist"
    msg "CHECKING ... "
    read -r -d '' dupeuid << EOM
#!/bin/bash
cat /etc/passwd | cut -f3 -d":" | sort -n | uniq -c | while read x ; do   
  [ -z "${x}" ] && break   
  set - $x
  if [ $1 -gt 1 ]; then 
    users=`awk -F: '($3 == n) { print $1 }' n=$2 /etc/passwd | xargs`
    echo "Duplicate UID ($2): ${users}"
  fi
done
EOM
    if [[ $(eval $dupeuid | wc -l) -eq 0 ]];then
      success_result
    else
      failed_result
    fi

    #######################################
    # 6.2.17 Ensure no duplicate UIDs exist
    #######################################
    header "6.2.17 Ensure no duplicate GIDs exist"
    msg "CHECKING ... "
    read -r -d '' dupegid << EOM
#!/bin/bash
cat /etc/group | cut -f3 -d":" | sort -n | uniq -c | while read x ; do   
  [ -z "${x}" ] && break   
  set - $x
  if [ $1 -gt 1 ]; then 
    groups=`awk -F: '($3 == n) { print $1 }' n=$2 /etc/group | xargs`
    echo "Duplicate GID ($2): ${groups}"
  fi
done
EOM
    if [[ $(eval $dupegid | wc -l) -eq 0 ]];then
      success_result
    else
      failed_result
    fi

    #############################################
    # 6.2.18 Ensure no duplicate user names exist
    #############################################
    header "6.2.18 Ensure no duplicate user names exist"
    msg "CHECKING ... "
    read -r -d '' dupeu << EOM
#!/bin/bash
cat /etc/passwd | cut -f1 -d":" | sort -n | uniq -c | while read x ; do   
  [ -z "${x}" ] && break   
  set - $x
  if [ $1 -gt 1 ]; then 
    uids=`awk -F: '($1 == n) { print $3 }' n=$2 /etc/passwd | xargs`     
    echo "Duplicate User Name ($2): ${uids}"
  fi
done
EOM
    if [[ $(eval $dupeu | wc -l) -eq 0 ]];then
      success_result
    else
      failed_result
    fi

    ##############################################
    # 6.2.19 Ensure no duplicate group names exist
    ##############################################
    header "6.2.18 Ensure no duplicate group names exist"
    msg "CHECKING ... "
    read -r -d '' dupeg << EOM
#!/bin/bash
cat /etc/group | cut -f1 -d":" | sort -n | uniq -c | while read x ; do   
  [ -z "${x}" ] && break   
  set - $x   
  if [ $1 -gt 1 ]; then     
    gids=`gawk -F: '($1 == n) { print $3 }' n=$2 /etc/group | xargs`     
    echo "Duplicate Group Name ($2): ${gids}"   
  fi 
done
EOM
    if [[ $(eval $dupeg | wc -l) -eq 0 ]];then
      success_result
    else
      failed_result
    fi

##############
# FINAL REPORT
##############
for (( x=0; x < $(($WIDTH+1)); x++));do
    printf %s '='
done
printf "\n"
printf "%$(($WIDTH - 4))s" "TOTAL CHECKS: "
printf "%4s\n" "$(($PASSED_CHECKS + $FAILED_CHECKS))"
printf "%$(($WIDTH - 4))s" "FAILED CHECKS: "
printf "%4s\n" "$FAILED_CHECKS"
printf "%$(($WIDTH - 4))s" "PASSED CHECKS: "
printf "%4s\n" "$PASSED_CHECKS"