# frozen_string_literal: true

require 'net/ssh'
module Vmpooler
  class PoolManager
    # This class connects to existing running VMs via NET:SSH
    # it uses a local key to do so and then setup SSHD on the hosts to enable
    # dev and CI users to connect.
    class AwsSetup
      ROOT_KEYS_SCRIPT = ENV['ROOT_KEYS_SCRIPT']
      ROOT_KEYS_SYNC_CMD = "curl -k -o - -L #{ROOT_KEYS_SCRIPT} | %s"

      def self.setup_node_by_ssh(host, platform)
        @key_file = ENV['KEY_FILE_LOCATION'] || '/app/abs/.ssh/abs-aws-ec2.rsa'
        conn = check_ssh_accepting_connections(host, platform)
        configure_host(host, platform, conn)
      end

      # For an Amazon Linux AMI, the user name is ec2-user.
      #
      #     For a Centos AMI, the user name is centos.
      #
      #     For a Debian AMI, the user name is admin or root.
      #
      #     For a Fedora AMI, the user name is ec2-user or fedora.
      #
      #     For a RHEL AMI, the user name is ec2-user or root.
      #
      #     For a SUSE AMI, the user name is ec2-user or root.
      #
      #     For an Ubuntu AMI, the user name is ubuntu.

      def self.get_user(platform)
        if platform =~ /centos/
          'centos'
        elsif platform =~ /ubuntu/
          'ubuntu'
        elsif platform =~ /debian/
          'root'
        else
          'ec2-user'
        end
      end

      def self.check_ssh_accepting_connections(host, platform)
        retries = 0
        begin
          user = get_user(platform)
          netssh_jruby_workaround
          Net::SSH.start(host, user, keys: @key_file, timeout: 10)
        rescue Net::SSH::ConnectionTimeout, Errno::ECONNREFUSED => e
          puts "Requested instances do not have sshd ready yet, try again: #{e}"
          sleep 1
          retry if (retries += 1) < 300
        end
      end

      # Configure the aws host by enabling root and setting the hostname
      # @param host [String] the internal dns name of the instance
      def self.configure_host(host, platform, ssh)
        ssh.exec!('sudo cp -r .ssh /root/.')
        ssh.exec!("sudo sed -ri 's/^#?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config")
        ssh.exec!("sudo hostname #{host}")
        if platform =~ /amazon/
          # Amazon Linux requires this to preserve host name changes across reboots.
          ssh.exec!("sudo sed -ie '/^HOSTNAME/ s/=.*/=#{host}/' /etc/sysconfig/network")
        end
        restart_sshd(host, platform, ssh)
        sync_root_keys(host, platform)
      end

      def self.restart_sshd(host, platform, ssh)
        ssh.open_channel do |channel|
          channel.request_pty do |ch, success|
            raise "can't get pty request" unless success

            if platform =~ /centos|el-|redhat|fedora|eos|amazon/
              ch.exec('sudo -E /sbin/service sshd reload')
            elsif platform =~ /debian|ubuntu|cumulus/
              ch.exec('sudo su -c \"service sshd restart\"')
            elsif platform =~ /arch|centos-7|el-7|redhat-7|fedora-(1[4-9]|2[0-9])/
              ch.exec('sudo -E systemctl restart sshd.service')
            else
              services.logger.error("Attempting to update ssh on non-supported platform: #{host}: #{platform}")
            end
          end
        end
        ssh.loop
      end

      def self.sync_root_keys(host, _platform)
        return if ROOT_KEYS_SCRIPT.nil?

        user = 'root'
        netssh_jruby_workaround
        Net::SSH.start(host, user, keys: @key_file) do |ssh|
          ssh.exec!(ROOT_KEYS_SYNC_CMD % 'env PATH="/usr/gnu/bin:$PATH" bash')
        end
      end

      # issue when using net ssh 6.1.0 with jruby
      # https://github.com/jruby/jruby-openssl/issues/105
      # this will turn off some algos that match /^ecd(sa|h)-sha2/
      def self.netssh_jruby_workaround
        Net::SSH::Transport::Algorithms::ALGORITHMS.each_value { |algs| algs.reject! { |a| a =~ /^ecd(sa|h)-sha2/ } }
        Net::SSH::KnownHosts::SUPPORTED_TYPE.reject! { |t| t =~ /^ecd(sa|h)-sha2/ }
      end
    end
  end
end
