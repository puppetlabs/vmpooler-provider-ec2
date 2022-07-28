# frozen_string_literal: true

require 'bigdecimal'
require 'bigdecimal/util'
require 'vmpooler/providers/base'
require 'vmpooler/cloud_dns'
require 'aws-sdk-ec2'
require 'vmpooler/aws_setup'

module Vmpooler
  class PoolManager
    class Provider
      # This class represent a GCE provider to CRUD resources in a gce cloud.
      class Ec2 < Vmpooler::PoolManager::Provider::Base
        # The connection_pool method is normally used only for testing
        attr_reader :connection_pool

        def initialize(config, logger, metrics, redis_connection_pool, name, options)
          super(config, logger, metrics, redis_connection_pool, name, options)

          @aws_access_key = ENV['ABS_AWS_ACCESS_KEY'] || provider_config['ABS_AWS_ACCESS_KEY']
          @aws_secret_key = ENV['ABS_AWS_SECRET_KEY'] || provider_config['ABS_AWS_SECRET_KEY']

          task_limit = global_config[:config].nil? || global_config[:config]['task_limit'].nil? ? 10 : global_config[:config]['task_limit'].to_i
          # The default connection pool size is:
          # Whatever is biggest from:
          #   - How many pools this provider services
          #   - Maximum number of cloning tasks allowed
          #   - Need at least 2 connections so that a pool can have inventory functions performed while cloning etc.
          default_connpool_size = [provided_pools.count, task_limit, 2].max
          connpool_size = provider_config['connection_pool_size'].nil? ? default_connpool_size : provider_config['connection_pool_size'].to_i
          # The default connection pool timeout should be quite large - 60 seconds
          connpool_timeout = provider_config['connection_pool_timeout'].nil? ? 60 : provider_config['connection_pool_timeout'].to_i
          logger.log('d', "[#{name}] ConnPool - Creating a connection pool of size #{connpool_size} with timeout #{connpool_timeout}")
          @logger = logger
          @connection_pool = Vmpooler::PoolManager::GenericConnectionPool.new(
            metrics: metrics,
            connpool_type: 'provider_connection_pool',
            connpool_provider: name,
            size: connpool_size,
            timeout: connpool_timeout
          ) do
            logger.log('d', "[#{name}] Connection Pool - Creating a connection object")
            # Need to wrap the vSphere connection object in another object. The generic connection pooler will preserve
            # the object reference for the connection, which means it cannot "reconnect" by creating an entirely new connection
            # object.  Instead by wrapping it in a Hash, the Hash object reference itself never changes but the content of the
            # Hash can change, and is preserved across invocations.
            new_conn = connect_to_aws
            { connection: new_conn }
          end
          @redis = redis_connection_pool
        end

        # name of the provider class
        def name
          'ec2'
        end

        def connection
          @connection_pool.with_metrics do |pool_object|
            return ensured_aws_connection(pool_object)
          end
        end

        # main configuration options
        def region
          provider_config['region']
        end

        # main configuration options, overridable for each pool
        def zone(pool_name)
          return pool_config(pool_name)['zone'] if pool_config(pool_name)['zone']

          provider_config['zone']
        end

        def amisize(pool_name)
          return pool_config(pool_name)['amisize'] if pool_config(pool_name)['amisize']

          provider_config['amisize']
        end

        def volume_size(pool_name)
          return pool_config(pool_name)['volume_size'] if pool_config(pool_name)['volume_size']

          provider_config['volume_size']
        end

        # dns
        def project
          provider_config['project']
        end

        def domain
          provider_config['domain']
        end

        def dns_zone_resource_name
          provider_config['dns_zone_resource_name']
        end

        # subnets
        def get_subnet_id(pool_name)
          case zone(pool_name)
          when 'us-west-2b'
            'subnet-0fe90a688844f6f26'
          when 'us-west-2a'
            'subnet-091b436f'
          end
        end

        def to_provision(pool_name)
          pool_config(pool_name)['provision']
        end

        # Base methods that are implemented:

        # vms_in_pool lists all the VM names in a pool, which is based on the VMs
        # having a tag "pool" that match a pool config name.
        # inputs
        #   [String] pool_name : Name of the pool
        # returns
        #   empty array [] if no VMs found in the pool
        #   [Array]
        #     [Hashtable]
        #       [String] name : the name of the VM instance (unique for whole project)
        def vms_in_pool(pool_name)
          debug_logger('vms_in_pool')
          vms = []
          pool = pool_config(pool_name)
          raise("Pool #{pool_name} does not exist for the provider #{name}") if pool.nil?

          filters = [
            {
              name: 'tag:pool',
              values: [pool_name]
            },
            {
              name: 'instance-state-name',
              values: %w[pending running shutting-down stopping stopped]
            }
          ]
          instance_list = connection.instances(filters: filters)

          return vms if instance_list.first.nil?

          instance_list.each do |vm|
            vms << { 'name' => vm.tags.detect { |f| f.key == 'vm_name' }&.value || 'vm_name not found in tags' }
          end
          debug_logger(vms)
          vms
        end

        # inputs
        #   [String] pool_name : Name of the pool
        #   [String] vm_name   : Name of the VM to find
        # returns
        #   nil if VM doesn't exist name, template, poolname, boottime, status, image_size, private_ip_address
        #   [Hastable] of the VM
        #    [String] name       : The name of the resource, provided by the client when initially creating the resource
        #    [String] template   : This is the name of template
        #    [String] poolname   : Name of the pool the VM
        #    [Time]   boottime   : Time when the VM was created/booted
        #    [String] status     : One of the following values: pending, running, shutting-down, terminated, stopping, stopped
        #    [String] image_size : The EC2 image size eg a1.large
        #    [String] private_ip_address: The private IPv4 address
        def get_vm(pool_name, vm_name)
          debug_logger('get_vm')
          vm_hash = nil

          filters = [{
            name: 'tag:vm_name',
            values: [vm_name]
          }]
          instances = connection.instances(filters: filters).first
          return vm_hash if instances.nil?

          vm_hash = generate_vm_hash(instances, pool_name)
          debug_logger("vm_hash #{vm_hash}")
          vm_hash
        end

        # create_vm creates a new VM with a default network from the config,
        # a initial disk named #{new_vmname}-disk0 that uses the 'template' as its source image
        # and labels added for vm and pool
        # and an instance configuration for machine_type from the config and
        # labels vm and pool
        # having a label "pool" that match a pool config name.
        # inputs
        #   [String] pool       : Name of the pool
        #   [String] new_vmname : Name to give the new VM
        # returns
        #   [Hashtable] of the VM as per get_vm(pool_name, vm_name)
        def create_vm(pool_name, new_vmname)
          debug_logger('create_vm')
          pool = pool_config(pool_name)
          raise("Pool #{pool_name} does not exist for the provider #{name}") if pool.nil?
          raise("Instance creation not attempted, #{new_vmname} already exists") if get_vm(pool_name, new_vmname)

          subnet_id = get_subnet_id(pool_name)
          domain_set = domain
          name_to_use = if domain_set.nil?
                          new_vmname
                        else
                          "#{new_vmname}.#{domain_set}"
                        end

          tag = [
            {
              resource_type: 'instance', # accepts capacity-reservation, client-vpn-endpoint, customer-gateway, carrier-gateway, dedicated-host, dhcp-options, egress-only-internet-gateway, elastic-ip, elastic-gpu, export-image-task, export-instance-task, fleet, fpga-image, host-reservation, image, import-image-task, import-snapshot-task, instance, instance-event-window, internet-gateway, ipam, ipam-pool, ipam-scope, ipv4pool-ec2, ipv6pool-ec2, key-pair, launch-template, local-gateway, local-gateway-route-table, local-gateway-virtual-interface, local-gateway-virtual-interface-group, local-gateway-route-table-vpc-association, local-gateway-route-table-virtual-interface-group-association, natgateway, network-acl, network-interface, network-insights-analysis, network-insights-path, network-insights-access-scope, network-insights-access-scope-analysis, placement-group, prefix-list, replace-root-volume-task, reserved-instances, route-table, security-group, security-group-rule, snapshot, spot-fleet-request, spot-instances-request, subnet, subnet-cidr-reservation, traffic-mirror-filter, traffic-mirror-session, traffic-mirror-target, transit-gateway, transit-gateway-attachment, transit-gateway-connect-peer, transit-gateway-multicast-domain, transit-gateway-route-table, volume, vpc, vpc-endpoint, vpc-endpoint-service, vpc-peering-connection, vpn-connection, vpn-gateway, vpc-flow-log
              tags: [
                {
                  key: 'vm_name',
                  value: new_vmname
                },
                {
                  key: 'pool',
                  value: pool_name
                },
                {
                  key: 'lifetime', # required by AWS reaper
                  value: max_lifetime
                },
                {
                  key: 'created_by', # required by AWS reaper
                  value: get_current_user(new_vmname)
                },
                {
                  key: 'job_url',
                  value: get_current_job_url(new_vmname)
                },
                {
                  key: 'organization', # required by AWS reaper
                  value: 'engineering'
                },
                {
                  key: 'portfolio', # required by AWS reaper
                  value: 'ds-ci'
                },
                {
                  key: 'Name',
                  value: name_to_use
                }
              ]
            }
          ]
          config = {
            min_count: 1,
            max_count: 1,
            image_id: pool['template'],
            monitoring: { enabled: true },
            key_name: 'always-be-scheduling',
            security_group_ids: ['sg-697fb015'],
            instance_type: amisize(pool_name),
            disable_api_termination: false,
            instance_initiated_shutdown_behavior: 'terminate',
            tag_specifications: tag,
            subnet_id: subnet_id
          }

          config[:block_device_mappings] = get_block_device_mappings(config['image_id'], volume_size(pool_name)) if volume_size(pool_name)

          debug_logger('trigger insert_instance')
          batch_instance = connection.create_instances(config)
          instance_id = batch_instance.first.instance_id
          connection.client.wait_until(:instance_running, { instance_ids: [instance_id] })
          @logger.log('s', "[>] [#{pool_name}] '#{new_vmname}' instance running")
          ### System status checks
          # This check verifies that your instance is reachable. Amazon EC2 tests that network packets can get to your instance.
          ### Instance status checks
          # This check verifies that your instance's operating system is accepting traffic.
          connection.client.wait_until(:instance_status_ok, { instance_ids: [instance_id] })
          @logger.log('s', "[>] [#{pool_name}] '#{new_vmname}' instance ready to accept traffic")
          created_instance = get_vm(pool_name, new_vmname)

          @redis.with_metrics do |redis|
            redis.hset("vmpooler__vm__#{new_vmname}", 'host', created_instance['private_dns_name'])
          end

          if domain
            dns_setup(created_instance)
            provision_node_aws(created_instance['name'], pool_name, new_vmname) if to_provision(pool_name) == 'true' || to_provision(pool_name) == true
          elsif to_provision(pool_name) == 'true' || to_provision(pool_name) == true
            provision_node_aws(created_instance['private_dns_name'], pool_name, new_vmname)
          end

          created_instance
        end

        def provision_node_aws(vm, pool_name, new_vmname)
          aws_setup = AwsSetup.new(@logger, new_vmname)
          aws_setup.setup_node_by_ssh(vm, pool_name)
        end

        def get_block_device_mappings(image_id, volume_size)
          ec2_client = connection.client
          image = ec2_client.describe_images(image_ids: [image_id]).images.first
          raise "Image not found: #{image_id}" if image.nil?
          raise "#{image_id} does not have an ebs root device type" unless image.root_device_type == 'ebs'

          # Transform the images block_device_mappings output into a format
          # ready for a create.
          block_device_mappings = []
          orig_bdm = image.block_device_mappings
          orig_bdm.each do |block_device|
            block_device_mappings << {
              device_name: block_device.device_name,
              ebs: {
                # Change the default size of the root volume.
                volume_size: volume_size,
                # This is required to override the images default for
                # delete_on_termination, forcing all volumes to be deleted once the
                # instance is terminated.
                delete_on_termination: true
              }
            }
          end
          block_device_mappings
        end

        # create_disk creates an additional disk for an existing VM. It will name the new
        # disk #{vm_name}-disk#{number_disk} where number_disk is the next logical disk number
        # starting with 1 when adding an additional disk to a VM with only the boot disk:
        # #{vm_name}-disk0 == boot disk
        # #{vm_name}-disk1 == additional disk added via create_disk
        # #{vm_name}-disk2 == additional disk added via create_disk if run a second time etc
        # the new disk has labels added for vm and pool
        # The AWS lifecycle is to create a new disk (lives independently of the instance) then to attach
        # it to the existing instance.
        # inputs
        #   [String] pool_name  : Name of the pool
        #   [String] vm_name    : Name of the existing VM
        #   [String] disk_size  : The new disk size in GB
        # returns
        #   [boolean] true : once the operations are finished

        # create_snapshot creates new snapshots with the unique name {new_snapshot_name}-#{disk.name}
        # for one vm, and one create_snapshot() there could be multiple snapshots created, one for each drive.
        # since the snapshot resource needs a unique name in the gce project,
        # we create a unique name by concatenating {new_snapshot_name}-#{disk.name}
        # the disk name is based on vm_name which makes it unique.
        # The snapshot is added tags snapshot_name, vm, pool, diskname and boot
        # inputs
        #   [String] pool_name  : Name of the pool
        #   [String] vm_name    : Name of the existing VM
        #   [String] new_snapshot_name : a unique name for this snapshot, which would be used to refer to it when reverting
        # returns
        #   [boolean] true : once the operations are finished
        # raises
        #   RuntimeError if the vm_name cannot be found
        #   RuntimeError if the snapshot_name already exists for this VM

        # revert_snapshot reverts an existing VM's disks to an existing snapshot_name
        # reverting in aws entails
        # 1. shutting down the VM,
        # 2. detaching and deleting the drives,
        # 3. creating new disks with the same name from the snapshot for each disk
        # 4. attach disks and start instance
        # for one vm, there might be multiple snapshots in time. We select the ones referred to by the
        # snapshot_name, but that may be multiple snapshots, one for each disks
        # The new disk is added tags vm and pool
        # inputs
        #   [String] pool_name  : Name of the pool
        #   [String] vm_name    : Name of the existing VM
        #   [String] snapshot_name : Name of an existing snapshot
        # returns
        #   [boolean] true : once the operations are finished
        # raises
        #   RuntimeError if the vm_name cannot be found
        #   RuntimeError if the snapshot_name already exists for this VM

        # destroy_vm deletes an existing VM instance and any disks and snapshots via the labels
        # in gce instances, disks and snapshots are resources that can exist independent of each other
        # inputs
        #   [String] pool_name  : Name of the pool
        #   [String] vm_name    : Name of the existing VM
        # returns
        #   [boolean] true : once the operations are finished
        def destroy_vm(pool_name, vm_name)
          debug_logger('destroy_vm')
          deleted = false

          filters = [{
            name: 'tag:vm_name',
            values: [vm_name]
          }]
          instances = connection.instances(filters: filters).first
          return true if instances.nil?

          instance_hash = get_vm(pool_name, vm_name)
          debug_logger("trigger delete_instance #{vm_name}")
          instances.terminate
          begin
            connection.client.wait_until(:instance_terminated, { instance_ids: [instances.id] })
            deleted = true
          rescue ::Aws::Waiters::Errors => e
            debug_logger("failed waiting for instance terminated #{vm_name}: #{e}")
          end

          dns_teardown(instance_hash) if domain

          deleted
        end

        # check if a vm is ready by opening a socket on port 22
        # if a domain is set, it will use vn_name.domain,
        # if not then it will use the private dns name directly (AWS workaround)
        def vm_ready?(pool_name, vm_name)
          begin
            domain_set = domain
            if domain_set.nil?
              vm_ip = get_vm(pool_name, vm_name)['private_dns_name']
              vm_name = vm_ip unless vm_ip.nil?
            end
            open_socket(vm_name, domain_set)
          rescue StandardError => e
            @logger.log('s', "[!] [#{pool_name}] '#{vm_name}' instance cannot be reached by vmpooler on tcp port 22; #{e}")
            return false
          end
          true
        end

        # tag_vm_user This method is called once we know who is using the VM (it is running). This method enables seeing
        # who is using what in the provider pools.
        #
        # inputs
        #   [String] pool_name : Name of the pool
        #   [String] vm_name   : Name of the VM to check if ready
        # returns
        #   [Boolean] : true if successful, false if an error occurred and it should retry
        def tag_vm_user(pool, vm_name)
          user = get_current_user(vm_name)
          vm_hash = get_vm(pool, vm_name)
          return false if vm_hash.nil?

          filters = [{
            name: 'tag:vm_name',
            values: [vm_name]
          }]
          instances = connection.instances(filters: filters).first
          return false if instances.nil?

          # add new label called token-user, with value as user
          instances.create_tags(tags: [key: 'token-user', value: user])
          true
        rescue StandardError => _e
          false
        end

        # END BASE METHODS

        def dns_setup(created_instance)
          dns = Vmpooler::PoolManager::CloudDns.new(project, dns_zone_resource_name)
          dns.dns_create_or_replace(created_instance)
        end

        def dns_teardown(created_instance)
          dns = Vmpooler::PoolManager::CloudDns.new(project, dns_zone_resource_name)
          dns.dns_teardown(created_instance)
        end

        def get_current_user(vm_name)
          @redis.with_metrics do |redis|
            user = redis.hget("vmpooler__vm__#{vm_name}", 'token:user')
            return '' if user.nil?

            # cleanup so it's a valid label value
            # can't have upercase
            user = user.downcase
            # replace invalid chars with dash
            user = user.gsub(/[^0-9a-z_-]/, '-')
            return user
          end
        end

        # returns lifetime in hours in the format Xh defaults to 1h
        def get_current_lifetime(vm_name)
          @redis.with_metrics do |redis|
            lifetime = redis.hget("vmpooler__vm__#{vm_name}", 'lifetime') || '1'
            return "#{lifetime}h"
          end
        end

        # returns max_lifetime_upper_limit in hours in the format Xh defaults to 12h
        def max_lifetime
          max_hours = global_config[:config]['max_lifetime_upper_limit'] || '12'
          "#{max_hours}h"
        end

        def get_current_job_url(vm_name)
          @redis.with_metrics do |redis|
            job = redis.hget("vmpooler__vm__#{vm_name}", 'tag:jenkins_build_url') || ''
            return job
          end
        end

        # Return a hash of VM data
        # Provides name, template, poolname, boottime, status, image_size, private_ip_address
        def generate_vm_hash(vm_object, pool_name)
          pool_configuration = pool_config(pool_name)
          return nil if pool_configuration.nil?

          {
            'name' => vm_object.tags.detect { |f| f.key == 'Name' }&.value,
            # 'hostname' => vm_object.hostname,
            'template' => pool_configuration&.key?('template') ? pool_configuration['template'] : nil, # was expecting to get it from API, not from config, but this is what vSphere does too!
            'poolname' => vm_object.tags.detect { |f| f.key == 'pool' }&.value,
            'boottime' => vm_object.launch_time,
            'status' => vm_object.state&.name, # One of the following values: pending, running, shutting-down, terminated, stopping, stopped
            # 'zone' => vm_object.zone,
            'image_size' => vm_object.instance_type,
            'ip' => vm_object.private_ip_address, # used by the cloud dns class to set the record to this value
            'private_ip_address' => vm_object.private_ip_address,
            'private_dns_name' => vm_object.private_dns_name
          }
        end

        def ensured_aws_connection(connection_pool_object)
          connection_pool_object[:connection] = connect_to_aws unless connection_pool_object[:connection]
          connection_pool_object[:connection]
        end

        def connect_to_aws
          max_tries = global_config[:config]['max_tries'] || 3
          retry_factor = global_config[:config]['retry_factor'] || 10
          try = 1
          begin
            compute = ::Aws::EC2::Resource.new(
              region: region,
              credentials: ::Aws::Credentials.new(@aws_access_key, @aws_secret_key),
              log_level: :debug
            )

            metrics.increment('connect.open')
            compute
          rescue StandardError => e # is that even a thing?
            metrics.increment('connect.fail')
            raise e if try >= max_tries

            sleep(try * retry_factor)
            try += 1
            retry
          end
        end

        # This should supercede the open_socket method in the Pool Manager
        def open_socket(host, domain = nil, timeout = 5, port = 22, &_block)
          Timeout.timeout(timeout) do
            target_host = host
            target_host = "#{host}.#{domain}" if domain
            sock = TCPSocket.new target_host, port
            begin
              yield sock if block_given?
            ensure
              sock.close
            end
          end
        end

        # used in local dev environment, set DEBUG_FLAG=true
        # this way the upstream vmpooler manager does not get polluted with logs
        def debug_logger(message, send_to_upstream: false)
          # the default logger is simple and does not enforce debug levels (the first argument)
          puts message if ENV['DEBUG_FLAG']
          @logger.log('[g]', message) if send_to_upstream
        end
      end
    end
  end
end
