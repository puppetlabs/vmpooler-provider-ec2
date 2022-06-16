# frozen_string_literal: true

require 'bigdecimal'
require 'bigdecimal/util'
require 'vmpooler/providers/base'
require 'aws-sdk-ec2'

module Vmpooler
  class PoolManager
    class Provider
      # This class represent a GCE provider to CRUD resources in a gce cloud.
      class Aws < Vmpooler::PoolManager::Provider::Base
        # The connection_pool method is normally used only for testing
        attr_reader :connection_pool

        def initialize(config, logger, metrics, redis_connection_pool, name, options)
          super(config, logger, metrics, redis_connection_pool, name, options)
          
          @aws_access_key = ENV['ABS_AWS_ACCESS_KEY']
          @aws_secret_key = ENV['ABS_AWS_SECRET_KEY'] 
    
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
            new_conn = #connect to aws
            { connection: new_conn }
          end
          @redis = redis_connection_pool
        end

        # name of the provider class
        def name
          'aws'
        end

        def connection
          @connection_pool.with_metrics do |pool_object|
            return ensured_aws_connection(pool_object)
          end
        end

        def dns
          
          @dns
        end

        # main configuration options
        def project
          provider_config['project']
        end

        def network_name
          provider_config['network_name']
        end

        def subnetwork_name(pool_name)
          return pool_config(pool_name)['subnetwork_name'] if pool_config(pool_name)['subnetwork_name']
        end

        # main configuration options, overridable for each pool
        def zone(pool_name)
          return pool_config(pool_name)['zone'] if pool_config(pool_name)['zone']
          return provider_config['zone'] if provider_config['zone']
        end

        def region
          return provider_config['region'] if provider_config['region']
        end

        def machine_type(pool_name)
          return pool_config(pool_name)['machine_type'] if pool_config(pool_name)['machine_type']
          return provider_config['machine_type'] if provider_config['machine_type']
        end

        def domain
          provider_config['domain']
        end

        def dns_zone_resource_name
          provider_config['dns_zone_resource_name']
        end

        # Base methods that are implemented:

        # vms_in_pool lists all the VM names in a pool, which is based on the VMs
        # having a label "pool" that match a pool config name.
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

          zone = zone(pool_name)
          filter = "(labels.pool = #{pool_name})"
          instance_list = connection.list_instances(project, zone, filter: filter)

          return vms if instance_list.items.nil?

          instance_list.items.each do |vm|
            vms << { 'name' => vm.name }
          end
          debug_logger(vms)
          vms
        end

        # inputs
        #   [String] pool_name : Name of the pool
        #   [String] vm_name   : Name of the VM to find
        # returns
        #   nil if VM doesn't exist
        #   [Hastable] of the VM
        #    [String] name       : The name of the resource, provided by the client when initially creating the resource
        #    [String] hostname   : Specifies the hostname of the instance. The specified hostname must be RFC1035 compliant. If hostname is not specified,
        #                          the default hostname is [ INSTANCE_NAME].c.[PROJECT_ID].internal when using the global DNS, and
        #                          [ INSTANCE_NAME].[ZONE].c.[PROJECT_ID].internal when using zonal DNS
        #    [String] template   : This is the name of template
        #    [String] poolname   : Name of the pool the VM as per labels
        #    [Time]   boottime   : Time when the VM was created/booted
        #    [String] status     : One of the following values: PROVISIONING, STAGING, RUNNING, STOPPING, SUSPENDING, SUSPENDED, REPAIRING, and TERMINATED
        #    [String] zone       : URL of the zone where the instance resides.
        #    [String] machine_type : Full or partial URL of the machine type resource to use for this instance, in the format: zones/zone/machineTypes/machine-type.
        def get_vm(pool_name, vm_name)
          debug_logger('get_vm')
          vm_hash = nil
          begin
            vm_object = connection.get_instance(project, zone(pool_name), vm_name)
          rescue ::Google::Apis::ClientError => e
            raise e unless e.status_code == 404

            # swallow the ClientError error 404 and return nil when the VM was not found
            return nil
          end

          return vm_hash if vm_object.nil?

          vm_hash = generate_vm_hash(vm_object, pool_name)
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
          
          if zone(pool_name) == 'us-west-2b'
            subnet_id = 'subnet-0fe90a688844f6f26'
          else
            subnet_id = 'subnet-091b436f'
          end
          tag =  [
            {
              resource_type: "instance", # accepts capacity-reservation, client-vpn-endpoint, customer-gateway, carrier-gateway, dedicated-host, dhcp-options, egress-only-internet-gateway, elastic-ip, elastic-gpu, export-image-task, export-instance-task, fleet, fpga-image, host-reservation, image, import-image-task, import-snapshot-task, instance, instance-event-window, internet-gateway, ipam, ipam-pool, ipam-scope, ipv4pool-ec2, ipv6pool-ec2, key-pair, launch-template, local-gateway, local-gateway-route-table, local-gateway-virtual-interface, local-gateway-virtual-interface-group, local-gateway-route-table-vpc-association, local-gateway-route-table-virtual-interface-group-association, natgateway, network-acl, network-interface, network-insights-analysis, network-insights-path, network-insights-access-scope, network-insights-access-scope-analysis, placement-group, prefix-list, replace-root-volume-task, reserved-instances, route-table, security-group, security-group-rule, snapshot, spot-fleet-request, spot-instances-request, subnet, subnet-cidr-reservation, traffic-mirror-filter, traffic-mirror-session, traffic-mirror-target, transit-gateway, transit-gateway-attachment, transit-gateway-connect-peer, transit-gateway-multicast-domain, transit-gateway-route-table, volume, vpc, vpc-endpoint, vpc-endpoint-service, vpc-peering-connection, vpn-connection, vpn-gateway, vpc-flow-log
              tags: [
                {
                  key: "lifetime",
                  value: "1d",
                },
                {
                  key: "created_by",
                  value: "Tanisha",
                },
                {
                  key: "job_url",
                  value: "",
                },
                {
                  key: "organization",
                  value: "engineering",
                },
                {
                  key: "portfolio",
                  value: "ds-ci",
                },

              ],
            },
          ]
          config = {
              min_count: 1,
              max_count: 1,
              image_id: pool['template'],
              monitoring: {:enabled => true},
              key_name: 'always-be-scheduling',
              security_group_ids: ['sg-697fb015'],
              instance_type: pool['amisize'],
              disable_api_termination: false,
              instance_initiated_shutdown_behavior: 'terminate',
              tag_specifications: tag,
              subnet_id: subnet_id
          }
    
        #  if volume_size
        #    config[:block_device_mappings] = get_block_device_mappings(image_id, volume_size)
        #  end          

          debug_logger('trigger insert_instance')
          result = connection.create_instances(config)
          wait_for_operation(project, pool_name, result)
          created_instance = get_vm(pool_name, new_vmname)
          dns_setup(created_instance)
          created_instance
        end

        # create_disk creates an additional disk for an existing VM. It will name the new
        # disk #{vm_name}-disk#{number_disk} where number_disk is the next logical disk number
        # starting with 1 when adding an additional disk to a VM with only the boot disk:
        # #{vm_name}-disk0 == boot disk
        # #{vm_name}-disk1 == additional disk added via create_disk
        # #{vm_name}-disk2 == additional disk added via create_disk if run a second time etc
        # the new disk has labels added for vm and pool
        # The GCE lifecycle is to create a new disk (lives independently of the instance) then to attach
        # it to the existing instance.
        # inputs
        #   [String] pool_name  : Name of the pool
        #   [String] vm_name    : Name of the existing VM
        #   [String] disk_size  : The new disk size in GB
        # returns
        #   [boolean] true : once the operations are finished
        def create_disk(pool_name, vm_name, disk_size)
          debug_logger('create_disk')
          pool = pool_config(pool_name)
          raise("Pool #{pool_name} does not exist for the provider #{name}") if pool.nil?

          begin
            vm_object = connection.get_instance(project, zone(pool_name), vm_name)
          rescue ::Google::Apis::ClientError => e
            raise e unless e.status_code == 404

            # if it does not exist
            raise("VM #{vm_name} in pool #{pool_name} does not exist for the provider #{name}")
          end
          # this number should start at 1 when there is only the boot disk,
          # eg the new disk will be named spicy-proton-disk1
          number_disk = vm_object.disks.length

          disk_name = "#{vm_name}-disk#{number_disk}"
          disk = Google::Apis::ComputeV1::Disk.new(
            name: disk_name,
            size_gb: disk_size,
            labels: { 'pool' => pool_name, 'vm' => vm_name }
          )
          debug_logger("trigger insert_disk #{disk_name} for #{vm_name}")
          result = connection.insert_disk(project, zone(pool_name), disk)
          wait_for_operation(project, pool_name, result)
          debug_logger("trigger get_disk #{disk_name} for #{vm_name}")
          new_disk = connection.get_disk(project, zone(pool_name), disk_name)

          attached_disk = Google::Apis::ComputeV1::AttachedDisk.new(
            auto_delete: true,
            boot: false,
            source: new_disk.self_link
          )
          debug_logger("trigger attach_disk #{disk_name} for #{vm_name}")
          result = connection.attach_disk(project, zone(pool_name), vm_object.name, attached_disk)
          wait_for_operation(project, pool_name, result)
          true
        end

        # create_snapshot creates new snapshots with the unique name {new_snapshot_name}-#{disk.name}
        # for one vm, and one create_snapshot() there could be multiple snapshots created, one for each drive.
        # since the snapshot resource needs a unique name in the gce project,
        # we create a unique name by concatenating {new_snapshot_name}-#{disk.name}
        # the disk name is based on vm_name which makes it unique.
        # The snapshot is added labels snapshot_name, vm, pool, diskname and boot
        # inputs
        #   [String] pool_name  : Name of the pool
        #   [String] vm_name    : Name of the existing VM
        #   [String] new_snapshot_name : a unique name for this snapshot, which would be used to refer to it when reverting
        # returns
        #   [boolean] true : once the operations are finished
        # raises
        #   RuntimeError if the vm_name cannot be found
        #   RuntimeError if the snapshot_name already exists for this VM
        def create_snapshot(pool_name, vm_name, new_snapshot_name)
          debug_logger('create_snapshot')
          begin
            vm_object = connection.get_instance(project, zone(pool_name), vm_name)
          rescue ::Google::Apis::ClientError => e
            raise e unless e.status_code == 404

            # if it does not exist
            raise("VM #{vm_name} in pool #{pool_name} does not exist for the provider #{name}")
          end

          old_snap = find_snapshot(vm_name, new_snapshot_name)
          raise("Snapshot #{new_snapshot_name} for VM #{vm_name} in pool #{pool_name} already exists for the provider #{name}") unless old_snap.nil?

          result_list = []
          vm_object.disks.each do |attached_disk|
            disk_name = disk_name_from_source(attached_disk)
            snapshot_obj = ::Google::Apis::ComputeV1::Snapshot.new(
              name: "#{new_snapshot_name}-#{disk_name}",
              labels: {
                'snapshot_name' => new_snapshot_name,
                'vm' => vm_name,
                'pool' => pool_name,
                'diskname' => disk_name,
                'boot' => attached_disk.boot.to_s
              }
            )
            debug_logger("trigger async create_disk_snapshot #{vm_name}: #{new_snapshot_name}-#{disk_name}")
            result = connection.create_disk_snapshot(project, zone(pool_name), disk_name, snapshot_obj)
            # do them all async, keep a list, check later
            result_list << result
          end
          # now check they are done
          result_list.each do |result|
            wait_for_operation(project, pool_name, result)
          end
          true
        end

        # revert_snapshot reverts an existing VM's disks to an existing snapshot_name
        # reverting in gce entails
        # 1. shutting down the VM,
        # 2. detaching and deleting the drives,
        # 3. creating new disks with the same name from the snapshot for each disk
        # 4. attach disks and start instance
        # for one vm, there might be multiple snapshots in time. We select the ones referred to by the
        # snapshot_name, but that may be multiple snapshots, one for each disks
        # The new disk is added labels vm and pool
        # inputs
        #   [String] pool_name  : Name of the pool
        #   [String] vm_name    : Name of the existing VM
        #   [String] snapshot_name : Name of an existing snapshot
        # returns
        #   [boolean] true : once the operations are finished
        # raises
        #   RuntimeError if the vm_name cannot be found
        #   RuntimeError if the snapshot_name already exists for this VM
        def revert_snapshot(pool_name, vm_name, snapshot_name)
          debug_logger('revert_snapshot')
          begin
            vm_object = connection.get_instance(project, zone(pool_name), vm_name)
          rescue ::Google::Apis::ClientError => e
            raise e unless e.status_code == 404

            # if it does not exist
            raise("VM #{vm_name} in pool #{pool_name} does not exist for the provider #{name}")
          end

          snapshot_object = find_snapshot(vm_name, snapshot_name)
          raise("Snapshot #{snapshot_name} for VM #{vm_name} in pool #{pool_name} does not exist for the provider #{name}") if snapshot_object.nil?

          # Shutdown instance
          debug_logger("trigger stop_instance #{vm_name}")
          result = connection.stop_instance(project, zone(pool_name), vm_name)
          wait_for_operation(project, pool_name, result)

          # Delete existing disks
          vm_object.disks&.each do |attached_disk|
            debug_logger("trigger detach_disk #{vm_name}: #{attached_disk.device_name}")
            result = connection.detach_disk(project, zone(pool_name), vm_name, attached_disk.device_name)
            wait_for_operation(project, pool_name, result)
            current_disk_name = disk_name_from_source(attached_disk)
            debug_logger("trigger delete_disk #{vm_name}: #{current_disk_name}")
            result = connection.delete_disk(project, zone(pool_name), current_disk_name)
            wait_for_operation(project, pool_name, result)
          end

          # this block is sensitive to disruptions, for example if vmpooler is stopped while this is running
          snapshot_object.each do |snapshot|
            current_disk_name = snapshot.labels['diskname']
            bootable = (snapshot.labels['boot'] == 'true')
            disk = Google::Apis::ComputeV1::Disk.new(
              name: current_disk_name,
              labels: { 'pool' => pool_name, 'vm' => vm_name },
              source_snapshot: snapshot.self_link
            )
            # create disk in GCE as a separate resource
            debug_logger("trigger insert_disk #{vm_name}: #{current_disk_name} based on #{snapshot.self_link}")
            result = connection.insert_disk(project, zone(pool_name), disk)
            wait_for_operation(project, pool_name, result)
            # read the new disk info
            new_disk_info = connection.get_disk(project, zone(pool_name), current_disk_name)
            new_attached_disk = Google::Apis::ComputeV1::AttachedDisk.new(
              auto_delete: true,
              boot: bootable,
              source: new_disk_info.self_link
            )
            # attach the new disk to existing instance
            debug_logger("trigger attach_disk #{vm_name}: #{current_disk_name}")
            result = connection.attach_disk(project, zone(pool_name), vm_name, new_attached_disk)
            wait_for_operation(project, pool_name, result)
          end

          debug_logger("trigger start_instance #{vm_name}")
          result = connection.start_instance(project, zone(pool_name), vm_name)
          wait_for_operation(project, pool_name, result)
          true
        end

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
          begin
            connection.get_instance(project, zone(pool_name), vm_name)
          rescue ::Google::Apis::ClientError => e
            raise e unless e.status_code == 404

            # If a VM doesn't exist then it is effectively deleted
            deleted = true
            debug_logger("instance #{vm_name} already deleted")
          end

          unless deleted
            debug_logger("trigger delete_instance #{vm_name}")
            vm_hash = get_vm(pool_name, vm_name)
            result = connection.delete_instance(project, zone(pool_name), vm_name)
            wait_for_operation(project, pool_name, result, 10)
            dns_teardown(vm_hash)
          end

          # list and delete any leftover disk, for instance if they were detached from the instance
          filter = "(labels.vm = #{vm_name})"
          disk_list = connection.list_disks(project, zone(pool_name), filter: filter)
          result_list = []
          disk_list.items&.each do |disk|
            debug_logger("trigger delete_disk #{disk.name}")
            result = connection.delete_disk(project, zone(pool_name), disk.name)
            # do them all async, keep a list, check later
            result_list << result
          end
          # now check they are done
          result_list.each do |r|
            wait_for_operation(project, pool_name, r)
          end

          # list and delete leftover snapshots, this could happen if snapshots were taken,
          # as they are not removed when the original disk is deleted or the instance is detroyed
          snapshot_list = find_all_snapshots(vm_name)
          result_list = []
          snapshot_list&.each do |snapshot|
            debug_logger("trigger delete_snapshot #{snapshot.name}")
            result = connection.delete_snapshot(project, snapshot.name)
            # do them all async, keep a list, check later
            result_list << result
          end
          # now check they are done
          result_list.each do |r|
            wait_for_operation(project, pool_name, r)
          end
          true
        end

        def vm_ready?(_pool_name, vm_name)
          begin
            # TODO: we could use a healthcheck resource attached to instance
            open_socket(vm_name, domain || global_config[:config]['domain'])
          rescue StandardError => _e
            return false
          end
          true
        end

        # Scans zones that are configured for list of resources (VM, disks, snapshots) that do not have the label.pool set
        # to one of the configured pools. If it is also not in the allowlist, the resource is destroyed
        def purge_unconfigured_resources(allowlist)
          debug_logger('purge_unconfigured_resources')
          pools_array = provided_pools
          filter = {}
          # we have to group things by zone, because the API search feature is done against a zone and not global
          # so we will do the searches in each configured zone
          pools_array.each do |pool|
            filter[zone(pool)] = [] if filter[zone(pool)].nil?
            filter[zone(pool)] << "(labels.pool != #{pool})"
          end
          filter.each_key do |zone|
            # this filter should return any item that have a labels.pool that is not in the config OR
            # do not have a pool label at all
            filter_string = "#{filter[zone].join(' AND ')} OR -labels.pool:*"
            # VMs
            instance_list = connection.list_instances(project, zone, filter: filter_string)

            result_list = []
            instance_list.items&.each do |vm|
              next if should_be_ignored(vm, allowlist)

              debug_logger("trigger async delete_instance #{vm.name}")
              result = connection.delete_instance(project, zone, vm.name)
              vm_pool = vm.labels&.key?('pool') ? vm.labels['pool'] : nil
              existing_vm = generate_vm_hash(vm, vm_pool)
              dns_teardown(existing_vm)
              result_list << result
            end
            # now check they are done
            result_list.each do |result|
              wait_for_zone_operation(project, zone, result)
            end

            # Disks
            disks_list = connection.list_disks(project, zone, filter: filter_string)
            disks_list.items&.each do |disk|
              next if should_be_ignored(disk, allowlist)

              debug_logger("trigger async no wait delete_disk #{disk.name}")
              connection.delete_disk(project, zone, disk.name)
            end

            # Snapshots
            snapshot_list = connection.list_snapshots(project, filter: filter_string)
            next if snapshot_list.items.nil?

            snapshot_list.items.each do |sn|
              next if should_be_ignored(sn, allowlist)

              debug_logger("trigger async no wait delete_snapshot #{sn.name}")
              connection.delete_snapshot(project, sn.name)
            end
          end
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

          new_labels = vm_hash['labels']
          # bailing in this case since labels should exist, and continuing would mean losing them
          return false if new_labels.nil?

          # add new label called token-user, with value as user
          new_labels['token-user'] = user
          begin
            instances_set_labels_request_object = Google::Apis::ComputeV1::InstancesSetLabelsRequest.new(label_fingerprint: vm_hash['label_fingerprint'], labels: new_labels)
            result = connection.set_instance_labels(project, zone(pool), vm_name, instances_set_labels_request_object)
            wait_for_zone_operation(project, zone(pool), result)
          rescue StandardError => _e
            return false
          end
          true
        end

        # END BASE METHODS

        def dns_setup(created_instance)
          dns_zone = dns.zone(dns_zone_resource_name) if dns_zone_resource_name
          return unless dns_zone && created_instance && created_instance['name'] && created_instance['ip']

          name = created_instance['name']
          begin
            change = dns_zone.add(name, 'A', 60, [created_instance['ip']])
            debug_logger("#{change.id} - #{change.started_at} - #{change.status} DNS address added") if change
          rescue Google::Cloud::AlreadyExistsError => _e
            # DNS setup is done only for new instances, so in the rare case where a DNS record already exists (it is stale) and we replace it.
            # the error is Google::Cloud::AlreadyExistsError: alreadyExists: The resource 'entity.change.additions[0]' named 'instance-8.test.vmpooler.net. (A)' already exists
            change = dns_zone.replace(name, 'A', 60, [created_instance['ip']])
            debug_logger("#{change.id} - #{change.started_at} - #{change.status} DNS address previously existed and was replaced") if change
          end
        end

        def dns_teardown(created_instance)
          dns_zone = dns.zone(dns_zone_resource_name) if dns_zone_resource_name
          return unless dns_zone && created_instance

          name = created_instance['name']
          change = dns_zone.remove(name, 'A')
          debug_logger("#{change.id} - #{change.started_at} - #{change.status} DNS address removed") if change
        end

        def should_be_ignored(item, allowlist)
          return false if allowlist.nil?

          allowlist.map!(&:downcase) # remove uppercase from configured values because its not valid as resource label
          array_flattened_labels = []
          item.labels&.each do |k, v|
            array_flattened_labels << "#{k}=#{v}"
          end
          (!item.labels.nil? && allowlist&.include?(item.labels['pool'])) || # the allow list specifies the value within the pool label
            (allowlist&.include?('') && !item.labels&.keys&.include?('pool')) || # the allow list specifies "" string and the pool label is not set
            !(allowlist & array_flattened_labels).empty? # the allow list specify a fully qualified label eg user=Bob and the item has it
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

        # Compute resource wait for operation to be DONE (synchronous operation)
        def wait_for_zone_operation(project, zone, result, retries = 5)
          while result.status != 'DONE'
            result = connection.wait_zone_operation(project, zone, result.name)
            debug_logger("  -> wait_for_zone_operation status #{result.status} (#{result.name})")
          end
          if result.error # unsure what kind of error can be stored here
            error_message = ''
            # array of errors, combine them all
            result.error.errors.each do |error|
              error_message = "#{error_message} #{error.code}:#{error.message}"
            end
            raise "Operation: #{result.description} failed with error: #{error_message}"
          end
          result
        rescue Google::Apis::TransmissionError => e
          # Error returned once timeout reached, each retry typically about 1 minute.
          if retries.positive?
            retries -= 1
            retry
          end
          raise
        rescue Google::Apis::ClientError => e
          raise e unless e.status_code == 404

          # if the operation is not found, and we are 'waiting' on it, it might be because it
          # is already finished
          puts "waited on #{result.name} but was not found, so skipping"
        end

        def wait_for_operation(project, pool_name, result, retries = 5)
          wait_for_zone_operation(project, zone(pool_name), result, retries)
        end

        # Return a hash of VM data
        # Provides vmname, hostname, template, poolname, boottime, status, zone, machine_type, labels, label_fingerprint, ip information
        def generate_vm_hash(vm_object, pool_name)
          pool_configuration = pool_config(pool_name)
          return nil if pool_configuration.nil?

          {
            'name' => vm_object.name,
            'hostname' => vm_object.hostname,
            'template' => pool_configuration&.key?('template') ? pool_configuration['template'] : nil, # was expecting to get it from API, not from config, but this is what vSphere does too!
            'poolname' => vm_object.labels&.key?('pool') ? vm_object.labels['pool'] : nil,
            'boottime' => vm_object.creation_timestamp,
            'status' => vm_object.status, # One of the following values: PROVISIONING, STAGING, RUNNING, STOPPING, SUSPENDING, SUSPENDED, REPAIRING, and TERMINATED
            'zone' => vm_object.zone,
            'machine_type' => vm_object.machine_type,
            'labels' => vm_object.labels,
            'label_fingerprint' => vm_object.label_fingerprint,
            'ip' => vm_object.network_interfaces ? vm_object.network_interfaces.first.network_ip : nil
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

        # this is used because for one vm, with the same snapshot name there could be multiple snapshots,
        # one for each disk
        def find_snapshot(vm_name, snapshotname)
          filter = "(labels.vm = #{vm_name}) AND (labels.snapshot_name = #{snapshotname})"
          snapshot_list = connection.list_snapshots(project, filter: filter)
          snapshot_list.items # array of snapshot objects
        end

        # find all snapshots ever created for one vm,
        # regardless of snapshot name, for example when deleting it all
        def find_all_snapshots(vm_name)
          filter = "(labels.vm = #{vm_name})"
          snapshot_list = connection.list_snapshots(project, filter: filter)
          snapshot_list.items # array of snapshot objects
        end

        def disk_name_from_source(attached_disk)
          attached_disk.source.split('/')[-1] # disk name is after the last / of the full source URL
        end

        # used in local dev environment, set DEBUG_FLAG=true
        # this way the upstream vmpooler manager does not get polluted with logs
        def debug_logger(message, send_to_upstream: false)
          # the default logger is simple and does not enforce debug levels (the first argument)
          puts message if ENV['DEBUG_FLAG']
          logger.log('[g]', message) if send_to_upstream
        end
      end
    end
  end
end
