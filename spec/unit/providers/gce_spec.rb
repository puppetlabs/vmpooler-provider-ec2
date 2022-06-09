require 'spec_helper'
require 'mock_redis'
require 'vmpooler/providers/gce'

RSpec::Matchers.define :relocation_spec_with_host do |value|
  match { |actual| actual[:spec].host == value }
end

describe 'Vmpooler::PoolManager::Provider::Gce' do
  let(:logger) { MockLogger.new }
  let(:metrics) { Vmpooler::Metrics::DummyStatsd.new }
  let(:poolname) { 'debian-9' }
  let(:provider_options) { { 'param' => 'value' } }
  let(:project) { 'vmpooler-test' }
  let(:zone) { 'us-west1-b' }
  let(:config) { YAML.load(<<~EOT
  ---
  :config:
    max_tries: 3
    retry_factor: 10
  :providers:
    :gce:
      connection_pool_timeout: 1
      project: '#{project}'
      zone: '#{zone}'
      network_name: global/networks/default
  :pools:
    - name: '#{poolname}'
      alias: [ 'mockpool' ]
      template: 'projects/debian-cloud/global/images/family/debian-9'
      size: 5
      timeout: 10
      ready_ttl: 1440
      provider: 'gce'
      machine_type: 'zones/#{zone}/machineTypes/e2-micro'
EOT
    )
  }

  let(:vmname) { 'vm17' }
  let(:connection) { MockComputeServiceConnection.new }
  let(:redis_connection_pool) do
    Vmpooler::PoolManager::GenericConnectionPool.new(
      metrics: metrics,
      connpool_type: 'redis_connection_pool',
      connpool_provider: 'testprovider',
      size: 1,
      timeout: 5
    ) { MockRedis.new }
  end

  subject { Vmpooler::PoolManager::Provider::Gce.new(config, logger, metrics, redis_connection_pool, 'gce', provider_options) }

  before(:each) { allow(subject).to receive(:dns).and_return(MockDNS.new()) }

  describe '#name' do
    it 'should be gce' do
      expect(subject.name).to eq('gce')
    end
  end

  describe '#manual tests live' do
    context 'in itsysops' do
      before(:each) { allow(subject).to receive(:dns).and_call_original }
      let(:vmname) { "instance-24" }
      let(:project) { 'vmpooler-test' }
      let(:config) { YAML.load(<<~EOT
      ---
      :config:
        max_tries: 3
        retry_factor: 10
      :providers:
        :gce:
          connection_pool_timeout: 1
          project: '#{project}'
          zone: '#{zone}'
          network_name: 'projects/itsysopsnetworking/global/networks/shared1'
          dns_zone_resource_name: 'test-vmpooler-puppet-net'
          domain: 'test.vmpooler.puppet.net'
      :pools:
        - name: '#{poolname}'
          alias: [ 'mockpool' ]
          template: 'projects/debian-cloud/global/images/family/debian-9'
          size: 5
          timeout: 10
          ready_ttl: 1440
          provider: 'gce'
          subnetwork_name: 'projects/itsysopsnetworking/regions/us-west1/subnetworks/vmpooler-test'
          machine_type: 'zones/#{zone}/machineTypes/e2-micro'
EOT
      ) }
      skip 'gets a vm' do
        result = subject.create_vm(poolname, vmname)
        #result = subject.destroy_vm(poolname, vmname)
        subject.get_vm(poolname, vmname)
        #subject.dns_teardown({'name' => vmname})
        # subject.dns_setup({'name' => vmname, 'ip' => '1.2.3.5'})
      end
    end
  end

  describe '#vms_in_pool' do
    let(:pool_config) { config[:pools][0] }

    before(:each) do
      allow(subject).to receive(:connect_to_gce).and_return(connection)
    end

    context 'Given an empty pool folder' do
      it 'should return an empty array' do
        instance_list = MockInstanceList.new(items: nil)
        allow(connection).to receive(:list_instances).and_return(instance_list)
        result = subject.vms_in_pool(poolname)

        expect(result).to eq([])
      end
    end

    context 'Given a pool folder with many VMs' do
      let(:expected_vm_list) do
        [
          { 'name' => 'vm1' },
          { 'name' => 'vm2' },
          { 'name' => 'vm3' }
        ]
      end
      before(:each) do
        instance_list = MockInstanceList.new(items: [])
        expected_vm_list.each do |vm_hash|
          mock_vm = MockInstance.new(name: vm_hash['name'])
          instance_list.items << mock_vm
        end

        expect(connection).to receive(:list_instances).and_return(instance_list)
      end

      it 'should list all VMs in the VM folder for the pool' do
        result = subject.vms_in_pool(poolname)

        expect(result).to eq(expected_vm_list)
      end
    end
  end

  describe '#get_vm' do
    before(:each) do
      allow(subject).to receive(:connect_to_gce).and_return(connection)
    end

    context 'when VM does not exist' do
      it 'should return nil' do
        allow(connection).to receive(:get_instance).and_raise(create_google_client_error(404, "The resource 'projects/#{project}/zones/#{zone}/instances/#{vmname}' was not found"))
        expect(subject.get_vm(poolname, vmname)).to be_nil
      end
    end

    context 'when VM exists but is missing information' do
      before(:each) do
        allow(connection).to receive(:get_instance).and_return(MockInstance.new(name: vmname))
      end

      it 'should return a hash' do
        expect(subject.get_vm(poolname, vmname)).to be_kind_of(Hash)
      end

      it 'should return the VM name' do
        result = subject.get_vm(poolname, vmname)

        expect(result['name']).to eq(vmname)
      end

      %w[hostname boottime zone status].each do |testcase|
        it "should return nil for #{testcase}" do
          result = subject.get_vm(poolname, vmname)

          expect(result[testcase]).to be_nil
        end
      end
    end

    context 'when VM exists and contains all information' do
      let(:vm_hostname) { "#{vmname}.demo.local" }
      let(:boot_time) { Time.now }
      let(:vm_object) do
        MockInstance.new(
          name: vmname,
          hostname: vm_hostname,
          labels: { 'pool' => poolname },
          creation_timestamp: boot_time,
          status: 'RUNNING',
          zone: zone,
          machine_type: "zones/#{zone}/machineTypes/e2-micro"
        )
      end
      let(:pool_info) { config[:pools][0] }

      before(:each) do
        allow(connection).to receive(:get_instance).and_return(vm_object)
      end

      it 'should return a hash' do
        expect(subject.get_vm(poolname, vmname)).to be_kind_of(Hash)
      end

      it 'should return the VM name' do
        result = subject.get_vm(poolname, vmname)

        expect(result['name']).to eq(vmname)
      end

      it 'should return the VM hostname' do
        result = subject.get_vm(poolname, vmname)

        expect(result['hostname']).to eq(vm_hostname)
      end

      it 'should return the template name' do
        result = subject.get_vm(poolname, vmname)

        expect(result['template']).to eq(pool_info['template'])
      end

      it 'should return the pool name' do
        result = subject.get_vm(poolname, vmname)

        expect(result['poolname']).to eq(pool_info['name'])
      end

      it 'should return the boot time' do
        result = subject.get_vm(poolname, vmname)

        expect(result['boottime']).to eq(boot_time)
      end
    end
  end

  describe '#create_vm' do
    before(:each) do
      allow(subject).to receive(:connect_to_gce).and_return(connection)
    end

    context 'Given an invalid pool name' do
      it 'should raise an error' do
        expect { subject.create_vm('missing_pool', vmname) }.to raise_error(/missing_pool does not exist/)
      end
    end

    context 'Given a template VM that does not exist' do
      before(:each) do
        config[:pools][0]['template'] = 'Templates/missing_template'
        #         result = MockResult.new
        #         result.status = "PENDING"
        #         errors = MockOperationError
        #         errors << MockOperationErrorError.new(code: "foo", message: "it's missing")
        #         result.error = errors
        allow(connection).to receive(:insert_instance).and_raise(create_google_client_error(404, 'The resource \'Templates/missing_template\' was not found'))
      end

      it 'should raise an error' do
        expect { subject.create_vm(poolname, vmname) }.to raise_error(Google::Apis::ClientError)
      end
    end

    context 'Given a successful creation' do
      before(:each) do
        result = MockResult.new
        result.status = 'DONE'
        allow(connection).to receive(:insert_instance).and_return(result)
      end

      it 'should return a hash' do
        allow(connection).to receive(:get_instance).and_return(MockInstance.new)
        result = subject.create_vm(poolname, vmname)

        expect(result.is_a?(Hash)).to be true
      end

      it 'should have the new VM name' do
        instance = MockInstance.new(name: vmname)
        allow(connection).to receive(:get_instance).and_return(instance)
        result = subject.create_vm(poolname, vmname)

        expect(result['name']).to eq(vmname)
      end
    end
  end

  describe '#destroy_vm' do
    before(:each) do
      allow(subject).to receive(:connect_to_gce).and_return(connection)
    end

    context 'Given a missing VM name' do
      before(:each) do
        allow(connection).to receive(:get_instance).and_raise(create_google_client_error(404, "The resource 'projects/#{project}/zones/#{zone}/instances/#{vmname}' was not found"))
        disk_list = MockDiskList.new(items: nil)
        allow(connection).to receive(:list_disks).and_return(disk_list)
        allow(subject).to receive(:find_all_snapshots).and_return(nil)
      end

      it 'should return true' do
        expect(connection.should_receive(:delete_instance).never)
        expect(subject.destroy_vm(poolname, 'missing_vm')).to be true
      end
    end

    context 'Given a running VM' do
      before(:each) do
        instance = MockInstance.new(name: vmname)
        allow(connection).to receive(:get_instance).and_return(instance)
        result = MockResult.new
        result.status = 'DONE'
        allow(subject).to receive(:wait_for_operation).and_return(result)
        allow(connection).to receive(:delete_instance).and_return(result)
      end

      it 'should return true' do
        # no dangling disks
        disk_list = MockDiskList.new(items: nil)
        allow(connection).to receive(:list_disks).and_return(disk_list)
        # no dangling snapshots
        allow(subject).to receive(:find_all_snapshots).and_return(nil)
        expect(subject.destroy_vm(poolname, vmname)).to be true
      end

      it 'should delete any dangling disks' do
        disk = MockDisk.new(name: vmname)
        disk_list = MockDiskList.new(items: [disk])
        allow(connection).to receive(:list_disks).and_return(disk_list)
        # no dangling snapshots
        allow(subject).to receive(:find_all_snapshots).and_return(nil)
        expect(connection).to receive(:delete_disk).with(project, zone, disk.name)
        subject.destroy_vm(poolname, vmname)
      end

      it 'should delete any dangling snapshots' do
        # no dangling disks
        disk_list = MockDiskList.new(items: nil)
        allow(connection).to receive(:list_disks).and_return(disk_list)
        snapshot = MockSnapshot.new(name: "snapshotname-#{vmname}")
        allow(subject).to receive(:find_all_snapshots).and_return([snapshot])
        expect(connection).to receive(:delete_snapshot).with(project, snapshot.name)
        subject.destroy_vm(poolname, vmname)
      end
    end
  end

  describe '#vm_ready?' do
    let(:domain) { nil }
    context 'When a VM is ready' do
      before(:each) do
        expect(subject).to receive(:open_socket).with(vmname, domain)
      end

      it 'should return true' do
        expect(subject.vm_ready?(poolname, vmname)).to be true
      end
    end

    context 'When an error occurs connecting to the VM' do
      before(:each) do
        expect(subject).to receive(:open_socket).and_raise(RuntimeError, 'MockError')
      end

      it 'should return false' do
        expect(subject.vm_ready?(poolname, vmname)).to be false
      end
    end
  end

  describe '#create_disk' do
    let(:disk_size) { 10 }
    before(:each) do
      allow(subject).to receive(:connect_to_gce).and_return(connection)
    end

    context 'Given an invalid pool name' do
      it 'should raise an error' do
        expect { subject.create_disk('missing_pool', vmname, disk_size) }.to raise_error(/missing_pool does not exist/)
      end
    end

    context 'when VM does not exist' do
      before(:each) do
        expect(connection).to receive(:get_instance).and_raise(create_google_client_error(404, "The resource 'projects/#{project}/zones/#{zone}/instances/#{vmname}' was not found"))
      end

      it 'should raise an error' do
        expect { subject.create_disk(poolname, vmname, disk_size) }.to raise_error(/VM #{vmname} .+ does not exist/)
      end
    end

    context 'when adding the disk raises an error' do
      before(:each) do
        disk = MockDisk.new(name: vmname)
        instance = MockInstance.new(name: vmname, disks: [disk])
        allow(connection).to receive(:get_instance).and_return(instance)
        expect(connection).to receive(:insert_disk).and_raise(RuntimeError, 'Mock Disk Error')
      end

      it 'should raise an error' do
        expect { subject.create_disk(poolname, vmname, disk_size) }.to raise_error(/Mock Disk Error/)
      end
    end

    context 'when adding the disk succeeds' do
      before(:each) do
        disk = MockDisk.new(name: vmname)
        instance = MockInstance.new(name: vmname, disks: [disk])
        allow(connection).to receive(:get_instance).and_return(instance)
        result = MockResult.new
        result.status = 'DONE'
        allow(connection).to receive(:insert_disk).and_return(result)
        allow(subject).to receive(:wait_for_operation).and_return(result)
        new_disk = MockDisk.new(name: "#{vmname}-disk1", self_link: "/foo/bar/baz/#{vmname}-disk1")
        allow(connection).to receive(:get_disk).and_return(new_disk)
        allow(connection).to receive(:attach_disk).and_return(result)
      end

      it 'should return true' do
        expect(subject.create_disk(poolname, vmname, disk_size)).to be true
      end
    end
  end

  describe '#create_snapshot' do
    let(:snapshot_name) { 'snapshot' }

    before(:each) do
      allow(subject).to receive(:connect_to_gce).and_return(connection)
    end

    context 'when VM does not exist' do
      before(:each) do
        allow(connection).to receive(:get_instance).and_raise(create_google_client_error(404, "The resource 'projects/#{project}/zones/#{zone}/instances/#{vmname}' was not found"))
      end

      it 'should raise an error' do
        expect { subject.create_snapshot(poolname, vmname, snapshot_name) }.to raise_error(/VM #{vmname} .+ does not exist/)
      end
    end

    context 'when snapshot already exists' do
      it 'should raise an error' do
        disk = MockDisk.new(name: vmname)
        instance = MockInstance.new(name: vmname, disks: [disk])
        allow(connection).to receive(:get_instance).and_return(instance)
        snapshots = [MockSnapshot.new(name: snapshot_name)]
        allow(subject).to receive(:find_snapshot).and_return(snapshots)
        expect { subject.create_snapshot(poolname, vmname, snapshot_name) }.to raise_error(/Snapshot #{snapshot_name} .+ already exists /)
      end
    end

    context 'when snapshot raises an error' do
      before(:each) do
        attached_disk = MockAttachedDisk.new(device_name: vmname, source: "foo/bar/baz/#{vmname}")
        instance = MockInstance.new(name: vmname, disks: [attached_disk])
        allow(connection).to receive(:get_instance).and_return(instance)
        snapshots = nil
        allow(subject).to receive(:find_snapshot).and_return(snapshots)
        allow(connection).to receive(:create_disk_snapshot).and_raise(RuntimeError, 'Mock Snapshot Error')
      end

      it 'should raise an error' do
        expect { subject.create_snapshot(poolname, vmname, snapshot_name) }.to raise_error(/Mock Snapshot Error/)
      end
    end

    context 'when snapshot succeeds' do
      before(:each) do
        attached_disk = MockAttachedDisk.new(device_name: vmname, source: "foo/bar/baz/#{vmname}")
        instance = MockInstance.new(name: vmname, disks: [attached_disk])
        allow(connection).to receive(:get_instance).and_return(instance)
        snapshots = nil
        allow(subject).to receive(:find_snapshot).and_return(snapshots)
        result = MockResult.new
        result.status = 'DONE'
        allow(connection).to receive(:create_disk_snapshot).and_return(result)
      end

      it 'should return true' do
        expect(subject.create_snapshot(poolname, vmname, snapshot_name)).to be true
      end

      it 'should snapshot each attached disk' do
        attached_disk = MockAttachedDisk.new(device_name: vmname, source: "foo/bar/baz/#{vmname}")
        attached_disk2 = MockAttachedDisk.new(device_name: vmname, source: "foo/bar/baz/#{vmname}-disk1")
        instance = MockInstance.new(name: vmname, disks: [attached_disk, attached_disk2])
        allow(connection).to receive(:get_instance).and_return(instance)

        expect(connection.should_receive(:create_disk_snapshot).twice)
        subject.create_snapshot(poolname, vmname, snapshot_name)
      end
    end
  end

  describe '#revert_snapshot' do
    let(:snapshot_name) { 'snapshot' }

    before(:each) do
      allow(subject).to receive(:connect_to_gce).and_return(connection)
    end

    context 'when VM does not exist' do
      before(:each) do
        allow(connection).to receive(:get_instance).and_raise(create_google_client_error(404, "The resource 'projects/#{project}/zones/#{zone}/instances/#{vmname}' was not found"))
      end

      it 'should raise an error' do
        expect { subject.revert_snapshot(poolname, vmname, snapshot_name) }.to raise_error(/VM #{vmname} .+ does not exist/)
      end
    end

    context 'when snapshot does not exist' do
      it 'should raise an error' do
        attached_disk = MockAttachedDisk.new(device_name: vmname, source: "foo/bar/baz/#{vmname}")
        instance = MockInstance.new(name: vmname, disks: [attached_disk])
        allow(connection).to receive(:get_instance).and_return(instance)
        snapshots = nil
        allow(subject).to receive(:find_snapshot).and_return(snapshots)
        expect { subject.revert_snapshot(poolname, vmname, snapshot_name) }.to raise_error(/Snapshot #{snapshot_name} .+ does not exist /)
      end
    end

    context 'when instance does not have attached disks' do
      it 'should skip detaching/deleting disk' do
        instance = MockInstance.new(name: vmname, disks: nil)
        allow(connection).to receive(:get_instance).and_return(instance)
        snapshots = []
        allow(subject).to receive(:find_snapshot).and_return(snapshots)
        allow(connection).to receive(:stop_instance)
        allow(subject).to receive(:wait_for_operation)
        allow(connection).to receive(:start_instance)
        expect(subject).not_to receive(:detach_disk)
        expect(subject).not_to receive(:delete_disk)
        subject.revert_snapshot(poolname, vmname, snapshot_name)
      end
    end

    context 'when revert to snapshot raises an error' do
      before(:each) do
        attached_disk = MockAttachedDisk.new(device_name: vmname, source: "foo/bar/baz/#{vmname}")
        instance = MockInstance.new(name: vmname, disks: [attached_disk])
        allow(connection).to receive(:get_instance).and_return(instance)
        snapshots = [MockSnapshot.new(name: snapshot_name)]
        allow(subject).to receive(:find_snapshot).and_return(snapshots)
        allow(connection).to receive(:stop_instance)
        allow(subject).to receive(:wait_for_operation)
        expect(connection).to receive(:detach_disk).and_raise(RuntimeError, 'Mock Snapshot Error')
      end

      it 'should raise an error' do
        expect { subject.revert_snapshot(poolname, vmname, snapshot_name) }.to raise_error(/Mock Snapshot Error/)
      end
    end

    context 'when revert to snapshot succeeds' do
      before(:each) do
        attached_disk = MockAttachedDisk.new(device_name: vmname, source: "foo/bar/baz/#{vmname}")
        instance = MockInstance.new(name: vmname, disks: [attached_disk])
        allow(connection).to receive(:get_instance).and_return(instance)
        snapshots = [MockSnapshot.new(name: snapshot_name, self_link: "foo/bar/baz/snapshot/#{snapshot_name}", labels: { 'diskname' => vmname })]
        allow(subject).to receive(:find_snapshot).and_return(snapshots)
        allow(connection).to receive(:stop_instance)
        allow(subject).to receive(:wait_for_operation)
        allow(connection).to receive(:detach_disk)
        allow(connection).to receive(:delete_disk)
        new_disk = MockDisk.new(name: vmname, self_link: "foo/bar/baz/disk/#{vmname}")
        allow(connection).to receive(:insert_disk)
        allow(connection).to receive(:get_disk).and_return(new_disk)
        allow(connection).to receive(:attach_disk)
        allow(connection).to receive(:start_instance)
      end

      it 'should return true' do
        expect(subject.revert_snapshot(poolname, vmname, snapshot_name)).to be true
      end
    end
  end

  describe '#purge_unconfigured_resources' do
    let(:empty_list) { [] }

    before(:each) do
      allow(subject).to receive(:connect_to_gce).and_return(connection)
    end

    context 'with empty allowlist' do
      before(:each) do
        allow(subject).to receive(:wait_for_zone_operation)
      end
      it 'should attempt to delete unconfigured instances when they dont have a label' do
        instance_list = MockInstanceList.new(items: [MockInstance.new(name: 'foo')])
        disk_list = MockDiskList.new(items: nil)
        snapshot_list = MockSnapshotList.new(items: nil)
        # the instance_list is filtered in the real code, and should only return non-configured VMs based on labels
        # that do not match a real pool name
        allow(connection).to receive(:list_instances).and_return(instance_list)
        allow(connection).to receive(:list_disks).and_return(disk_list)
        allow(connection).to receive(:list_snapshots).and_return(snapshot_list)
        expect(connection).to receive(:delete_instance)
        subject.purge_unconfigured_resources(nil)
      end
      it 'should attempt to delete unconfigured instances when they have a label that is not a configured pool' do
        instance_list = MockInstanceList.new(items: [MockInstance.new(name: 'foo', labels: { 'pool' => 'foobar' })])
        disk_list = MockDiskList.new(items: nil)
        snapshot_list = MockSnapshotList.new(items: nil)
        allow(connection).to receive(:list_instances).and_return(instance_list)
        allow(connection).to receive(:list_disks).and_return(disk_list)
        allow(connection).to receive(:list_snapshots).and_return(snapshot_list)
        expect(connection).to receive(:delete_instance)
        subject.purge_unconfigured_resources(nil)
      end
      it 'should attempt to delete unconfigured disks and snapshots when they do not have a label' do
        instance_list = MockInstanceList.new(items: nil)
        disk_list = MockDiskList.new(items: [MockDisk.new(name: 'diskfoo')])
        snapshot_list = MockSnapshotList.new(items: [MockSnapshot.new(name: 'snapfoo')])
        allow(connection).to receive(:list_instances).and_return(instance_list)
        allow(connection).to receive(:list_disks).and_return(disk_list)
        allow(connection).to receive(:list_snapshots).and_return(snapshot_list)
        expect(connection).to receive(:delete_disk)
        expect(connection).to receive(:delete_snapshot)
        subject.purge_unconfigured_resources(nil)
      end
    end

    context 'with allowlist containing a pool name' do
      before(:each) do
        allow(subject).to receive(:wait_for_zone_operation)
        $allowlist = ['allowed']
      end
      it 'should attempt to delete unconfigured instances when they dont have the allowlist label' do
        instance_list = MockInstanceList.new(items: [MockInstance.new(name: 'foo', labels: { 'pool' => 'not_this' })])
        disk_list = MockDiskList.new(items: nil)
        snapshot_list = MockSnapshotList.new(items: nil)
        allow(connection).to receive(:list_instances).and_return(instance_list)
        allow(connection).to receive(:list_disks).and_return(disk_list)
        allow(connection).to receive(:list_snapshots).and_return(snapshot_list)
        expect(connection).to receive(:delete_instance)
        subject.purge_unconfigured_resources($allowlist)
      end
      it 'should ignore unconfigured instances when they have a label that is allowed' do
        instance_list = MockInstanceList.new(items: [MockInstance.new(name: 'foo', labels: { 'pool' => 'allowed' })])
        disk_list = MockDiskList.new(items: nil)
        snapshot_list = MockSnapshotList.new(items: nil)
        allow(connection).to receive(:list_instances).and_return(instance_list)
        allow(connection).to receive(:list_disks).and_return(disk_list)
        allow(connection).to receive(:list_snapshots).and_return(snapshot_list)
        expect(connection).not_to receive(:delete_instance)
        subject.purge_unconfigured_resources($allowlist)
      end
      it 'should ignore unconfigured disks and snapshots when they have a label that is allowed' do
        instance_list = MockInstanceList.new(items: nil)
        disk_list = MockDiskList.new(items: [MockDisk.new(name: 'diskfoo', labels: { 'pool' => 'allowed' })])
        snapshot_list = MockSnapshotList.new(items: [MockSnapshot.new(name: 'snapfoo', labels: { 'pool' => 'allowed' })])
        allow(connection).to receive(:list_instances).and_return(instance_list)
        allow(connection).to receive(:list_disks).and_return(disk_list)
        allow(connection).to receive(:list_snapshots).and_return(snapshot_list)
        expect(connection).not_to receive(:delete_disk)
        expect(connection).not_to receive(:delete_snapshot)
        subject.purge_unconfigured_resources($allowlist)
      end
      it 'should ignore unconfigured item when they have the empty label that is allowed, which means we allow the pool label to not be set' do
        $allowlist = ['allowed', '']
        instance_list = MockInstanceList.new(items: [MockInstance.new(name: 'foo', labels: { 'some' => 'not_important' })])
        disk_list = MockDiskList.new(items: [MockDisk.new(name: 'diskfoo', labels: { 'other' => 'thing' })])
        snapshot_list = MockSnapshotList.new(items: [MockSnapshot.new(name: 'snapfoo')])
        allow(connection).to receive(:list_instances).and_return(instance_list)
        allow(connection).to receive(:list_disks).and_return(disk_list)
        allow(connection).to receive(:list_snapshots).and_return(snapshot_list)
        expect(connection).not_to receive(:delete_instance)
        expect(connection).not_to receive(:delete_disk)
        expect(connection).not_to receive(:delete_snapshot)
        subject.purge_unconfigured_resources($allowlist)
      end
    end

    context 'with allowlist containing a pool name and the empty string' do
      before(:each) do
        allow(subject).to receive(:wait_for_zone_operation)
        $allowlist = ['allowed', '']
      end
      it 'should attempt to delete unconfigured instances when they dont have the allowlist label' do
        instance_list = MockInstanceList.new(items: [MockInstance.new(name: 'foo', labels: { 'pool' => 'not_this' })])
        disk_list = MockDiskList.new(items: nil)
        snapshot_list = MockSnapshotList.new(items: nil)
        allow(connection).to receive(:list_instances).and_return(instance_list)
        allow(connection).to receive(:list_disks).and_return(disk_list)
        allow(connection).to receive(:list_snapshots).and_return(snapshot_list)
        expect(connection).to receive(:delete_instance)
        subject.purge_unconfigured_resources($allowlist)
      end
      it 'should ignore unconfigured disks and snapshots when they have a label that is allowed' do
        instance_list = MockInstanceList.new(items: nil)
        disk_list = MockDiskList.new(items: [MockDisk.new(name: 'diskfoo', labels: { 'pool' => 'allowed' })])
        snapshot_list = MockSnapshotList.new(items: [MockSnapshot.new(name: 'snapfoo', labels: { 'pool' => 'allowed' })])
        allow(connection).to receive(:list_instances).and_return(instance_list)
        allow(connection).to receive(:list_disks).and_return(disk_list)
        allow(connection).to receive(:list_snapshots).and_return(snapshot_list)
        expect(connection).not_to receive(:delete_disk)
        expect(connection).not_to receive(:delete_snapshot)
        subject.purge_unconfigured_resources($allowlist)
      end
      it 'should ignore unconfigured item when they have the empty label that is allowed, which means we allow the pool label to not be set' do
        instance_list = MockInstanceList.new(items: [MockInstance.new(name: 'foo', labels: { 'some' => 'not_important' })])
        disk_list = MockDiskList.new(items: [MockDisk.new(name: 'diskfoo', labels: { 'other' => 'thing' })])
        snapshot_list = MockSnapshotList.new(items: [MockSnapshot.new(name: 'snapfoo')])
        allow(connection).to receive(:list_instances).and_return(instance_list)
        allow(connection).to receive(:list_disks).and_return(disk_list)
        allow(connection).to receive(:list_snapshots).and_return(snapshot_list)
        expect(connection).not_to receive(:delete_instance)
        expect(connection).not_to receive(:delete_disk)
        expect(connection).not_to receive(:delete_snapshot)
        subject.purge_unconfigured_resources($allowlist)
      end
    end

    context 'with allowlist containing a a fully qualified label that is not pool' do
      before(:each) do
        allow(subject).to receive(:wait_for_zone_operation)
        $allowlist = ['user=Bob']
      end
      it 'should attempt to delete unconfigured instances when they dont have the allowlist label' do
        instance_list = MockInstanceList.new(items: [MockInstance.new(name: 'foo', labels: { 'pool' => 'not_this' })])
        disk_list = MockDiskList.new(items: nil)
        snapshot_list = MockSnapshotList.new(items: nil)
        allow(connection).to receive(:list_instances).and_return(instance_list)
        allow(connection).to receive(:list_disks).and_return(disk_list)
        allow(connection).to receive(:list_snapshots).and_return(snapshot_list)
        expect(connection).to receive(:delete_instance)
        subject.purge_unconfigured_resources($allowlist)
      end
      it 'should ignore unconfigured item when they match the fully qualified label' do
        instance_list = MockInstanceList.new(items: [MockInstance.new(name: 'foo', labels: { 'some' => 'not_important', 'user' => 'bob' })])
        disk_list = MockDiskList.new(items: [MockDisk.new(name: 'diskfoo', labels: { 'other' => 'thing', 'user' => 'bob' })])
        snapshot_list = MockSnapshotList.new(items: [MockSnapshot.new(name: 'snapfoo', labels: { 'user' => 'bob' })])
        allow(connection).to receive(:list_instances).and_return(instance_list)
        allow(connection).to receive(:list_disks).and_return(disk_list)
        allow(connection).to receive(:list_snapshots).and_return(snapshot_list)
        expect(connection).not_to receive(:delete_instance)
        expect(connection).not_to receive(:delete_disk)
        expect(connection).not_to receive(:delete_snapshot)
        subject.purge_unconfigured_resources($allowlist)
      end
    end

    it 'should raise any errors' do
      expect(subject).to receive(:provided_pools).and_throw('mockerror')
      expect { subject.purge_unconfigured_resources(nil) }.to raise_error(/mockerror/)
    end
  end

  describe '#get_current_user' do
    it 'should downcase and replace invalid chars with dashes' do
      redis_connection_pool.with_metrics do |redis|
        redis.hset("vmpooler__vm__#{vmname}", 'token:user', 'BOBBY.PUPPET')
        expect(subject.get_current_user(vmname)).to eq('bobby-puppet')
      end
    end

    it 'returns "" for nil values' do
      redis_connection_pool.with_metrics do |_redis|
        expect(subject.get_current_user(vmname)).to eq('')
      end
    end
  end
end
