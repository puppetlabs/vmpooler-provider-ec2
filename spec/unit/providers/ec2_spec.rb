require 'spec_helper'
require 'mock_redis'
require 'ec2_helper'
require 'vmpooler/providers/ec2'

RSpec::Matchers.define :relocation_spec_with_host do |value|
  match { |actual| actual[:spec].host == value }
end

describe 'Vmpooler::PoolManager::Provider::Ec2' do
  let(:logger) { MockLogger.new }
  let(:metrics) { Vmpooler::Metrics::DummyStatsd.new }
  let(:poolname) { 'debian-9' }
  let(:provider_options) { { 'param' => 'value' } }
  let(:zone) { 'us-west-2b' }
  let(:region) { 'us-west-2'}
  let(:config) { YAML.load(<<~EOT
  ---
  :config:
    max_tries: 3
    retry_factor: 10
  :providers:
    :ec2:
      connection_pool_timeout: 1
      zone: '#{zone}'
      region: '#{region}'
  :pools:
    - name: '#{poolname}'
      alias: [ 'mockpool' ]
      amisize: 'a1.large'
      template: 'ami-03c1b544a7566b3e5'
      size: 5
      timeout: 10
      ready_ttl: 1440
      provider: 'ec2'
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

  subject { Vmpooler::PoolManager::Provider::Ec2.new(config, logger, metrics, redis_connection_pool, 'ec2', provider_options) }

  describe '#manual tests live' do
    context 'in itsysops' do
      let(:vmname) { "instance-60" }
      let(:poolname) { "amazon-7-x86_64-local" }
      let(:amisize) { "c5.xlarge" }
      let(:config) { YAML.load(<<~EOT
  ---
  :config:
    max_tries: 3
    retry_factor: 10
    site_name: 'vmpooler-local-dev'
  :providers:
    :ec2:
      connection_pool_timeout: 1
      zone: '#{zone}'
      region: '#{region}'
      project: 'vmpooler-test'
      dns_zone_resource_name: 'vmpooler-test-puppet-net'
      domain: 'vmpooler-test.puppet.net'
  :pools:
    - name: '#{poolname}'
      alias: [ 'mockpool' ]
      amisize: '#{amisize}'
      template: 'ami-31394949'
      size: 5
      timeout: 10
      ready_ttl: 1440
      provider: 'ec2'
      provision: 'true'
      EOT
      )
      }
      before(:each) {
        allow(subject).to receive(:dns).and_call_original
      }
      skip 'gets a vm' do
        result = subject.create_vm(poolname, vmname)
        subject.tag_vm_user(poolname, vmname)
        #result = subject.destroy_vm(poolname, vmname)
        #subject.vms_in_pool("amazon-6-x86_64-ec2")
        #subject.provision_node_aws("ip-10-227-4-97.amz-dev.puppet.net", poolname)
        # subject.create_snapshot(poolname, vmname, "foo")
        #subject.create_disk(poolname, vmname, 10)
        # a = subject.destroy_vm(poolname, vmname)
        # b = subject.get_vm(poolname, vmname)
        puts "done"
        # subject.dns_teardown({'name' => vmname})
        # subject.dns_setup({'name' => vmname, 'ip' => '1.2.3.5'})
      end
    end
  end

  describe '#vms_in_pool' do
    let(:pool_config) { config[:pools][0] }

    before(:each) do
      allow(subject).to receive(:connect_to_aws).and_return(connection)
    end

    context 'Given an empty pool folder' do
      it 'should return an empty array' do
        allow(connection).to receive(:instances).and_return([nil])
        result = subject.vms_in_pool(poolname)

        expect(result).to eq([])
      end
    end

    context 'Given a pool with many VMs' do
      let(:expected_vm_list) do
        [
          { 'name' => 'vm1' },
          { 'name' => 'vm2' },
          { 'name' => 'vm3' }
        ]
      end
      before(:each) do
        instance_list = []
        expected_vm_list.each do |vm_hash|
          tags = [MockTag.new(key: "vm_name", value: vm_hash['name'])]
          mock_vm = MockInstance.new(tags: tags)
          instance_list << mock_vm
        end

        expect(connection).to receive(:instances).and_return(instance_list)
      end

      it 'should list all VMs in the VM folder for the pool' do
        result = subject.vms_in_pool(poolname)

        expect(result).to eq(expected_vm_list)
      end
    end
  end

  describe '#get_vm' do
    before(:each) do
      allow(subject).to receive(:connect_to_aws).and_return(connection)
    end

    context 'when VM does not exist' do
      it 'should return nil' do
        allow(connection).to receive(:instances).and_return([nil])
        expect(subject.get_vm(poolname, vmname)).to be_nil
      end
    end

    context 'when VM exists but is missing information' do
      before(:each) do
        tags = [
          MockTag.new(key: "Name", value: vmname),
          MockTag.new(key: "vm_name", value: vmname)
        ]
        allow(connection).to receive(:instances).and_return([MockInstance.new(tags: tags)])
      end

      it 'should return a hash' do
        expect(subject.get_vm(poolname, vmname)).to be_kind_of(Hash)
      end

      it 'should return the VM name when domain set' do
        config[:providers][:ec2]['domain'] = "foobar.com"
        result = subject.get_vm(poolname, vmname)

        expect(result['name']).to eq(vmname)
      end

      %w[boottime image_size status private_ip_address].each do |testcase|
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
        state = Struct.new(:name)
        runningstate = state.new "running"
        MockInstance.new(
          launch_time: boot_time,
          state: runningstate,
          instance_type: "a1.large",
          private_ip_address: "1.1.1.1",
          tags: [
                  MockTag.new(key: "Name", value: vmname),
                  MockTag.new(key: "pool", value: poolname)
                ]
        )
      end
      let(:pool_info) { config[:pools][0] }

      before(:each) do
        allow(connection).to receive(:instances).and_return([vm_object])
      end

      it 'should return a hash' do
        expect(subject.get_vm(poolname, vmname)).to be_kind_of(Hash)
      end

      it 'should return the VM name' do
        result = subject.get_vm(poolname, vmname)

        expect(result['name']).to eq(vmname)
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

      it 'should return the status' do
        result = subject.get_vm(poolname, vmname)

        expect(result['status']).to eq("running")
      end

      it 'should return the status' do
        result = subject.get_vm(poolname, vmname)

        expect(result['image_size']).to eq("a1.large")
      end
    end
  end

  describe '#create_vm' do
    before(:each) do
      allow(subject).to receive(:connect_to_aws).and_return(connection)
    end

    context 'Given an invalid pool name' do
      it 'should raise an error' do
        expect { subject.create_vm('missing_pool', vmname) }.to raise_error(/missing_pool does not exist/)
      end
    end

    context 'Given a vmname that already exists' do
      before(:each) do
        allow(subject).to receive(:get_vm).and_return({
                                                        'name' => "foobar",
                                                        'template' => "abc",
                                                        'status' => "running"
                                                      })
      end

      it 'should raise an error' do
        expect { subject.create_vm(poolname, vmname) }.to raise_error(/Instance creation not attempted, .* already exists/)
      end
    end

    context 'Given a successful creation' do
      let(:client) { double }
      before(:each) do
        allow(subject).to receive(:get_vm).and_return(nil,{
          'name' => vmname,
          'template' => "abc",
          'status' => "running"
        })
        result = Struct.new(:instance_id)
        batch_instance = result.new(instance_id: "abcfoo")
        allow(connection).to receive(:create_instances).and_return([batch_instance])
        allow(connection).to receive(:client).and_return(client)
        allow(client).to receive(:wait_until)
      end

      it 'should return a hash' do
        result = subject.create_vm(poolname, vmname)

        expect(result.is_a?(Hash)).to be true
      end

      it 'should have the new VM name' do
        result = subject.create_vm(poolname, vmname)

        expect(result['name']).to eq(vmname)
      end
    end
  end

  describe '#destroy_vm' do
    before(:each) do
      allow(subject).to receive(:connect_to_aws).and_return(connection)
    end

    context 'Given a missing VM name' do
      let(:client) { double }
      before(:each) do
        allow(connection).to receive(:instances).and_return([nil])
        allow(connection).to receive(:client).and_return(client)
        allow(client).to receive(:wait_until)
      end

      it 'should return true' do
        expect(subject.destroy_vm(poolname, 'missing_vm')).to be true
      end
    end

    context 'Given a running VM' do
      let(:instance) { double("instance") }
      let(:client) { double }
      before(:each) do
        allow(connection).to receive(:instances).and_return([instance])
        expect(instance).to receive(:terminate)
        allow(connection).to receive(:client).and_return(client)
        allow(client).to receive(:wait_until)
        allow(instance).to receive(:id)
        allow(subject).to receive(:get_vm).and_return({})
        allow(subject).to receive(:dns_teardown).and_return(true)
      end

      it 'should return true' do
        expect(subject.destroy_vm(poolname, vmname)).to be true
      end
    end
  end
end

