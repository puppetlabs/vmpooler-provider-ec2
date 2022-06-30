require 'spec_helper'
require 'mock_redis'
require 'vmpooler/providers/aws'

RSpec::Matchers.define :relocation_spec_with_host do |value|
  match { |actual| actual[:spec].host == value }
end

describe 'Vmpooler::PoolManager::Provider::Aws' do
  let(:logger) { MockLogger.new }
  let(:metrics) { Vmpooler::Metrics::DummyStatsd.new }
  let(:poolname) { 'debian-9' }
  let(:provider_options) { { 'param' => 'value' } }
  let(:project) { 'vmpooler-test' }
  let(:zone) { 'us-west-2b' }
  let(:region) { 'us-west-2'}
  let(:config) { YAML.load(<<~EOT
  ---
  :config:
    max_tries: 3
    retry_factor: 10
  :providers:
    :aws:
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
      provider: 'aws'
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

  subject { Vmpooler::PoolManager::Provider::Aws.new(config, logger, metrics, redis_connection_pool, 'aws', provider_options) }

  describe '#manual tests live' do
    context 'in itsysops' do
      before(:each) { allow(subject).to receive(:dns).and_call_original }
      let(:vmname) { "instance-24" }
      let(:project) { 'vmpooler-test' }
      it 'gets a vm' do
        result = subject.create_vm(poolname, vmname)
        # result = subject.destroy_vm(poolname, vmname)
        # subject.get_vm(poolname, vmname)
        # subject.dns_teardown({'name' => vmname})
        # subject.dns_setup({'name' => vmname, 'ip' => '1.2.3.5'})
      end
    end
  end


end
