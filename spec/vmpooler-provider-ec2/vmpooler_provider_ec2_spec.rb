require 'rspec'

describe 'VmpoolerProviderEc2' do
  context 'when creating class ' do
    it 'sets a version' do
      expect(VmpoolerProviderEc2::VERSION).not_to be_nil
    end
  end
end