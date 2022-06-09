require 'rspec'

describe 'VmpoolerProviderGce' do
  context 'when creating class ' do
    it 'sets a version' do
      expect(VmpoolerProviderGce::VERSION).not_to be_nil
    end
  end
end